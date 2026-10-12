//! QUICP underlay: fake-TCP session table over platform raw sockets.
//!
//! Implements Quinn's [`AsyncUdpSocket`] so the rest of the carrier sees a
//! datagram transport regardless of UDP vs quicp scheme.
#![cfg(target_os = "linux")]

use super::{BareDatagram, CarrierError, InboundPacketKind};
use quinn::{AsyncUdpSocket, UdpPoller, udp::RecvMeta};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, futures::OwnedNotified, mpsc};

const MAX_QUICP_SESSIONS: usize = 4_096;
const MAX_QUICP_PENDING_PER_SESSION: usize = 32;
const MAX_QUICP_RECEIVED: usize = 4_096;
/// A fake-TCP session has not passed QUIC's authenticated handshake yet, so
/// keep the raw pre-session state deliberately short-lived.
fn quicp_handshake_timeout() -> Duration {
    crate::timing::active().quicp_handshake_timeout
}
/// Established fake-TCP flows are retained while Quinn is idle.  This is
/// intentionally much longer than the handshake deadline, but finite so a
/// peer that disappears without a RST cannot occupy a slot forever.
fn quicp_established_idle_timeout() -> Duration {
    crate::timing::active().quicp_established_idle_timeout
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
struct QuicpSession {
    state: tinect_fake_tcp::FakeTcpSession,
    pending: VecDeque<Vec<u8>>,
    /// Last handshake packet, replayed when a raw SYN or SYN|ACK is lost.
    handshake_reply: Option<tinect_fake_tcp::OutboundPacket>,
    /// Last peer progress, or successful established-path write.  Handshake
    /// retransmits do not refresh this value: otherwise our own retries could
    /// keep a spoofed SYN state alive indefinitely.
    last_activity: Instant,
}

impl QuicpSession {
    fn timeout(&self) -> Duration {
        if self.state.state() == tinect_fake_tcp::State::Established {
            quicp_established_idle_timeout()
        } else {
            quicp_handshake_timeout()
        }
    }

    fn is_handshake(&self) -> bool {
        self.state.state() != tinect_fake_tcp::State::Established
    }
}

/// Reclaim sessions which have had no peer progress (or established-path
/// traffic) within their state-specific deadline.  Kept independent of the
/// raw socket so lifecycle rules have deterministic, privilege-free tests.
fn reap_expired_sessions(sessions: &mut HashMap<SocketAddr, QuicpSession>, now: Instant) -> usize {
    let before = sessions.len();
    sessions.retain(|_, session| {
        now.saturating_duration_since(session.last_activity) < session.timeout()
    });
    before - sessions.len()
}

/// Make room for one new fake-TCP tuple.  A full table may evict only its
/// oldest half-open flow; established flows are never displaced by an
/// unauthenticated SYN.
fn make_session_room(sessions: &mut HashMap<SocketAddr, QuicpSession>, now: Instant) -> bool {
    reap_expired_sessions(sessions, now);
    if sessions.len() < MAX_QUICP_SESSIONS {
        return true;
    }
    let oldest_handshake = sessions
        .iter()
        .filter(|(_, session)| session.is_handshake())
        .min_by_key(|(_, session)| session.last_activity)
        .map(|(remote, _)| *remote);
    if let Some(remote) = oldest_handshake {
        sessions.remove(&remote);
    }
    sessions.len() < MAX_QUICP_SESSIONS
}

fn pending_has_capacity(pending: &VecDeque<Vec<u8>>) -> bool {
    pending.len() < MAX_QUICP_PENDING_PER_SESSION
}

fn accepts_destination(local: SocketAddr, destination: SocketAddr) -> bool {
    destination.port() == local.port()
        && (local.ip().is_unspecified() || destination.ip() == local.ip())
}

fn bare_receive_id(packet: &[u8]) -> Option<u32> {
    (packet.len() >= 5).then(|| u32::from_be_bytes(packet[1..5].try_into().expect("receive id")))
}

fn fill_received_datagrams(
    received: &mut VecDeque<(SocketAddr, Vec<u8>)>,
    local: SocketAddr,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
    max: usize,
) -> Option<usize> {
    if received.is_empty() {
        return None;
    }
    let dst_ip = (!local.ip().is_unspecified()).then_some(local.ip());
    let mut filled = 0;
    while filled < max {
        let Some((remote, payload)) = received.pop_front() else {
            break;
        };
        let len = payload.len().min(bufs[filled].len());
        bufs[filled][..len].copy_from_slice(&payload[..len]);
        meta[filled] = RecvMeta {
            addr: remote,
            len,
            stride: len,
            ecn: None,
            dst_ip,
        };
        filled += 1;
    }
    (filled > 0).then_some(filled)
}

#[derive(Debug)]
pub(crate) struct QuicpSocket {
    local: SocketAddr,
    raw: Arc<crate::platform::quicp::RawTcpSocket>,
    sessions: Arc<Mutex<HashMap<SocketAddr, QuicpSession>>>,
    received: Mutex<VecDeque<(SocketAddr, Vec<u8>)>>,
    bare_routes: Mutex<HashMap<u32, mpsc::Sender<BareDatagram>>>,
    notify: Arc<Notify>,
    waiter: Mutex<Option<Pin<Box<OwnedNotified>>>>,
    reset_key: Option<Vec<u8>>,
}

impl QuicpSocket {
    pub(super) fn new(
        bind: SocketAddr,
        fwmark: Option<u32>,
        reset_key: Option<&[u8]>,
    ) -> Result<Arc<Self>, CarrierError> {
        let (raw, local) = crate::platform::quicp::RawTcpSocket::open(bind, fwmark)
            .map_err(|e| CarrierError::Protocol(e.to_string()))?;
        tracing::info!(%local, "quicp socket created");
        let sessions: Arc<Mutex<HashMap<SocketAddr, QuicpSession>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let sessions_ref = Arc::downgrade(&sessions);
        let raw = Arc::new(raw);
        let raw_for_task = Arc::downgrade(&raw);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                interval.tick().await;
                let (Some(raw), Some(sessions)) = (raw_for_task.upgrade(), sessions_ref.upgrade())
                else {
                    break;
                };
                let mut sessions = sessions.lock().unwrap();
                let expired = reap_expired_sessions(&mut sessions, Instant::now());
                if expired > 0 {
                    tracing::debug!(
                        expired,
                        remaining = sessions.len(),
                        "reclaimed expired fake-TCP sessions"
                    );
                }
                for session in sessions.values() {
                    if session.state.state() == tinect_fake_tcp::State::Established {
                        continue;
                    }
                    if let Some(packet) = &session.handshake_reply {
                        let _ = raw.try_send(&packet.bytes, packet.packet.destination);
                    }
                }
            }
        });
        let socket = Arc::new(Self {
            local,
            raw,
            sessions,
            received: Mutex::new(VecDeque::new()),
            bare_routes: Mutex::new(HashMap::new()),
            notify: Arc::new(Notify::new()),
            waiter: Mutex::new(None),
            reset_key: reset_key.map(ToOwned::to_owned),
        });
        let socket_ref = Arc::downgrade(&socket);
        tokio::spawn(async move {
            loop {
                let Some(socket) = socket_ref.upgrade() else {
                    break;
                };
                let packet = match std::future::poll_fn(|cx| socket.raw.poll_recv(cx)).await {
                    Ok(packet) => packet,
                    Err(error) => {
                        tracing::debug!(%error, "fake-TCP reader stopped");
                        break;
                    }
                };
                let _ = socket.receive_one(&packet);
                while let Ok(Some(packet)) = socket.raw.try_recv() {
                    let _ = socket.receive_one(&packet);
                }
                socket.notify.notify_waiters();
            }
        });
        Ok(socket)
    }
    fn send_raw(&self, outbound: &tinect_fake_tcp::OutboundPacket) -> io::Result<()> {
        self.raw
            .try_send(&outbound.bytes, outbound.packet.destination)
    }
    pub(crate) fn register_receive_id(&self, id: u32) -> io::Result<mpsc::Receiver<BareDatagram>> {
        if id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero receive id",
            ));
        }
        let (sender, receiver) = mpsc::channel(1024);
        if self
            .bare_routes
            .lock()
            .unwrap()
            .insert(id, sender)
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "receive id already registered",
            ));
        }
        Ok(receiver)
    }
    pub(crate) fn unregister_receive_id(&self, id: u32) {
        self.bare_routes.lock().unwrap().remove(&id);
    }
    pub(crate) fn send_bare(&self, remote: SocketAddr, frame: &[u8]) -> io::Result<usize> {
        let mut sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(&remote) {
            if !make_session_room(&mut sessions, Instant::now()) {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let local = self.outbound_local(remote)?;
            let mut state = tinect_fake_tcp::FakeTcpSession::client_with_reset_key(
                local,
                remote,
                random_initial_sequence(),
                self.reset_key.as_deref(),
            )
            .map_err(io::Error::other)?;
            let syn = state.start().expect("fresh fake TCP session");
            self.send_raw(&syn)?;
            sessions.insert(
                remote,
                QuicpSession {
                    state,
                    pending: VecDeque::new(),
                    handshake_reply: Some(syn),
                    last_activity: Instant::now(),
                },
            );
        }
        let session = sessions
            .get_mut(&remote)
            .expect("session was just inserted");
        if session.state.state() == tinect_fake_tcp::State::Established {
            self.send_raw(&session.state.encapsulate(frame).map_err(io::Error::other)?)?;
            session.last_activity = Instant::now();
        } else {
            if let Some(reply) = &session.handshake_reply {
                self.send_raw(reply)?;
            }
            if !pending_has_capacity(&session.pending) {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            session.pending.push_back(frame.to_vec());
        }
        Ok(frame.len())
    }
    fn divert_bare(&self, source: SocketAddr, packet: &[u8]) {
        let Some(id) = bare_receive_id(packet) else {
            return;
        };
        let sender = self.bare_routes.lock().unwrap().get(&id).cloned();
        if let Some(sender) = sender {
            let _ = sender.try_send(BareDatagram {
                source,
                frame: packet.to_vec(),
            });
        }
    }
    fn drain_pending(&self, session: &mut QuicpSession) -> io::Result<()> {
        while let Some(payload) = session.pending.pop_front() {
            match self.send_raw(
                &session
                    .state
                    .encapsulate(&payload)
                    .map_err(io::Error::other)?,
            ) {
                Err(ref e) if e.raw_os_error() == Some(libc::EMSGSIZE) => {
                    tracing::debug!("ignoring EMSGSIZE in drain_pending");
                }
                other => other?,
            }
        }
        Ok(())
    }
    fn accepts_destination(&self, destination: SocketAddr) -> bool {
        accepts_destination(self.local, destination)
    }
    fn outbound_local(&self, remote: SocketAddr) -> io::Result<SocketAddr> {
        if self.local.ip().is_unspecified() {
            self.raw.source_addr_for(remote, self.local.port())
        } else {
            Ok(self.local)
        }
    }
    /// Copies queued decoded datagrams into Quinn receive buffers.
    /// Returns `Some(n)` when at least one datagram was filled, else `None`.
    fn fill_recv_bufs(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        max: usize,
    ) -> Option<usize> {
        let mut received = self.received.lock().unwrap();
        fill_received_datagrams(&mut received, self.local, bufs, meta, max)
    }

    fn receive_one(&self, packet: &[u8]) -> io::Result<()> {
        // Decode once; hand the owned Packet into the state machine.
        let parsed = match tinect_fake_tcp::decode(packet) {
            Ok(packet) => packet,
            Err(_) => return Ok(()),
        };
        if !self.accepts_destination(parsed.destination) {
            return Ok(());
        }
        let remote = parsed.source;
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&remote) {
            if session.state.state() == tinect_fake_tcp::State::SynReceived
                && parsed.flags == tinect_fake_tcp::flags::SYN
            {
                if let Some(reply) = &session.handshake_reply {
                    self.send_raw(reply)?;
                }
                return Ok(());
            }
            if session.state.state() == tinect_fake_tcp::State::Established
                && parsed.flags == (tinect_fake_tcp::flags::SYN | tinect_fake_tcp::flags::ACK)
            {
                if let Some(reply) = &session.handshake_reply {
                    self.send_raw(reply)?;
                }
                return Ok(());
            }
            let was_established = session.state.state() == tinect_fake_tcp::State::Established;
            let event = match session.state.handle_packet(parsed) {
                Ok(event) => event,
                Err(_) => return Ok(()),
            };
            session.last_activity = Instant::now();
            if let Some(reply) = event.reply {
                self.send_raw(&reply)?;
                if !was_established && event.state == tinect_fake_tcp::State::Established {
                    session.handshake_reply = Some(reply);
                    self.drain_pending(session)?;
                }
            } else if !was_established && event.state == tinect_fake_tcp::State::Established {
                self.drain_pending(session)?;
            }
            if let Some(payload) = event.datagram {
                if super::classify_inbound_packet(&payload) == InboundPacketKind::BarePhysical {
                    self.divert_bare(remote, &payload);
                } else {
                    let mut received = self.received.lock().unwrap();
                    if received.len() < MAX_QUICP_RECEIVED {
                        received.push_back((remote, payload));
                    }
                }
            }
            let reset = event.state == tinect_fake_tcp::State::Reset;
            if reset {
                sessions.remove(&remote);
            }
            return Ok(());
        }
        let (state, reply) = match tinect_fake_tcp::FakeTcpSession::accept_packet_with_reset_key(
            parsed,
            random_initial_sequence(),
            self.reset_key.as_deref(),
        ) {
            Ok(value) => value,
            Err(_) => return Ok(()),
        };
        if !make_session_room(&mut sessions, Instant::now()) {
            return Ok(());
        }
        self.send_raw(&reply)?;
        sessions.insert(
            remote,
            QuicpSession {
                state,
                pending: VecDeque::new(),
                handshake_reply: Some(reply),
                last_activity: Instant::now(),
            },
        );
        Ok(())
    }
}

/// The RST authenticator binds both initial sequence numbers. They must be
/// unpredictable so a valid reset from an old session cannot be replayed
/// after a new fake-TCP session is created, including after process restart.
fn random_initial_sequence() -> u32 {
    let mut bytes = [0; 4];
    getrandom::fill(&mut bytes).expect("OS random source unavailable");
    u32::from_ne_bytes(bytes)
}

#[derive(Debug)]
struct QuicpPoller(Arc<crate::platform::quicp::RawTcpSocket>);
impl UdpPoller for QuicpPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.0.poll_writable(cx)
    }
}

impl AsyncUdpSocket for QuicpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(QuicpPoller(self.raw.clone()))
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let remote = transmit.destination;
        let mut sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(&remote) {
            if !make_session_room(&mut sessions, Instant::now()) {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let local = self.outbound_local(remote)?;
            let mut state = tinect_fake_tcp::FakeTcpSession::client_with_reset_key(
                local,
                remote,
                random_initial_sequence(),
                self.reset_key.as_deref(),
            )
            .map_err(io::Error::other)?;
            let syn = state.start().expect("fresh fake TCP session");
            self.send_raw(&syn)?;
            sessions.insert(
                remote,
                QuicpSession {
                    state,
                    pending: VecDeque::new(),
                    handshake_reply: Some(syn),
                    last_activity: Instant::now(),
                },
            );
        }
        let session = sessions
            .get_mut(&remote)
            .expect("session was just inserted");
        if session.state.state() == tinect_fake_tcp::State::Established {
            match self.send_raw(
                &session
                    .state
                    .encapsulate(transmit.contents)
                    .map_err(io::Error::other)?,
            ) {
                Ok(()) => {
                    session.last_activity = Instant::now();
                    Ok(())
                }
                Err(ref e) if e.raw_os_error() == Some(libc::EMSGSIZE) => {
                    tracing::debug!(
                        packet_len = transmit.contents.len(),
                        "ignoring EMSGSIZE error for packet to allow PMTUD to converge"
                    );
                    Ok(())
                }
                other => other,
            }
        } else {
            if let Some(handshake_reply) = &session.handshake_reply {
                self.send_raw(handshake_reply)?;
            }
            if !pending_has_capacity(&session.pending) {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            session.pending.push_back(transmit.contents.to_vec());
            Ok(())
        }
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> std::task::Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        let max = bufs.len().min(meta.len());
        loop {
            // Serve already-decoded datagrams first (may fill multiple Quinn bufs).
            if let Some(filled) = self.fill_recv_bufs(bufs, meta, max) {
                return std::task::Poll::Ready(Ok(filled));
            }
            let mut waiter = self.waiter.lock().unwrap();
            if waiter.is_none() {
                *waiter = Some(Box::pin(self.notify.clone().notified_owned()));
            }
            if waiter
                .as_mut()
                .expect("fake-TCP waiter")
                .as_mut()
                .poll(cx)
                .is_pending()
            {
                return std::task::Poll::Pending;
            }
            *waiter = None;
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

impl Drop for QuicpSocket {
    fn drop(&mut self) {
        let mut sessions = self.sessions.lock().unwrap();
        for session in sessions.values_mut() {
            if let Ok(reset) = session.state.reset() {
                let _ = self.send_raw(&reset);
            }
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    fn remote(index: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, 1], 10_000 + index))
    }

    #[test]
    fn destination_and_receive_id_helpers_reject_mismatches_and_short_packets() {
        let local = "192.0.2.10:443".parse().unwrap();
        assert!(accepts_destination(
            local,
            "192.0.2.10:443".parse().unwrap()
        ));
        assert!(!accepts_destination(
            local,
            "192.0.2.11:443".parse().unwrap()
        ));
        assert!(!accepts_destination(
            local,
            "192.0.2.10:444".parse().unwrap()
        ));

        let wildcard = "0.0.0.0:443".parse().unwrap();
        assert!(accepts_destination(
            wildcard,
            "198.51.100.10:443".parse().unwrap()
        ));
        assert!(!accepts_destination(
            wildcard,
            "198.51.100.10:444".parse().unwrap()
        ));

        assert_eq!(bare_receive_id(&[0, 1, 2, 3]), None);
        assert_eq!(bare_receive_id(&[0, 1, 2, 3, 4]), Some(0x0102_0304));
    }

    #[test]
    fn pending_capacity_and_receive_buffer_helpers_cover_boundaries() {
        assert!(pending_has_capacity(&VecDeque::new()));
        assert!(!pending_has_capacity(&VecDeque::from(vec![
            Vec::new();
            MAX_QUICP_PENDING_PER_SESSION
        ])));

        let local = "192.0.2.10:443".parse().unwrap();
        let peer = "198.51.100.10:5000".parse().unwrap();
        let mut received = VecDeque::from([(peer, vec![1, 2, 3]), (peer, vec![4, 5, 6, 7])]);
        let mut first = [0_u8; 2];
        let mut second = [0_u8; 8];
        let mut meta = [
            RecvMeta {
                addr: peer,
                len: 0,
                stride: 0,
                ecn: None,
                dst_ip: None,
            },
            RecvMeta {
                addr: peer,
                len: 0,
                stride: 0,
                ecn: None,
                dst_ip: None,
            },
        ];
        {
            let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
            assert_eq!(
                fill_received_datagrams(&mut received, local, &mut bufs, &mut meta, 2),
                Some(2)
            );
        }
        assert_eq!(&first, &[1, 2]);
        assert_eq!(&second[..4], &[4, 5, 6, 7]);
        assert_eq!(meta[0].len, 2);
        assert_eq!(meta[1].len, 4);
        assert_eq!(meta[0].dst_ip, Some(local.ip()));
        assert!(received.is_empty());
        let mut empty_buf = [0_u8; 1];
        let mut empty_bufs = [IoSliceMut::new(&mut empty_buf)];
        assert_eq!(
            fill_received_datagrams(&mut received, local, &mut empty_bufs, &mut meta, 2),
            None
        );
    }

    #[test]
    fn receive_buffer_helper_omits_destination_for_wildcard_local_address() {
        let local = "0.0.0.0:443".parse().unwrap();
        let peer = "198.51.100.10:5000".parse().unwrap();
        let mut received = VecDeque::from([(peer, vec![9])]);
        let mut buffer = [0_u8; 1];
        let mut bufs = [IoSliceMut::new(&mut buffer)];
        let mut meta = [RecvMeta {
            addr: peer,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        assert_eq!(
            fill_received_datagrams(&mut received, local, &mut bufs, &mut meta, 0),
            None
        );
        assert_eq!(received.len(), 1);
        assert_eq!(
            fill_received_datagrams(&mut received, local, &mut bufs, &mut meta, 1),
            Some(1)
        );
        assert_eq!(meta[0].dst_ip, None);
    }

    fn half_open(at: Instant) -> QuicpSession {
        QuicpSession {
            state: tinect_fake_tcp::FakeTcpSession::client(
                "192.0.2.1:443".parse().unwrap(),
                "198.51.100.1:443".parse().unwrap(),
                1,
            )
            .unwrap(),
            pending: VecDeque::new(),
            handshake_reply: None,
            last_activity: at,
        }
    }

    fn established(at: Instant) -> QuicpSession {
        let mut client = tinect_fake_tcp::FakeTcpSession::client(
            "192.0.2.1:443".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
            1,
        )
        .unwrap();
        let syn = client.start().unwrap();
        let (mut server, syn_ack) = tinect_fake_tcp::FakeTcpSession::accept(&syn.bytes, 2).unwrap();
        let ack = client
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        server.handle_inbound(&ack.bytes).unwrap();
        assert_eq!(client.state(), tinect_fake_tcp::State::Established);
        QuicpSession {
            state: client,
            pending: VecDeque::new(),
            handshake_reply: None,
            last_activity: at,
        }
    }

    #[test]
    fn reaps_expired_half_open_sessions_but_keeps_established_flows() {
        let now = Instant::now();
        let mut sessions =
            HashMap::from([(remote(1), half_open(now)), (remote(2), established(now))]);

        assert_eq!(
            reap_expired_sessions(&mut sessions, now + quicp_handshake_timeout()),
            1
        );
        assert!(!sessions.contains_key(&remote(1)));
        assert!(sessions.contains_key(&remote(2)));

        assert_eq!(
            reap_expired_sessions(&mut sessions, now + quicp_established_idle_timeout()),
            1
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn full_table_evicts_oldest_half_open_session_for_new_flow() {
        let now = Instant::now();
        let mut sessions = HashMap::new();
        for index in 0..MAX_QUICP_SESSIONS as u16 {
            sessions.insert(
                remote(index),
                half_open(now + Duration::from_millis(u64::from(index))),
            );
        }

        assert!(make_session_room(
            &mut sessions,
            now + Duration::from_secs(1)
        ));
        assert_eq!(sessions.len(), MAX_QUICP_SESSIONS - 1);
        assert!(!sessions.contains_key(&remote(0)));
        sessions.insert(remote(MAX_QUICP_SESSIONS as u16), half_open(now));
        assert_eq!(sessions.len(), MAX_QUICP_SESSIONS);
    }

    #[test]
    fn full_table_never_evicts_established_sessions() {
        let now = Instant::now();
        let protected = remote(0);
        let mut sessions = HashMap::from([(protected, established(now))]);
        for index in 1..MAX_QUICP_SESSIONS as u16 {
            sessions.insert(
                remote(index),
                half_open(now + Duration::from_millis(u64::from(index))),
            );
        }

        assert!(make_session_room(
            &mut sessions,
            now + Duration::from_secs(1)
        ));
        assert!(sessions.contains_key(&protected));
        assert_eq!(sessions.len(), MAX_QUICP_SESSIONS - 1);
    }

    #[test]
    fn full_established_table_rejects_new_session_without_eviction() {
        let now = Instant::now();
        let template = established(now);
        let mut sessions = HashMap::new();
        for index in 0..MAX_QUICP_SESSIONS as u16 {
            sessions.insert(remote(index), template.clone());
        }

        assert!(!make_session_room(
            &mut sessions,
            now + Duration::from_secs(1)
        ));
        assert_eq!(sessions.len(), MAX_QUICP_SESSIONS);
        assert!(
            sessions
                .values()
                .all(|session| session.state.state() == tinect_fake_tcp::State::Established)
        );
    }

    #[test]
    fn session_timeout_tracks_handshake_and_established_states() {
        let now = Instant::now();
        let handshake = half_open(now);
        assert!(handshake.is_handshake());
        assert_eq!(handshake.timeout(), quicp_handshake_timeout());

        let established = established(now);
        assert!(!established.is_handshake());
        assert_eq!(established.timeout(), quicp_established_idle_timeout());
    }

    #[test]
    fn expired_sessions_are_reclaimed_at_the_state_specific_boundary() {
        let now = Instant::now();
        let mut sessions = HashMap::from([
            (remote(1), half_open(now - quicp_handshake_timeout())),
            (
                remote(2),
                established(now - quicp_established_idle_timeout()),
            ),
        ]);
        assert_eq!(reap_expired_sessions(&mut sessions, now), 2);
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn raw_socket_handshake_delivers_quic_and_bare_datagrams() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();

        let server =
            QuicpSocket::new("127.0.0.1:0".parse().unwrap(), None, Some(b"test-reset")).unwrap();
        let client =
            QuicpSocket::new("127.0.0.1:0".parse().unwrap(), None, Some(b"test-reset")).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();

        assert!(server.register_receive_id(0).is_err());
        let _bare_receiver = server.register_receive_id(7).unwrap();
        assert_eq!(
            server.register_receive_id(7).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        server.unregister_receive_id(7);
        let mut bare_receiver = server.register_receive_id(7).unwrap();

        server.divert_bare(client_addr, &[crate::physical::FORM_KEEPALIVE]);
        server.receive_one(&[]).unwrap();
        let mut foreign = tinect_fake_tcp::FakeTcpSession::client_with_reset_key(
            "127.0.0.1:40000".parse().unwrap(),
            server_addr,
            17,
            Some(b"test-reset"),
        )
        .unwrap();
        let syn = foreign.start().unwrap();
        let mut wrong_destination = syn.packet.clone();
        wrong_destination
            .destination
            .set_port(server_addr.port() + 1);
        server
            .receive_one(&tinect_fake_tcp::encode(&wrong_destination).unwrap())
            .unwrap();
        server.receive_one(&syn.bytes).unwrap();
        // A retransmitted SYN is answered from the cached handshake state.
        server.receive_one(&syn.bytes).unwrap();
        let mut unexpected_ack = syn.packet.clone();
        unexpected_ack.flags = tinect_fake_tcp::flags::ACK;
        server
            .receive_one(&tinect_fake_tcp::encode(&unexpected_ack).unwrap())
            .unwrap();

        let mut empty_bufs = [];
        let mut empty_meta = [];
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            quinn::AsyncUdpSocket::poll_recv(
                server.as_ref(),
                &mut cx,
                &mut empty_bufs,
                &mut empty_meta,
            ),
            std::task::Poll::Ready(Ok(0))
        ));
        let mut poller = client.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();

        let quic_payload = vec![0x40, 1, 2, 3];
        assert_eq!(
            client.send_bare(server_addr, &quic_payload).unwrap(),
            quic_payload.len()
        );

        let mut buffer = [0_u8; 256];
        let mut bufs = [IoSliceMut::new(&mut buffer)];
        let mut meta = [RecvMeta {
            addr: server_addr,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| server.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("fake-TCP handshake and datagram delivery")
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(&buffer[..meta[0].len], quic_payload);
        assert_eq!(meta[0].addr, client_addr);
        assert!(!server.may_fragment());

        let bare_payload = [
            crate::physical::FORM_KEEPALIVE,
            0,
            0,
            0,
            7,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(
            client.send_bare(server_addr, &bare_payload).unwrap(),
            bare_payload.len()
        );
        let datagram = tokio::time::timeout(Duration::from_secs(2), bare_receiver.recv())
            .await
            .expect("bare physical route receives the established payload")
            .expect("bare physical route remains registered");
        assert_eq!(datagram.source, client_addr);
        assert_eq!(datagram.frame, bare_payload);

        let _ = client.raw.try_recv().unwrap();
        assert!(
            client
                .send_bare("[::1]:443".parse().unwrap(), b"wrong family")
                .is_err()
        );

        let transmit = quinn::udp::Transmit {
            destination: server_addr,
            ecn: None,
            contents: b"try-send",
            segment_size: None,
            src_ip: None,
        };
        quinn::AsyncUdpSocket::try_send(client.as_ref(), &transmit).unwrap();

        server.sessions.lock().unwrap().insert(
            remote(100),
            half_open(Instant::now() - quicp_handshake_timeout() - Duration::from_secs(1)),
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!server.sessions.lock().unwrap().contains_key(&remote(100)));
    }

    /// Builds a `QuicpSocket` over a UDP-backed stand-in raw socket so the
    /// session-table logic runs without raw-socket privileges.  No background
    /// reader/reaper tasks are spawned, keeping the tests deterministic.
    fn udp_test_socket(bind: SocketAddr, reset_key: Option<&[u8]>) -> io::Result<QuicpSocket> {
        let (raw, local) = crate::platform::quicp::RawTcpSocket::udp_backed_for_test(bind)?;
        Ok(QuicpSocket {
            local,
            raw: Arc::new(raw),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            received: Mutex::new(VecDeque::new()),
            bare_routes: Mutex::new(HashMap::new()),
            notify: Arc::new(Notify::new()),
            waiter: Mutex::new(None),
            reset_key: reset_key.map(ToOwned::to_owned),
        })
    }

    fn test_socket(bind: &str, reset_key: Option<&[u8]>) -> QuicpSocket {
        udp_test_socket(bind.parse().unwrap(), reset_key).unwrap()
    }

    fn transmit<'a>(destination: SocketAddr, contents: &'a [u8]) -> quinn::udp::Transmit<'a> {
        quinn::udp::Transmit {
            destination,
            ecn: None,
            contents,
            segment_size: None,
            src_ip: None,
        }
    }

    /// Drives a full fake-TCP handshake where the peer is the active opener,
    /// returning the `(peer_side, socket_side)` established sessions.
    fn established_pair(
        socket_local: SocketAddr,
        peer: SocketAddr,
        key: Option<&[u8]>,
    ) -> (
        tinect_fake_tcp::FakeTcpSession,
        tinect_fake_tcp::FakeTcpSession,
    ) {
        let mut peer_side =
            tinect_fake_tcp::FakeTcpSession::client_with_reset_key(peer, socket_local, 11, key)
                .unwrap();
        let syn = peer_side.start().unwrap();
        let syn_packet = tinect_fake_tcp::decode(&syn.bytes).unwrap();
        let (mut socket_side, syn_ack) =
            tinect_fake_tcp::FakeTcpSession::accept_packet_with_reset_key(syn_packet, 22, key)
                .unwrap();
        let ack = peer_side
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        socket_side.handle_inbound(&ack.bytes).unwrap();
        assert_eq!(socket_side.state(), tinect_fake_tcp::State::Established);
        assert_eq!(peer_side.state(), tinect_fake_tcp::State::Established);
        (peer_side, socket_side)
    }

    fn insert_session(
        socket: &QuicpSocket,
        peer: SocketAddr,
        state: tinect_fake_tcp::FakeTcpSession,
        pending: Vec<Vec<u8>>,
        handshake_reply: Option<tinect_fake_tcp::OutboundPacket>,
        last_activity: Instant,
    ) {
        socket.sessions.lock().unwrap().insert(
            peer,
            QuicpSession {
                state,
                pending: pending.into_iter().collect(),
                handshake_reply,
                last_activity,
            },
        );
    }

    fn session_state(socket: &QuicpSocket, peer: &SocketAddr) -> Option<tinect_fake_tcp::State> {
        socket
            .sessions
            .lock()
            .unwrap()
            .get(peer)
            .map(|session| session.state.state())
    }

    #[test]
    fn random_initial_sequence_draws_from_the_os_random_source() {
        // Only exercise the call: equality of two draws is a 2^-32 event, so
        // asserting inequality would introduce a flaky failure mode.
        let _ = (random_initial_sequence(), random_initial_sequence());
    }

    #[tokio::test]
    async fn receive_id_registration_rejects_zero_duplicate_and_allows_reuse() {
        let socket = test_socket("127.0.0.1:0", None);
        assert_eq!(
            socket.register_receive_id(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let _first = socket.register_receive_id(9).unwrap();
        assert_eq!(
            socket.register_receive_id(9).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        socket.unregister_receive_id(9);
        let _second = socket.register_receive_id(9).unwrap();
        socket.unregister_receive_id(9);
    }

    #[tokio::test]
    async fn divert_bare_drops_short_unrouted_and_unregistered_frames() {
        let socket = test_socket("127.0.0.1:0", None);
        let source: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        socket.divert_bare(source, &[1, 2, 3]); // too short to carry an id
        socket.divert_bare(source, &[0, 0, 0, 0, 9]); // id 9 not registered

        let mut receiver = socket.register_receive_id(9).unwrap();
        socket.divert_bare(source, &[0, 0, 0, 0, 9, 0xaa]);
        let datagram = receiver.recv().await.unwrap();
        assert_eq!(datagram.source, source);
        assert_eq!(datagram.frame, [0, 0, 0, 0, 9, 0xaa]);

        socket.unregister_receive_id(9);
        socket.divert_bare(source, &[0, 0, 0, 0, 9]);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn send_bare_creates_half_open_session_and_bounds_pending() {
        let socket = test_socket("127.0.0.1:0", None);
        let peer: SocketAddr = "127.0.0.1:45000".parse().unwrap();

        assert_eq!(socket.send_bare(peer, b"one").unwrap(), 3);
        {
            let sessions = socket.sessions.lock().unwrap();
            let session = sessions.get(&peer).unwrap();
            assert_eq!(session.state.state(), tinect_fake_tcp::State::SynSent);
            assert_eq!(session.pending.len(), 1);
            assert!(session.handshake_reply.is_some());
        }
        // Further frames replay the cached SYN and queue behind the handshake.
        for _ in 1..MAX_QUICP_PENDING_PER_SESSION {
            socket.send_bare(peer, b"x").unwrap();
        }
        assert_eq!(
            socket.send_bare(peer, b"x").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // A new session with a mismatched address family cannot be created.
        assert!(
            socket
                .send_bare("[::1]:443".parse().unwrap(), b"v6")
                .is_err()
        );
        assert_eq!(session_state(&socket, &"[::1]:443".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn send_bare_established_refreshes_activity_and_rejects_oversized_frames() {
        let socket = test_socket("127.0.0.1:0", None);
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:45001".parse().unwrap();
        let (_peer_side, socket_side) = established_pair(local, peer, None);
        let stale = Instant::now() - Duration::from_secs(1);
        insert_session(&socket, peer, socket_side, Vec::new(), None, stale);

        assert_eq!(socket.send_bare(peer, b"data").unwrap(), 4);
        assert!(
            socket
                .sessions
                .lock()
                .unwrap()
                .get(&peer)
                .unwrap()
                .last_activity
                > stale
        );
        // encapsulate() rejects frames beyond the IPv4 payload limit.
        let huge = vec![0_u8; 65_500];
        assert!(socket.send_bare(peer, &huge).is_err());
    }

    #[tokio::test]
    async fn try_send_queues_during_handshake_and_sends_once_established() {
        let socket = test_socket("127.0.0.1:0", None);
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:45002".parse().unwrap();

        // Unknown peer: the session is created and the datagram queued.
        quinn::AsyncUdpSocket::try_send(&socket, &transmit(peer, b"first")).unwrap();
        {
            let sessions = socket.sessions.lock().unwrap();
            let session = sessions.get(&peer).unwrap();
            assert_eq!(session.state.state(), tinect_fake_tcp::State::SynSent);
            assert_eq!(session.pending.len(), 1);
        }
        for _ in 1..MAX_QUICP_PENDING_PER_SESSION {
            quinn::AsyncUdpSocket::try_send(&socket, &transmit(peer, b"x")).unwrap();
        }
        assert_eq!(
            quinn::AsyncUdpSocket::try_send(&socket, &transmit(peer, b"x"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );

        // Established session: transmits go straight out and refresh activity.
        let (_peer_side, socket_side) = established_pair(local, peer, None);
        let stale = Instant::now() - Duration::from_secs(1);
        insert_session(&socket, peer, socket_side, Vec::new(), None, stale);
        quinn::AsyncUdpSocket::try_send(&socket, &transmit(peer, b"live")).unwrap();
        assert!(
            socket
                .sessions
                .lock()
                .unwrap()
                .get(&peer)
                .unwrap()
                .last_activity
                > stale
        );
        let huge = vec![0_u8; 65_500];
        assert!(quinn::AsyncUdpSocket::try_send(&socket, &transmit(peer, &huge)).is_err());
    }

    #[tokio::test]
    async fn send_and_receive_reject_new_peers_when_session_table_is_full() {
        let socket = test_socket("127.0.0.1:0", None);
        let now = Instant::now();
        let template = established(now);
        {
            let mut sessions = socket.sessions.lock().unwrap();
            for index in 0..MAX_QUICP_SESSIONS as u16 {
                sessions.insert(remote(index), template.clone());
            }
        }

        let peer: SocketAddr = "127.0.0.1:45003".parse().unwrap();
        assert_eq!(
            socket.send_bare(peer, b"x").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            quinn::AsyncUdpSocket::try_send(&socket, &transmit(peer, b"x"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );

        // An inbound SYN for a new peer is silently dropped as well.
        let mut foreign = tinect_fake_tcp::FakeTcpSession::client(peer, socket.local, 5).unwrap();
        let syn = foreign.start().unwrap();
        socket.receive_one(&syn.bytes).unwrap();
        assert_eq!(session_state(&socket, &peer), None);
        assert_eq!(socket.sessions.lock().unwrap().len(), MAX_QUICP_SESSIONS);
    }

    #[tokio::test]
    async fn receive_one_filters_garbage_and_completes_server_handshake() {
        let socket = test_socket("127.0.0.1:0", None);
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:46000".parse().unwrap();

        // Undecodable bytes are ignored.
        socket.receive_one(&[]).unwrap();
        socket.receive_one(&[0x45, 0, 0]).unwrap();

        let mut peer_side =
            tinect_fake_tcp::FakeTcpSession::client_with_reset_key(peer, local, 5, None).unwrap();
        let syn = peer_side.start().unwrap();

        // Non-SYN packets from unknown peers cannot open a session.
        let mut lone_ack = syn.packet.clone();
        lone_ack.flags = tinect_fake_tcp::flags::ACK;
        socket
            .receive_one(&tinect_fake_tcp::encode(&lone_ack).unwrap())
            .unwrap();
        assert!(socket.sessions.lock().unwrap().is_empty());

        // Packets addressed to a different local port are ignored.
        let mut wrong_port = syn.packet.clone();
        wrong_port.destination.set_port(local.port() + 1);
        socket
            .receive_one(&tinect_fake_tcp::encode(&wrong_port).unwrap())
            .unwrap();
        assert!(socket.sessions.lock().unwrap().is_empty());

        // A valid SYN opens a half-open session; retransmits replay the reply.
        socket.receive_one(&syn.bytes).unwrap();
        socket.receive_one(&syn.bytes).unwrap();
        let syn_ack = {
            let sessions = socket.sessions.lock().unwrap();
            assert_eq!(sessions.len(), 1);
            let session = sessions.get(&peer).unwrap();
            assert_eq!(session.state.state(), tinect_fake_tcp::State::SynReceived);
            session.handshake_reply.clone().unwrap()
        };

        // An ACK that does not complete the handshake is dropped.
        let mut early_ack = syn.packet.clone();
        early_ack.flags = tinect_fake_tcp::flags::ACK;
        socket
            .receive_one(&tinect_fake_tcp::encode(&early_ack).unwrap())
            .unwrap();
        assert_eq!(
            session_state(&socket, &peer),
            Some(tinect_fake_tcp::State::SynReceived)
        );

        // The completing ACK establishes the session without sending a reply.
        let ack = peer_side
            .handle_inbound(&syn_ack.bytes)
            .unwrap()
            .reply
            .unwrap();
        socket.receive_one(&ack.bytes).unwrap();
        assert_eq!(
            session_state(&socket, &peer),
            Some(tinect_fake_tcp::State::Established)
        );

        // A replayed SYN|ACK is answered from the cached handshake reply
        // without disturbing the established session.
        let mut replayed = ack.packet.clone();
        replayed.flags = tinect_fake_tcp::flags::SYN | tinect_fake_tcp::flags::ACK;
        socket
            .receive_one(&tinect_fake_tcp::encode(&replayed).unwrap())
            .unwrap();
        assert_eq!(
            session_state(&socket, &peer),
            Some(tinect_fake_tcp::State::Established)
        );

        // Established payloads land in the decoded receive queue...
        let data = peer_side.encapsulate(&[0x40, 1, 2]).unwrap();
        socket.receive_one(&data.bytes).unwrap();
        assert_eq!(socket.received.lock().unwrap().len(), 1);

        // ...unless the queue is already full.
        {
            let mut received = socket.received.lock().unwrap();
            received.clear();
            for _ in 0..MAX_QUICP_RECEIVED {
                received.push_back((peer, vec![0]));
            }
        }
        let data = peer_side.encapsulate(&[0x40, 3]).unwrap();
        socket.receive_one(&data.bytes).unwrap();
        assert_eq!(socket.received.lock().unwrap().len(), MAX_QUICP_RECEIVED);
    }

    #[tokio::test]
    async fn receive_one_diverts_bare_physical_payloads_to_registered_routes() {
        let socket = test_socket("127.0.0.1:0", None);
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:46001".parse().unwrap();
        let (mut peer_side, socket_side) = established_pair(local, peer, None);
        insert_session(&socket, peer, socket_side, Vec::new(), None, Instant::now());

        let mut receiver = socket.register_receive_id(7).unwrap();
        let mut bare = vec![crate::physical::FORM_KEEPALIVE, 0, 0, 0, 7];
        bare.resize(1 + 4 + 8 + 16, 0);
        let packet = peer_side.encapsulate(&bare).unwrap();
        socket.receive_one(&packet.bytes).unwrap();
        let datagram = receiver.recv().await.unwrap();
        assert_eq!(datagram.source, peer);
        assert_eq!(datagram.frame, bare);
        assert!(socket.received.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn receive_one_removes_session_only_on_authenticated_reset() {
        let key = b"rst-key";
        let socket = test_socket("127.0.0.1:0", Some(key));
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:46002".parse().unwrap();
        let (mut peer_side, socket_side) = established_pair(local, peer, Some(key));
        insert_session(&socket, peer, socket_side, Vec::new(), None, Instant::now());

        // An RST without a valid authentication tag is dropped.
        let reset = peer_side.reset().unwrap();
        let mut forged = reset.packet.clone();
        forged.reset_auth = None;
        socket
            .receive_one(&tinect_fake_tcp::encode(&forged).unwrap())
            .unwrap();
        assert_eq!(
            session_state(&socket, &peer),
            Some(tinect_fake_tcp::State::Established)
        );

        // The authenticated reset tears the session down.
        socket.receive_one(&reset.bytes).unwrap();
        assert_eq!(session_state(&socket, &peer), None);
    }

    #[tokio::test]
    async fn receive_one_client_handshake_establishes_and_drains_pending() {
        let socket = test_socket("127.0.0.1:0", None);
        let peer: SocketAddr = "127.0.0.1:46003".parse().unwrap();

        socket.send_bare(peer, b"queued-1").unwrap();
        socket.send_bare(peer, b"queued-2").unwrap();
        let syn = {
            let sessions = socket.sessions.lock().unwrap();
            sessions
                .get(&peer)
                .unwrap()
                .handshake_reply
                .clone()
                .unwrap()
        };

        let (_server, syn_ack) = tinect_fake_tcp::FakeTcpSession::accept(&syn.bytes, 77).unwrap();
        socket.receive_one(&syn_ack.bytes).unwrap();
        let sessions = socket.sessions.lock().unwrap();
        let session = sessions.get(&peer).unwrap();
        assert_eq!(session.state.state(), tinect_fake_tcp::State::Established);
        assert!(session.pending.is_empty());
        // The final handshake ACK replaces the SYN as the cached reply.
        assert_eq!(
            session.handshake_reply.as_ref().unwrap().packet.flags,
            tinect_fake_tcp::flags::ACK
        );
    }

    #[tokio::test]
    async fn receive_one_reports_drain_failures() {
        let socket = test_socket("127.0.0.1:0", None);
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:46004".parse().unwrap();

        // A half-open client session holding a frame too large to encapsulate.
        let mut state = tinect_fake_tcp::FakeTcpSession::client(local, peer, 3).unwrap();
        let syn = state.start().unwrap();
        let huge = vec![0_u8; 65_500];
        insert_session(
            &socket,
            peer,
            state,
            vec![huge],
            Some(syn.clone()),
            Instant::now(),
        );

        let (_server, syn_ack) = tinect_fake_tcp::FakeTcpSession::accept(&syn.bytes, 9).unwrap();
        assert!(socket.receive_one(&syn_ack.bytes).is_err());
        // The session still advanced; only the drain failed.
        assert_eq!(
            session_state(&socket, &peer),
            Some(tinect_fake_tcp::State::Established)
        );
    }

    #[tokio::test]
    async fn poll_recv_handles_empty_buffers_and_waits_for_notify() {
        let socket = test_socket("127.0.0.1:0", None);
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:47000".parse().unwrap();
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);

        // Empty buffer or metadata slices complete immediately with zero.
        let mut empty_bufs: [IoSliceMut<'_>; 0] = [];
        let mut meta = [RecvMeta {
            addr: peer,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        assert!(matches!(
            quinn::AsyncUdpSocket::poll_recv(&socket, &mut cx, &mut empty_bufs, &mut meta),
            std::task::Poll::Ready(Ok(0))
        ));
        let mut buffer = [0_u8; 16];
        let mut empty_meta: [RecvMeta; 0] = [];
        {
            let mut bufs = [IoSliceMut::new(&mut buffer)];
            assert!(matches!(
                quinn::AsyncUdpSocket::poll_recv(&socket, &mut cx, &mut bufs, &mut empty_meta),
                std::task::Poll::Ready(Ok(0))
            ));
        }

        // With capacity available, an empty queue parks the waiter.
        let mut bufs = [IoSliceMut::new(&mut buffer)];
        assert!(
            quinn::AsyncUdpSocket::poll_recv(&socket, &mut cx, &mut bufs, &mut meta).is_pending()
        );
        // A wakeup without data re-registers the waiter and stays pending.
        socket.notify.notify_waiters();
        assert!(
            quinn::AsyncUdpSocket::poll_recv(&socket, &mut cx, &mut bufs, &mut meta).is_pending()
        );
        // A decoded datagram plus a wakeup completes the poll.
        socket
            .received
            .lock()
            .unwrap()
            .push_back((peer, vec![0x40, 7]));
        socket.notify.notify_waiters();
        assert!(matches!(
            quinn::AsyncUdpSocket::poll_recv(&socket, &mut cx, &mut bufs, &mut meta),
            std::task::Poll::Ready(Ok(1))
        ));
        assert_eq!(meta[0].len, 2);
        assert_eq!(meta[0].addr, peer);
        assert_eq!(meta[0].dst_ip, Some(local.ip()));
        assert_eq!(&buffer[..2], &[0x40, 7]);
    }

    #[tokio::test]
    async fn wildcard_bind_resolves_outbound_source_and_rejects_family_mismatch() {
        let socket = test_socket("0.0.0.0:0", None);
        assert!(socket.local.ip().is_unspecified());
        let source = socket
            .outbound_local("127.0.0.1:443".parse().unwrap())
            .unwrap();
        assert!(!source.ip().is_unspecified());
        assert_eq!(source.port(), socket.local.port());
        assert!(socket.outbound_local("[::1]:443".parse().unwrap()).is_err());

        // A specified bind address is used verbatim.
        let pinned = test_socket("127.0.0.1:0", None);
        let local = pinned.local_addr().unwrap();
        assert_eq!(
            pinned
                .outbound_local("127.0.0.1:443".parse().unwrap())
                .unwrap(),
            local
        );
        assert!(!pinned.may_fragment());
    }

    #[tokio::test]
    async fn io_poller_reports_writable() {
        let socket = Arc::new(test_socket("127.0.0.1:0", None));
        let mut poller = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn drop_resets_open_sessions_without_panicking() {
        let socket = test_socket("127.0.0.1:0", None);
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "127.0.0.1:48000".parse().unwrap();
        let (_peer_side, socket_side) = established_pair(local, peer, None);
        insert_session(&socket, peer, socket_side, Vec::new(), None, Instant::now());
        let half_open_peer: SocketAddr = "127.0.0.1:48001".parse().unwrap();
        insert_session(
            &socket,
            half_open_peer,
            half_open(Instant::now()).state,
            Vec::new(),
            None,
            Instant::now(),
        );
        drop(socket);
    }

    #[tokio::test]
    async fn oversized_ipv6_datagrams_are_ignored_for_pmtud_convergence() {
        let Ok(socket) = udp_test_socket("[::1]:0".parse().unwrap(), None) else {
            // IPv6 loopback unavailable in this environment.
            return;
        };
        let local = socket.local_addr().unwrap();
        let peer: SocketAddr = "[::1]:49000".parse().unwrap();

        // try_send on an established session swallows EMSGSIZE so Quinn's PMTUD
        // can converge instead of erroring the connection.
        let (_peer_side, socket_side) = established_pair(local, peer, None);
        insert_session(&socket, peer, socket_side, Vec::new(), None, Instant::now());
        let huge = vec![0_u8; 65_500];
        quinn::AsyncUdpSocket::try_send(&socket, &transmit(peer, &huge)).unwrap();

        // drain_pending swallows EMSGSIZE the same way.
        let other: SocketAddr = "[::1]:49001".parse().unwrap();
        let mut state = tinect_fake_tcp::FakeTcpSession::client(local, other, 3).unwrap();
        let syn = state.start().unwrap();
        insert_session(
            &socket,
            other,
            state,
            vec![huge],
            Some(syn.clone()),
            Instant::now(),
        );
        let (_server, syn_ack) = tinect_fake_tcp::FakeTcpSession::accept(&syn.bytes, 9).unwrap();
        socket.receive_one(&syn_ack.bytes).unwrap();
        assert_eq!(
            session_state(&socket, &other),
            Some(tinect_fake_tcp::State::Established)
        );
    }
}
