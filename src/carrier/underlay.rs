//! Shared UDP underlay for Quinn and the RFC-0014 bare Physical carrier.
use super::{BareDatagram, CarrierError, InboundPacketKind};
use crate::config::CarrierProtocol;
use quinn::{AsyncUdpSocket, Endpoint, ServerConfig, UdpPoller};
use std::{
    collections::{HashMap, hash_map::Entry},
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::sync::{Notify, mpsc};

/// Quinn and bare Physical consume the same socket. A packet with QUIC's
/// fixed bit is returned to Quinn; a registered RFC-0015 form is routed by
/// its clear receive-id and never reaches Quinn.
#[derive(Debug)]
pub struct MixedUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    routes: Mutex<HashMap<u32, mpsc::Sender<BareDatagram>>>,
    quic_packets: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    shutdown: Arc<Notify>,
}

impl MixedUdpSocket {
    fn new(socket: std::net::UdpSocket) -> io::Result<Arc<Self>> {
        socket.set_nonblocking(true)?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        let (quic_sender, quic_packets) = mpsc::channel(1024);
        let mixed = Arc::new(Self {
            io: io.clone(),
            routes: Mutex::new(HashMap::new()),
            quic_packets: Mutex::new(quic_packets),
            shutdown: Arc::new(Notify::new()),
        });
        // Keep the demultiplexer task from keeping the socket alive after the
        // endpoint and all carrier handles have been dropped.
        let reader = Arc::downgrade(&mixed);
        let reader_io = io.clone();
        let reader_shutdown = mixed.shutdown.clone();
        tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("mixed UDP socket requires a Tokio runtime"))?
            .spawn(async move {
                let mut packet = vec![0u8; 65_535];
                loop {
                    let received = tokio::select! {
                        result = reader_io.recv_from(&mut packet) => result,
                        _ = reader_shutdown.notified() => break,
                    };
                    let Ok((len, source)) = received else {
                        break;
                    };
                    let Some(reader) = reader.upgrade() else {
                        break;
                    };
                    match super::classify_inbound_packet(&packet[..len]) {
                        InboundPacketKind::Quic => {
                            // Never let an unauthenticated QUIC flood stop the
                            // reader from servicing bare Physical packets.
                            let _ = quic_sender.try_send((source, packet[..len].to_vec()));
                        }
                        InboundPacketKind::BarePhysical => reader.divert(source, &packet[..len]),
                        InboundPacketKind::Drop => {}
                    }
                }
            });
        Ok(mixed)
    }

    pub(crate) fn register_receive_id(&self, id: u32) -> io::Result<mpsc::Receiver<BareDatagram>> {
        if id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero receive id",
            ));
        }
        let (sender, receiver) = mpsc::channel(1024);
        match self.routes.lock().expect("bare route lock").entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(sender);
            }
            Entry::Occupied(_) => {
                // Do not replace the existing sender before returning an
                // error.  A duplicate registration is a local failure, not
                // a reason to disconnect the already-established carrier.
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "receive id already registered",
                ));
            }
        }
        Ok(receiver)
    }

    pub(crate) fn unregister_receive_id(&self, id: u32) {
        self.routes.lock().expect("bare route lock").remove(&id);
    }

    pub(crate) fn send_bare(&self, remote: SocketAddr, frame: &[u8]) -> io::Result<usize> {
        self.io.try_send_to(frame, remote)
    }

    fn divert(&self, source: SocketAddr, packet: &[u8]) {
        if packet.len() < 5 {
            return;
        }
        let id = u32::from_be_bytes(packet[1..5].try_into().expect("receive id"));
        let sender = self
            .routes
            .lock()
            .expect("bare route lock")
            .get(&id)
            .cloned();
        if let Some(sender) = sender {
            let _ = sender.try_send(BareDatagram {
                source,
                frame: packet.to_vec(),
            });
        }
    }
}

impl Drop for MixedUdpSocket {
    fn drop(&mut self) {
        // `notify_waiters` loses the notification when the reader task has
        // been spawned but has not reached its `select!` yet.  That race is
        // common for a failed outbound attempt, and would leave the reader
        // holding `reader_io` (and therefore the UDP socket) forever.  There
        // is exactly one reader, so retain a permit until it observes the
        // shutdown with `notify_one`.
        self.shutdown.notify_one();
    }
}

#[derive(Debug)]
struct MixedUdpPoller(Arc<MixedUdpSocket>);
impl UdpPoller for MixedUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for MixedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(MixedUdpPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP segmentation is unsupported by mixed carrier",
            ));
        }
        self.io
            .try_send_to(transmit.contents, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut packets = self.quic_packets.lock().expect("QUIC packet queue lock");
        match Pin::new(&mut *packets).poll_recv(cx) {
            Poll::Ready(Some((source, packet))) => {
                let len = packet.len();
                if bufs[0].len() < len {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "QUIC datagram exceeds receive buffer",
                    )));
                }
                bufs[0][..len].copy_from_slice(&packet);
                meta[0] = quinn::udp::RecvMeta {
                    addr: source,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mixed UDP reader stopped",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
    fn may_fragment(&self) -> bool {
        true
    }
}

/// Build a Quinn endpoint on the selected underlay, retaining the shared
/// socket when the endpoint is ordinary UDP.
pub(super) fn open_endpoint_with_bare(
    protocol: CarrierProtocol,
    bind: SocketAddr,
    server: ServerConfig,
    fwmark: Option<u32>,
    carrier_interface: Option<&str>,
    fake_tcp_reset_key: Option<&[u8]>,
) -> Result<(Endpoint, Option<Arc<super::BareEndpoint>>), CarrierError> {
    match protocol {
        CarrierProtocol::Quic | CarrierProtocol::QuicFull => {
            open_udp(bind, server, fwmark, carrier_interface)
        }
        CarrierProtocol::QuicFakeTcp | CarrierProtocol::QuicFullFakeTcp => {
            open_quicp(bind, server, fwmark, fake_tcp_reset_key)
        }
    }
}

fn open_udp(
    bind: SocketAddr,
    server: ServerConfig,
    fwmark: Option<u32>,
    carrier_interface: Option<&str>,
) -> Result<(Endpoint, Option<Arc<super::BareEndpoint>>), CarrierError> {
    let socket =
        std::net::UdpSocket::bind(bind).map_err(|e| CarrierError::Certificate(e.to_string()))?;
    set_path_mtu_discovery(&socket).map_err(|e| CarrierError::Certificate(e.to_string()))?;
    if let Some(mark) = fwmark {
        super::set_socket_mark(&socket, mark)?;
    }
    if let Some(interface) = carrier_interface {
        super::bind_socket_interface(&socket, interface)?;
    }
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .grease_quic_bit(false)
        .supported_versions(vec![1]);
    let mixed =
        MixedUdpSocket::new(socket).map_err(|e| CarrierError::Certificate(e.to_string()))?;
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(server),
        mixed.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| CarrierError::Certificate(e.to_string()))?;
    Ok((
        endpoint,
        Some(Arc::new(super::BareEndpoint {
            inner: super::BareEndpointInner::Udp(mixed),
        })),
    ))
}

#[cfg(target_os = "linux")]
fn set_path_mtu_discovery(socket: &std::net::UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    // IPv6 routers never fragment packets. Linux therefore already applies
    // the required path-MTU behaviour to IPv6 UDP sockets, and some network
    // namespaces reject an explicit IPV6_MTU_DISCOVER update with
    // EADDRNOTAVAIL even though ordinary IPv6 UDP is usable. IPv4 needs the
    // explicit DF policy because otherwise oversized probes may fragment.
    if socket.local_addr()?.is_ipv6() {
        return Ok(());
    }
    let value = libc::IP_PMTUDISC_DO;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn set_path_mtu_discovery(_socket: &std::net::UdpSocket) -> io::Result<()> {
    Ok(())
}

fn open_quicp(
    bind: SocketAddr,
    server: ServerConfig,
    fwmark: Option<u32>,
    reset_key: Option<&[u8]>,
) -> Result<(Endpoint, Option<Arc<super::BareEndpoint>>), CarrierError> {
    #[cfg(target_os = "linux")]
    {
        let socket = super::quicp::QuicpSocket::new(bind, fwmark, reset_key)?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config
            .grease_quic_bit(false)
            .supported_versions(vec![1]);
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server),
            socket.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| CarrierError::Protocol(error.to_string()))?;
        Ok((
            endpoint,
            Some(Arc::new(super::BareEndpoint {
                inner: super::BareEndpointInner::FakeTcp(socket),
            })),
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bind, server, fwmark, reset_key);
        Err(CarrierError::Protocol(
            "fake-TCP is supported only on Linux".into(),
        ))
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::set_path_mtu_discovery;
    use super::{CarrierError, MixedUdpSocket, open_endpoint_with_bare};
    use crate::{config::CarrierProtocol, physical::FORM_FORWARD};
    use quinn::AsyncUdpSocket;
    use std::{
        io::{self, IoSliceMut},
        net::UdpSocket,
        task::{Context, Poll, Waker},
        time::Duration,
    };

    fn test_server_config() -> quinn::ServerConfig {
        super::super::install_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["tinect".into()]).unwrap();
        let chain = vec![cert.cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        quinn::ServerConfig::with_single_cert(chain, key).unwrap()
    }

    #[tokio::test]
    async fn dropping_before_reader_poll_releases_udp_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();

        // Do not yield before dropping: this exercises the race where the
        // reader task has not polled its shutdown future yet.
        drop(mixed);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if UdpSocket::bind(address).is_ok() {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn duplicate_receive_id_keeps_the_existing_route_alive() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        let mut receiver = mixed.register_receive_id(7).unwrap();

        let error = mixed.register_receive_id(7).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

        mixed.divert(
            "127.0.0.1:9000".parse().unwrap(),
            &[FORM_FORWARD, 0, 0, 0, 7, 1],
        );
        let delivered = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("original route must remain registered")
            .expect("original sender must remain open");
        assert_eq!(delivered.frame, vec![FORM_FORWARD, 0, 0, 0, 7, 1]);
    }

    #[tokio::test]
    async fn underlay_handles_registration_send_and_empty_datagrams() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();

        assert_eq!(mixed.local_addr().unwrap(), address);
        assert!(mixed.may_fragment());
        assert_eq!(
            mixed.register_receive_id(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        mixed.unregister_receive_id(91);
        mixed.divert("127.0.0.1:9000".parse().unwrap(), &[]);
        mixed.divert(
            "127.0.0.1:9000".parse().unwrap(),
            &[FORM_FORWARD, 0, 0, 0, 91],
        );

        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let transmit = quinn::udp::Transmit {
            destination: peer.local_addr().unwrap(),
            ecn: None,
            contents: b"underlay",
            segment_size: None,
            src_ip: None,
        };
        loop {
            match mixed.try_send(&transmit) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("unexpected send error: {error}"),
            }
        }
        let mut received = [0; 32];
        let (len, source) = peer.recv_from(&mut received).unwrap();
        assert_eq!(&received[..len], b"underlay");
        assert_eq!(source, address);

        let segmented = quinn::udp::Transmit {
            segment_size: Some(4),
            ..transmit
        };
        assert_eq!(
            mixed.try_send(&segmented).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let sent = loop {
            match mixed.send_bare(peer.local_addr().unwrap(), b"bare") {
                Ok(sent) => break sent,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("unexpected bare send error: {error}"),
            }
        };
        assert_eq!(sent, 4);
        let (len, _) = peer.recv_from(&mut received).unwrap();
        assert_eq!(&received[..len], b"bare");

        let mut empty_bufs = [];
        let mut empty_meta = [];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            mixed.poll_recv(&mut cx, &mut empty_bufs, &mut empty_meta),
            Poll::Ready(Ok(0))
        ));
    }

    #[tokio::test]
    async fn poll_recv_delivers_quic_packets_and_reports_small_buffers() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(&[0x40, 1, 2, 3], address).unwrap();

        let mut packet = [0; 16];
        let mut bufs = [IoSliceMut::new(&mut packet)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let mut cx = Context::from_waker(Waker::noop());
        let received = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match mixed.poll_recv(&mut cx, &mut bufs, &mut meta) {
                    Poll::Ready(result) => break result,
                    Poll::Pending => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("QUIC packet should reach the abstract socket")
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(&packet[..meta[0].len], &[0x40, 1, 2, 3]);
        assert_eq!(meta[0].addr, peer.local_addr().unwrap());

        peer.send_to(&[0x40, 5, 6, 7], address).unwrap();
        let mut small_packet = [0; 2];
        let mut small_bufs = [IoSliceMut::new(&mut small_packet)];
        let mut small_meta = [quinn::udp::RecvMeta::default()];
        let error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match mixed.poll_recv(&mut cx, &mut small_bufs, &mut small_meta) {
                    Poll::Ready(result) => break result,
                    Poll::Pending => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("small-buffer result should be available")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn poll_recv_reports_reader_shutdown() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        mixed.quic_packets.lock().unwrap().close();
        let mut packet = [0; 8];
        let mut bufs = [IoSliceMut::new(&mut packet)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let mut cx = Context::from_waker(Waker::noop());
        let error = match mixed.poll_recv(&mut cx, &mut bufs, &mut meta) {
            Poll::Ready(Err(error)) => error,
            result => panic!("expected closed queue, got {result:?}"),
        };
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_mtu_discovery_is_enabled_for_ipv4_and_left_implicit_for_ipv6() {
        let ipv4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_path_mtu_discovery(&ipv4).unwrap();
        let ipv6 = UdpSocket::bind("[::1]:0").unwrap();
        set_path_mtu_discovery(&ipv6).unwrap();
    }

    #[tokio::test]
    async fn reader_ignores_dropped_packets_and_keeps_running() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();

        // 0x07 is above FORM_FEC_REPAIR and lacks the QUIC fixed bit: Drop.
        peer.send_to(&[0x07, 1, 2, 3], address).unwrap();
        // A bare form with a zero receive id is dropped as well.
        let mut zero_id = vec![FORM_FORWARD, 0, 0, 0, 0];
        zero_id.resize(29, 0);
        peer.send_to(&zero_id, address).unwrap();

        // The reader must survive both drops and still deliver QUIC packets.
        peer.send_to(&[0x40, 9, 9, 9], address).unwrap();
        let mut packet = [0; 16];
        let mut bufs = [IoSliceMut::new(&mut packet)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let mut cx = Context::from_waker(Waker::noop());
        let received = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match mixed.poll_recv(&mut cx, &mut bufs, &mut meta) {
                    Poll::Ready(result) => break result,
                    Poll::Pending => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("reader must survive dropped packets")
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(&packet[..meta[0].len], &[0x40, 9, 9, 9]);
    }

    #[tokio::test]
    async fn divert_drops_datagrams_when_the_route_queue_is_full() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        let mut receiver = mixed.register_receive_id(3).unwrap();

        // The route queue holds 1024 datagrams; anything beyond is dropped.
        for sequence in 0..1100u32 {
            let mut frame = vec![FORM_FORWARD, 0, 0, 0, 3];
            frame.extend_from_slice(&sequence.to_be_bytes());
            mixed.divert("127.0.0.1:9000".parse().unwrap(), &frame);
        }
        for sequence in 0..1024u32 {
            let delivered = receiver.recv().await.expect("queued datagram");
            assert_eq!(delivered.frame[5..], sequence.to_be_bytes());
        }
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn unregistered_receive_id_can_be_registered_again() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        let receiver = mixed.register_receive_id(5).unwrap();
        mixed.unregister_receive_id(5);
        drop(receiver);

        let mut receiver = mixed.register_receive_id(5).unwrap();
        mixed.divert(
            "127.0.0.1:9000".parse().unwrap(),
            &[FORM_FORWARD, 0, 0, 0, 5, 42],
        );
        let delivered = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("re-registered route must accept datagrams")
            .expect("sender must be open");
        assert_eq!(delivered.frame, vec![FORM_FORWARD, 0, 0, 0, 5, 42]);
    }

    #[tokio::test]
    async fn io_poller_reports_a_writable_udp_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        let mut poller = mixed.create_io_poller();
        let mut cx = Context::from_waker(Waker::noop());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match poller.as_mut().poll_writable(&mut cx) {
                    Poll::Ready(result) => break result,
                    Poll::Pending => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("UDP socket should become writable")
        .unwrap();
    }

    #[tokio::test]
    async fn poll_recv_returns_zero_when_meta_is_empty() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mixed = MixedUdpSocket::new(socket).unwrap();
        let mut packet = [0; 8];
        let mut bufs = [IoSliceMut::new(&mut packet)];
        let mut empty_meta = [];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            mixed.poll_recv(&mut cx, &mut bufs, &mut empty_meta),
            Poll::Ready(Ok(0))
        ));
    }

    #[tokio::test]
    async fn open_endpoint_with_bare_binds_quic_on_the_shared_socket() {
        for protocol in [CarrierProtocol::Quic, CarrierProtocol::QuicFull] {
            let (endpoint, bare) = open_endpoint_with_bare(
                protocol,
                "127.0.0.1:0".parse().unwrap(),
                test_server_config(),
                None,
                None,
                None,
            )
            .expect("QUIC underlay should open on loopback");
            assert!(endpoint.local_addr().unwrap().is_ipv4());
            let bare = bare.expect("UDP underlay must expose the bare endpoint");
            let receiver = bare.register_receive_id(11).unwrap();
            bare.unregister_receive_id(11);
            drop(receiver);
            endpoint.close(0u32.into(), b"");
        }
    }

    #[tokio::test]
    async fn open_endpoint_with_bare_reports_bind_conflicts() {
        let blocker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = open_endpoint_with_bare(
            CarrierProtocol::Quic,
            blocker.local_addr().unwrap(),
            test_server_config(),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CarrierError::Certificate(_)));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fake_tcp_endpoint_uses_the_linux_quicp_underlay() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let (endpoint, bare) = open_endpoint_with_bare(
            CarrierProtocol::QuicFakeTcp,
            "127.0.0.1:0".parse().unwrap(),
            test_server_config(),
            None,
            None,
            Some(b"underlay-test-reset"),
        )
        .unwrap();
        assert!(endpoint.local_addr().unwrap().is_ipv4());
        let bare = bare.expect("fake TCP endpoints expose their bare carrier");
        let _receiver = bare.register_receive_id(77).unwrap();
        bare.unregister_receive_id(77);
        let _ = bare.send("127.0.0.1:9".parse().unwrap(), &[1, 2, 3, 4, 5]);
        endpoint.close(0u32.into(), b"test complete");
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn open_endpoint_with_bare_rejects_fwmark_outside_linux() {
        let error = open_endpoint_with_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            test_server_config(),
            Some(17),
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CarrierError::Protocol(_)));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn open_endpoint_with_bare_rejects_unknown_carrier_interface() {
        let error = open_endpoint_with_bare(
            CarrierProtocol::Quic,
            "127.0.0.1:0".parse().unwrap(),
            test_server_config(),
            None,
            Some("tinect-nonexistent0"),
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CarrierError::Protocol(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn fake_tcp_protocols_are_rejected_outside_linux() {
        for protocol in [
            CarrierProtocol::QuicFakeTcp,
            CarrierProtocol::QuicFullFakeTcp,
        ] {
            let error = open_endpoint_with_bare(
                protocol,
                "127.0.0.1:0".parse().unwrap(),
                test_server_config(),
                None,
                None,
                None,
            )
            .unwrap_err();
            assert!(matches!(error, CarrierError::Protocol(_)));
        }
    }
}
