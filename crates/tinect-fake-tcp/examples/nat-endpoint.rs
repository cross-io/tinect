//! Privileged Linux-only endpoint used by `tests/remote_fake_tcp_nat.sh`.
//! It is deliberately an example, not part of the library API.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nat-endpoint is only available on Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::RawFd;
    use std::time::{Duration, Instant};
    use tinect_fake_tcp::{FakeTcpSession, State};

    const TIMEOUT: Duration = Duration::from_secs(5);
    const TEST_SOCKET_MARK: libc::c_uint = 0x5443;
    // This key exists only to exercise authenticated-reset wire behavior in
    // the isolated `raw-test` fixture. Production leaves its reset key empty.
    const TEST_RESET_KEY: [u8; 32] = [0x52; 32];

    struct RawIp(RawFd);
    impl Drop for RawIp {
        fn drop(&mut self) {
            // SAFETY: this object uniquely owns the file descriptor.
            unsafe { libc::close(self.0) };
        }
    }
    impl RawIp {
        fn open() -> io::Result<Self> {
            // SAFETY: arguments are constant Linux socket parameters.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
            if fd < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("open raw TCP socket: {}", io::Error::last_os_error()),
                ));
            }
            let enabled: libc::c_int = 1;
            // Mark test-originated packets so the namespace firewall can drop
            // only kernel-generated RSTs, not this endpoint's closing RST.
            // SAFETY: TEST_SOCKET_MARK is a valid SO_MARK value for this socket.
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&TEST_SOCKET_MARK as *const libc::c_uint).cast(),
                    std::mem::size_of_val(&TEST_SOCKET_MARK) as libc::socklen_t,
                )
            } < 0
            {
                let error = io::Error::last_os_error();
                // SAFETY: `fd` has not been wrapped and must be closed on this error path.
                unsafe { libc::close(fd) };
                return Err(io::Error::new(
                    error.kind(),
                    format!("mark raw test socket: {error}"),
                ));
            }
            // The packet header supplies the source address. IP_TRANSPARENT
            // permits that explicit source on the test-only raw transmitter;
            // namespace setup still assigns it normally and routes it via NAT.
            // SAFETY: `enabled` is a valid integer option value for this socket.
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            } < 0
            {
                let error = io::Error::last_os_error();
                // SAFETY: `fd` has not been wrapped and must be closed on this error path.
                unsafe { libc::close(fd) };
                return Err(io::Error::new(
                    error.kind(),
                    format!("enable IP_TRANSPARENT: {error}"),
                ));
            }
            // SAFETY: `enabled` is a valid integer option value for this socket.
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            } < 0
            {
                let error = io::Error::last_os_error();
                // SAFETY: `fd` has not been wrapped and must be closed on this error path.
                unsafe { libc::close(fd) };
                return Err(io::Error::new(
                    error.kind(),
                    format!("enable IP_HDRINCL: {error}"),
                ));
            }
            Ok(Self(fd))
        }

        fn send(&self, packet: &[u8], destination: SocketAddr) -> io::Result<()> {
            let address = socket_address(destination)?;
            // SAFETY: packet and sockaddr are valid for the duration of this call.
            let written = unsafe {
                libc::sendto(
                    self.0,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&address as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if written == packet.len() as isize {
                Ok(())
            } else if written < 0 {
                let error = io::Error::last_os_error();
                Err(io::Error::new(
                    error.kind(),
                    format!("send raw IP packet: {error}"),
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short raw-IP write",
                ))
            }
        }

        fn receive(&self, timeout: Duration) -> io::Result<Vec<u8>> {
            let mut poll = libc::pollfd {
                fd: self.0,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd is valid and points to one element.
            let ready = unsafe { libc::poll(&mut poll, 1, timeout.as_millis() as libc::c_int) };
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "raw-IP receive timed out",
                ));
            }
            if ready < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buffer = vec![0; 65_535];
            // SAFETY: buffer is writable for its full length.
            let read = unsafe { libc::recv(self.0, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            if read < 0 {
                return Err(io::Error::last_os_error());
            }
            buffer.truncate(read as usize);
            Ok(buffer)
        }
    }

    fn socket_address(address: SocketAddr) -> io::Result<libc::sockaddr_in> {
        let SocketAddr::V4(address) = address else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv4 is required",
            ));
        };
        Ok(libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            // Linux ignores this field for raw IPv4 sockets; it must stay zero.
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            },
            sin_zero: [0; 8],
        })
    }

    fn arg(name: &str) -> String {
        let mut args = std::env::args().skip(2);
        while let Some(argument) = args.next() {
            if argument == name {
                return args
                    .next()
                    .unwrap_or_else(|| panic!("missing value for {name}"));
            }
        }
        panic!("missing {name}");
    }
    fn optional_arg(name: &str) -> Option<String> {
        let mut args = std::env::args().skip(2);
        while let Some(argument) = args.next() {
            if argument == name {
                return args.next();
            }
        }
        None
    }
    fn v4(value: &str) -> SocketAddr {
        let address: SocketAddr = value.parse().expect("invalid socket address");
        assert!(address.is_ipv4(), "only IPv4 is used by the NAT test");
        address
    }
    fn wait_for<F>(socket: &RawIp, mut operation: F) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> io::Result<bool>,
    {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "expected fake-TCP packet not received",
                ));
            }
            match socket
                .receive(remaining)
                .and_then(|packet| operation(&packet))
            {
                Ok(true) => return Ok(()),
                Ok(false) => continue,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => return Err(error),
                Err(error) => return Err(error),
            }
        }
    }

    fn client() -> io::Result<()> {
        let local = v4(&arg("--local"));
        let remote = v4(&arg("--remote"));
        let payload = arg("--payload").into_bytes();
        let socket = RawIp::open()?;
        let mut session =
            FakeTcpSession::client(local, remote, 0x1234_5678).expect("valid IPv4 tuple");
        session.set_reset_key_for_test(TEST_RESET_KEY);
        socket.send(&session.start().unwrap().bytes, remote)?;
        wait_for(&socket, |packet| {
            let event = match session.handle_inbound(packet) {
                Ok(event) => event,
                Err(_) => return Ok(false),
            };
            if let Some(reply) = event.reply {
                socket.send(&reply.bytes, remote)?;
            }
            Ok(session.state() == State::Established)
        })?;
        // One data segment is enough: the peer pure-ACKs every data segment
        // (no delayed coalesce), which also exercises conntrack reverse SNAT.
        socket.send(&session.encapsulate(&payload).unwrap().bytes, remote)?;
        wait_for(&socket, |packet| {
            if session.handle_inbound(packet).is_ok() {
                Ok(true)
            } else {
                Ok(false)
            }
        })?;
        socket.send(&session.reset().unwrap().bytes, remote)?;
        println!("client: fake TCP NAT round trip complete");
        Ok(())
    }

    fn server() -> io::Result<()> {
        let local = v4(&arg("--local"));
        let expected_peer = optional_arg("--peer").map(|value| v4(&value));
        let expected_payload = arg("--payload").into_bytes();
        let socket = RawIp::open()?;
        let mut accepted = None;
        wait_for(&socket, |packet| {
            let Ok((session, reply)) = FakeTcpSession::accept(packet, 0x8765_4321) else {
                return Ok(false);
            };
            if session.local_addr() != local
                || expected_peer.is_some_and(|peer| session.remote_addr() != peer)
            {
                return Ok(false);
            }
            socket.send(&reply.bytes, session.remote_addr())?;
            let mut session = session;
            session.set_reset_key_for_test(TEST_RESET_KEY);
            accepted = Some(session);
            Ok(true)
        })?;
        let mut session = accepted.expect("session set by successful accept");
        let mut received_payload = false;
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            let packet = socket.receive(deadline.saturating_duration_since(Instant::now()))?;
            let Ok(event) = session.handle_inbound(&packet) else {
                continue;
            };
            if let Some(reply) = event.reply {
                socket.send(&reply.bytes, session.remote_addr())?;
            }
            if event.datagram.as_deref() == Some(expected_payload.as_slice()) {
                received_payload = true;
            }
            if received_payload && event.state == State::Reset {
                println!("server: payload received and fake TCP reset observed");
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "payload or RST not received",
        ))
    }

    pub fn main() -> io::Result<()> {
        match std::env::args().nth(1).as_deref() {
            Some("client") => {
                client().map_err(|error| io::Error::new(error.kind(), format!("client: {error}")))
            }
            Some("server") => {
                server().map_err(|error| io::Error::new(error.kind(), format!("server: {error}")))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "use client or server",
            )),
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::main() {
        eprintln!("nat-endpoint: {error}");
        std::process::exit(1);
    }
}
