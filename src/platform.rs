use crate::config::{DirectConfig, TunConfig};
use ipnet::IpNet;
use std::net::IpAddr;
#[cfg(any(target_os = "macos", test))]
use std::process::Command;
use std::sync::Arc;
use thiserror::Error;

mod conntrack;
mod forwarding;
mod plan;
mod routes;

pub use conntrack::{ConntrackFlowKey, DirectConntrack};
use forwarding::require_ip_forwarding;
#[cfg(test)]
use forwarding::validate_ip_forwarding;
pub use plan::{network_plan, run_lifecycle_hooks, run_plan};
pub use routes::{
    UnderlayRouteOwnership, cleanup_overlay_routes, cleanup_underlay_routes, install_overlay_routes,
};

#[cfg(all(test, target_os = "linux"))]
#[path = "platform_tests.rs"]
mod integration_tests;

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(not(unix))]
unsafe fn libc_geteuid() -> u32 {
    1
}

#[cfg(target_os = "linux")]
use crate::config::{NftHealthySetTarget, NftHealthySetTargets};
#[cfg(target_os = "linux")]
use std::collections::HashSet;

#[cfg(target_os = "linux")]
pub mod quicp {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
        os::fd::{AsRawFd, RawFd},
        task::{Context, Poll},
    };
    use tokio::io::unix::AsyncFd;

    #[derive(Debug)]
    struct Fd(RawFd);
    impl AsRawFd for Fd {
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    /// Linux raw IP transport. Packet shape and fake-TCP state remain in
    /// `carrier`; this platform boundary owns all raw socket I/O.
    #[derive(Debug)]
    pub struct RawTcpSocket {
        inner: AsyncFd<Fd>,
        family: AddressFamily,
        local: SocketAddr,
        rst_guard_port: u16,
    }

    const RAW_SOCKET_BUFFER_SIZE: libc::c_int = 16 * 1024 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AddressFamily {
        Ipv4,
        Ipv6,
    }

    impl AddressFamily {
        fn for_address(address: SocketAddr) -> io::Result<Self> {
            match address {
                SocketAddr::V4(_) => Ok(Self::Ipv4),
                SocketAddr::V6(address) if address.scope_id() == 0 => Ok(Self::Ipv6),
                SocketAddr::V6(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fake TCP does not support IPv6 link-local scope IDs",
                )),
            }
        }

        fn domain(self) -> libc::c_int {
            match self {
                Self::Ipv4 => libc::AF_INET,
                Self::Ipv6 => libc::AF_INET6,
            }
        }
    }

    impl RawTcpSocket {
        /// Opens the raw transport and reserves a stable fake-TCP source port.
        ///
        /// A raw socket cannot be bound like a normal TCP socket.  When the
        /// configuration uses port zero, obtain an ephemeral port once so all
        /// packets in this endpoint share a non-zero 4-tuple.
        pub fn open(
            requested_local: SocketAddr,
            configured_mark: Option<u32>,
        ) -> io::Result<(Self, SocketAddr)> {
            let family = AddressFamily::for_address(requested_local)?;
            let mut local = requested_local;
            if local.port() == 0 {
                let wildcard = match family {
                    AddressFamily::Ipv4 => {
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                    }
                    AddressFamily::Ipv6 => {
                        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                    }
                };
                let socket = UdpSocket::bind(wildcard)?;
                local.set_port(socket.local_addr()?.port());
            }
            let port = local.port();
            super::install_quicp_rst_guard(port, configured_mark)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let fd = unsafe {
                libc::socket(
                    family.domain(),
                    libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                    libc::IPPROTO_TCP,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                let _ = super::cleanup_quicp_rst_guard(port);
                return Err(error);
            }
            for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        option,
                        (&RAW_SOCKET_BUFFER_SIZE as *const libc::c_int).cast(),
                        std::mem::size_of_val(&RAW_SOCKET_BUFFER_SIZE) as libc::socklen_t,
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    let _ = super::cleanup_quicp_rst_guard(port);
                    return Err(error);
                }
            }
            if family == AddressFamily::Ipv6 {
                let enabled: libc::c_int = 1;
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_RECVPKTINFO,
                        (&enabled as *const libc::c_int).cast(),
                        std::mem::size_of_val(&enabled) as libc::socklen_t,
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    let _ = super::cleanup_quicp_rst_guard(port);
                    return Err(error);
                }
            }
            let enabled: libc::c_int = 1;
            if let Some(mark) = configured_mark {
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        (&mark as *const u32).cast(),
                        std::mem::size_of_val(&mark) as libc::socklen_t,
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    let _ = super::cleanup_quicp_rst_guard(port);
                    return Err(error);
                }
            }
            let (level, option) = match family {
                AddressFamily::Ipv4 => (libc::IPPROTO_IP, libc::IP_HDRINCL),
                // Linux exposes IPV6_HDRINCL in the UAPI but libc does not
                // expose it consistently across supported distributions.
                AddressFamily::Ipv6 => (libc::IPPROTO_IPV6, 36),
            };
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    option,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                let _ = super::cleanup_quicp_rst_guard(port);
                return Err(error);
            }
            AsyncFd::new(Fd(fd))
                .map(|inner| {
                    (
                        Self {
                            inner,
                            family,
                            local,
                            rst_guard_port: port,
                        },
                        local,
                    )
                })
                .inspect_err(|_| {
                    let _ = super::cleanup_quicp_rst_guard(port);
                })
        }
        pub fn try_send(&self, packet: &[u8], destination: SocketAddr) -> io::Result<()> {
            match (self.family, destination) {
                (AddressFamily::Ipv4, SocketAddr::V4(destination)) => {
                    let address = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        // Raw IP sockets ignore the port.  The UDP-backed
                        // test double uses it to route the datagram.
                        sin_port: if self.rst_guard_port == 0 {
                            destination.port().to_be()
                        } else {
                            0
                        },
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(destination.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    };
                    self.send_to(
                        packet,
                        (&address as *const libc::sockaddr_in).cast(),
                        std::mem::size_of_val(&address) as libc::socklen_t,
                    )
                }
                (AddressFamily::Ipv6, SocketAddr::V6(destination))
                    if destination.scope_id() == 0 =>
                {
                    let address = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        // See the IPv4 branch: raw sockets ignore the port,
                        // while the UDP-backed test double does not.
                        sin6_port: if self.rst_guard_port == 0 {
                            destination.port().to_be()
                        } else {
                            0
                        },
                        sin6_flowinfo: 0,
                        sin6_addr: libc::in6_addr {
                            s6_addr: destination.ip().octets(),
                        },
                        sin6_scope_id: 0,
                    };
                    self.send_to(
                        packet,
                        (&address as *const libc::sockaddr_in6).cast(),
                        std::mem::size_of_val(&address) as libc::socklen_t,
                    )
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "raw fake-TCP socket and destination address family differ",
                )),
            }
        }

        /// Builds a UDP-backed stand-in so carrier unit tests can exercise the
        /// fake-TCP session table without raw-socket privileges.  Datagrams are
        /// delivered nowhere useful; only the syscall surface is shared.
        #[cfg(test)]
        pub(crate) fn udp_backed_for_test(bind: SocketAddr) -> io::Result<(Self, SocketAddr)> {
            use std::os::fd::IntoRawFd;
            let family = AddressFamily::for_address(bind)?;
            let socket = UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            let local = socket.local_addr()?;
            let inner = AsyncFd::new(Fd(socket.into_raw_fd()))?;
            Ok((
                Self {
                    inner,
                    family,
                    local,
                    rst_guard_port: 0,
                },
                local,
            ))
        }

        /// UDP stand-in variant with `IPV6_RECVPKTINFO` enabled so tests can
        /// exercise the ancillary-data destination lookup without raw-socket
        /// privileges.
        #[cfg(test)]
        pub(crate) fn udp_backed_v6_pktinfo_for_test(
            bind: SocketAddr,
        ) -> io::Result<(Self, SocketAddr)> {
            use std::os::fd::IntoRawFd;
            let family = AddressFamily::for_address(bind)?;
            let socket = UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            let enabled: libc::c_int = 1;
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVPKTINFO,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            let local = socket.local_addr()?;
            let inner = AsyncFd::new(Fd(socket.into_raw_fd()))?;
            Ok((
                Self {
                    inner,
                    family,
                    local,
                    rst_guard_port: 0,
                },
                local,
            ))
        }

        #[cfg(test)]
        pub(super) fn socket_mark(&self) -> io::Result<u32> {
            let mut mark = 0_u32;
            let mut length = std::mem::size_of::<u32>() as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    self.inner.get_ref().as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mut mark as *mut u32).cast(),
                    &mut length,
                )
            };
            if result == 0 {
                Ok(mark)
            } else {
                Err(io::Error::last_os_error())
            }
        }

        fn send_to(
            &self,
            packet: &[u8],
            address: *const libc::sockaddr,
            address_len: libc::socklen_t,
        ) -> io::Result<()> {
            let sent = unsafe {
                libc::sendto(
                    self.inner.get_ref().as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    address,
                    address_len,
                )
            };
            if sent == packet.len() as isize {
                Ok(())
            } else if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short raw IP write",
                ))
            }
        }
        /// Blocking-style poll: waits until at least one raw IP packet is ready.
        pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
            loop {
                let mut ready = std::task::ready!(self.inner.poll_read_ready(cx))?;
                let mut packet = vec![0_u8; 65_535];
                match ready.try_io(|fd| self.recv_into(fd.as_raw_fd(), &mut packet, 0)) {
                    Ok(result) => return Poll::Ready(result.map(|()| packet)),
                    Err(_) => continue,
                }
            }
        }

        /// Non-blocking drain helper for batching after a successful `poll_recv`.
        /// Returns `Ok(None)` when the socket has no more packets ready.
        pub fn try_recv(&self) -> io::Result<Option<Vec<u8>>> {
            let mut packet = vec![0_u8; 65_535];
            match self.recv_into(
                self.inner.get_ref().as_raw_fd(),
                &mut packet,
                libc::MSG_DONTWAIT,
            ) {
                Ok(()) => Ok(Some(packet)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error),
            }
        }

        fn recv_into(&self, fd: RawFd, packet: &mut Vec<u8>, flags: libc::c_int) -> io::Result<()> {
            if self.family == AddressFamily::Ipv4 {
                let len =
                    unsafe { libc::recv(fd, packet.as_mut_ptr().cast(), packet.len(), flags) };
                if len < 0 {
                    return Err(io::Error::last_os_error());
                }
                packet.truncate(len as usize);
                return Ok(());
            }

            // Linux delivers only the TCP segment on an IPv6 raw TCP socket.
            // Reconstruct the IPv6 header expected by the fake-TCP decoder
            // from the peer address and PKTINFO.
            unsafe {
                let mut source = std::mem::zeroed::<libc::sockaddr_in6>();
                let mut iov = libc::iovec {
                    iov_base: packet.as_mut_ptr().add(40).cast(),
                    iov_len: packet.len() - 40,
                };
                let mut control = [0_u8; 128];
                // `msghdr` carries libc-private padding fields on musl, so
                // initialise it first and assign only its portable public fields.
                let mut message = std::mem::zeroed::<libc::msghdr>();
                message.msg_name = (&mut source as *mut libc::sockaddr_in6).cast();
                message.msg_namelen = std::mem::size_of_val(&source) as libc::socklen_t;
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = control.len() as _;
                let len = libc::recvmsg(fd, &mut message, flags);
                if len < 0 {
                    return Err(io::Error::last_os_error());
                }

                let mut destination = None;
                let mut cmsg = libc::CMSG_FIRSTHDR(&message);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                        && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
                    {
                        let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                        destination = Some((*pktinfo).ipi6_addr);
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&message, cmsg);
                }
                let destination = destination.unwrap_or_else(|| match self.local {
                    SocketAddr::V6(local) if !local.ip().is_unspecified() => libc::in6_addr {
                        s6_addr: local.ip().octets(),
                    },
                    _ => libc::in6_addr { s6_addr: [0; 16] },
                });

                packet[0] = 0x60;
                packet[1] = 0;
                packet[2] = 0;
                packet[3] = 0;
                packet[4..6].copy_from_slice(&(len as u16).to_be_bytes());
                packet[6] = libc::IPPROTO_TCP as u8;
                packet[7] = 64;
                packet[8..24].copy_from_slice(&source.sin6_addr.s6_addr);
                packet[24..40].copy_from_slice(&destination.s6_addr);
                packet.truncate(40 + len as usize);
                Ok(())
            }
        }
        pub fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut ready = std::task::ready!(self.inner.poll_write_ready(cx))?;
            ready.clear_ready();
            Poll::Ready(Ok(()))
        }
        /// Selects the kernel-routed source address without sending a packet.
        /// This is needed when a fake-TCP endpoint listens on an unspecified
        /// address, since the IP header must still contain a concrete source.
        pub fn source_addr_for(&self, remote: SocketAddr, port: u16) -> io::Result<SocketAddr> {
            if AddressFamily::for_address(remote)? != self.family {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "raw fake-TCP socket and destination address family differ",
                ));
            }
            let bind = match self.family {
                AddressFamily::Ipv4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                AddressFamily::Ipv6 => {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                }
            };
            let socket = UdpSocket::bind(bind)?;
            socket.connect(remote)?;
            let mut local = socket.local_addr()?;
            local.set_port(port);
            Ok(local)
        }
    }
    impl Drop for RawTcpSocket {
        fn drop(&mut self) {
            tracing::warn!(local = %self.local, port = self.rst_guard_port, "quicp raw socket dropped");
            let _ = super::cleanup_quicp_rst_guard(self.rst_guard_port);
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn address_family_matches_socket_address_and_rejects_scope_ids() {
            let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
            assert_eq!(AddressFamily::for_address(v4).unwrap(), AddressFamily::Ipv4);
            let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
            assert_eq!(AddressFamily::for_address(v6).unwrap(), AddressFamily::Ipv6);
            let scoped: SocketAddr = "[fe80::1%3]:443".parse().unwrap();
            let error = AddressFamily::for_address(scoped).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(AddressFamily::Ipv4.domain(), libc::AF_INET);
            assert_eq!(AddressFamily::Ipv6.domain(), libc::AF_INET6);
        }

        #[test]
        fn udp_backed_socket_covers_send_recv_and_source_selection() {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _guard = runtime.enter();
            let (socket, local) =
                RawTcpSocket::udp_backed_for_test("127.0.0.1:0".parse().unwrap()).unwrap();
            assert!(local.is_ipv4());
            assert_ne!(local.port(), 0);

            // Address-family mismatches are rejected before any syscall.
            assert_eq!(
                socket
                    .try_send(b"x", "[::1]:443".parse().unwrap())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(
                socket
                    .source_addr_for("[::1]:443".parse().unwrap(), 1)
                    .is_err()
            );
            assert!(
                socket
                    .source_addr_for("[fe80::1%3]:443".parse().unwrap(), 1)
                    .is_err()
            );
            let source = socket
                .source_addr_for("127.0.0.1:443".parse().unwrap(), 1234)
                .unwrap();
            assert_eq!(source.port(), 1234);

            // An idle socket drains to None. The successful raw send path
            // cannot be exercised through the UDP stand-in: the kernel
            // rejects a UDP destination port of zero, which `try_send`
            // hardcodes because the port lives in the IP payload.
            assert!(socket.try_recv().unwrap().is_none());

            // Feed the socket through a regular UDP sender so the receive
            // path has a real datagram to decode.
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.send_to(b"hello", local).unwrap();
            let received = runtime.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    std::future::poll_fn(|cx| socket.poll_recv(cx)),
                )
                .await
                .unwrap()
                .unwrap()
            });
            assert_eq!(received, b"hello");

            sender.send_to(b"again", local).unwrap();
            runtime.block_on(async {
                let packet = std::future::poll_fn(|cx| socket.poll_recv(cx))
                    .await
                    .unwrap();
                assert_eq!(packet, b"again");
                std::future::poll_fn(|cx| socket.poll_writable(cx))
                    .await
                    .unwrap();
            });

            assert_eq!(socket.socket_mark().unwrap(), 0);
        }

        #[test]
        fn udp_backed_ipv6_socket_reconstructs_headers_on_receive() {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _guard = runtime.enter();
            let (socket, local) =
                RawTcpSocket::udp_backed_for_test("[::1]:0".parse().unwrap()).unwrap();
            assert!(local.is_ipv6());

            assert!(
                socket
                    .try_send(b"x", "127.0.0.1:443".parse().unwrap())
                    .is_err()
            );
            let source = socket
                .source_addr_for("[::1]:443".parse().unwrap(), 4321)
                .unwrap();
            assert_eq!(source.port(), 4321);

            assert!(socket.try_recv().unwrap().is_none());
            let sender = UdpSocket::bind("[::1]:0").unwrap();
            sender.send_to(b"v6payload", local).unwrap();
            let packet = runtime.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    std::future::poll_fn(|cx| socket.poll_recv(cx)),
                )
                .await
                .unwrap()
                .unwrap()
            });
            assert_eq!(packet[0], 0x60);
            assert_eq!(packet[6], libc::IPPROTO_TCP as u8);
            assert_eq!(packet[7], 64);
            assert_eq!(
                u16::from_be_bytes([packet[4], packet[5]]) as usize,
                b"v6payload".len()
            );
            assert_eq!(&packet[8..24], Ipv6Addr::LOCALHOST.octets());
            assert_eq!(&packet[24..40], Ipv6Addr::LOCALHOST.octets());
            assert_eq!(&packet[40..], b"v6payload");
        }

        #[test]
        fn udp_backed_ipv6_pktinfo_supplies_the_destination_address() {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _guard = runtime.enter();
            let (socket, local) =
                RawTcpSocket::udp_backed_v6_pktinfo_for_test("[::1]:0".parse().unwrap()).unwrap();
            assert!(local.is_ipv6());

            let sender = UdpSocket::bind("[::1]:0").unwrap();
            sender.send_to(b"pktinfo", local).unwrap();
            let packet = runtime.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    std::future::poll_fn(|cx| socket.poll_recv(cx)),
                )
                .await
                .unwrap()
                .unwrap()
            });
            assert_eq!(packet[0], 0x60);
            assert_eq!(&packet[8..24], Ipv6Addr::LOCALHOST.octets());
            // The destination comes from the IPV6_PKTINFO control message.
            assert_eq!(&packet[24..40], Ipv6Addr::LOCALHOST.octets());
            assert_eq!(&packet[40..], b"pktinfo");
        }

        #[test]
        fn udp_backed_ipv6_wildcard_local_falls_back_to_zero_destination() {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _guard = runtime.enter();
            let (socket, local) =
                RawTcpSocket::udp_backed_for_test("[::]:0".parse().unwrap()).unwrap();
            assert!(local.ip().is_unspecified());

            let sender = UdpSocket::bind("[::1]:0").unwrap();
            let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, local.port(), 0, 0));
            sender.send_to(b"wildcard", target).unwrap();
            let packet = runtime.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    std::future::poll_fn(|cx| socket.poll_recv(cx)),
                )
                .await
                .unwrap()
                .unwrap()
            });
            // Without PKTINFO and with an unspecified local address, the
            // reconstructed header carries the all-zero destination.
            assert_eq!(&packet[8..24], Ipv6Addr::LOCALHOST.octets());
            assert_eq!(&packet[24..40], &[0; 16]);
            assert_eq!(&packet[40..], b"wildcard");
        }
    }
}

/// Suppresses only kernel-generated TCP RST packets for a fake-TCP listener.
/// When configured, packets emitted by the fake-TCP raw socket carry
/// `socket_mark` and are therefore excluded from the guard. Without a mark,
/// the guard retains the legacy behavior of dropping all matching RSTs.
#[cfg(target_os = "linux")]
pub fn install_quicp_rst_guard(port: u16, socket_mark: Option<u32>) -> Result<(), PlatformError> {
    use nftnl::{
        Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table, nft_expr,
    };

    let table_name = std::ffi::CString::new(quicp_rst_table_name(port))
        .map_err(|_| PlatformError::Command("invalid QUICP nft table name".into()))?;
    let table = Table::new(table_name.as_c_str(), ProtoFamily::Inet);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);

    let mut output = Chain::new(c"output", &table);
    output.set_hook(Hook::Out, 0);
    output.set_type(ChainType::Filter);
    output.set_policy(Policy::Accept);
    batch.add(&output, MsgType::Add);

    // Match the TCP RST bit explicitly.  The nftnl payload API takes byte
    // offsets despite the historical `*_bits` field names: flags are byte 13
    // in the TCP header.  Using a one-byte bitwise expression preserves all
    // other flags (ACK, ECN, ...), while matching both bare RST and RST|ACK.
    let mut rule = Rule::new(&output);
    rule.add_expr(&nft_expr!(meta l4proto));
    rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));
    if let Some(socket_mark) = socket_mark {
        rule.add_expr(&nft_expr!(meta mark));
        rule.add_expr(&nft_expr!(cmp != socket_mark));
    }
    rule.add_expr(&nft_expr!(payload tcp sport));
    // TCP ports are stored in network byte order in the transport header;
    // nftnl's integer serializer uses native-endian bytes.
    rule.add_expr(&nft_expr!(cmp == port.to_be()));
    rule.add_expr(&nft_expr!(payload_raw th 13, 1));
    rule.add_expr(&nft_expr!(bitwise mask 0x04_u8, xor 0_u8));
    rule.add_expr(&nft_expr!(cmp == 0x04_u8));
    rule.add_expr(&nft_expr!(verdict drop));
    batch.add(&rule, MsgType::Add);

    if let Err(error) = send_linux_nft_batch(batch.finalize()) {
        let _ = cleanup_quicp_rst_guard(port);
        return Err(error);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub fn cleanup_quicp_rst_guard(port: u16) -> Result<(), PlatformError> {
    use nftnl::{Batch, MsgType, ProtoFamily, Table};

    let table_name = std::ffi::CString::new(quicp_rst_table_name(port))
        .map_err(|_| PlatformError::Command("invalid QUICP nft table name".into()))?;
    let table = Table::new(table_name.as_c_str(), ProtoFamily::Inet);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);
    send_linux_nft_batch(batch.finalize())
}

#[cfg(target_os = "linux")]
fn quicp_rst_table_name(port: u16) -> String {
    format!("tinect_quicp_rst_{port}")
}
#[cfg(not(target_os = "linux"))]
pub fn install_quicp_rst_guard(_: u16, _: Option<u32>) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported("quicp requires Linux".into()))
}
#[cfg(not(target_os = "linux"))]
pub fn cleanup_quicp_rst_guard(_: u16) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(target_os = "linux")]
use futures_util::TryStreamExt;
#[cfg(target_os = "linux")]
use rtnetlink::{LinkUnspec, RouteMessageBuilder, new_connection};
#[cfg(target_os = "linux")]
use std::ffi::CString;

#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "com.tinect";
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("unsupported OS: {0}")]
    Unsupported(String),
    #[error("network changes require root privileges")]
    Permission,
    #[error("command failed: {0}")]
    Command(String),
}

#[cfg(target_os = "linux")]
struct RawNftSet {
    set: std::ptr::NonNull<nftnl::nftnl_sys::nftnl_set>,
    family: nftnl::ProtoFamily,
    exclusive: bool,
}

#[cfg(target_os = "linux")]
impl RawNftSet {
    fn identity(
        target: &NftHealthySetTarget,
        table_family: nftnl::ProtoFamily,
    ) -> Result<Self, PlatformError> {
        use std::ffi::CString;
        let table = CString::new(target.table.as_str())
            .map_err(|_| PlatformError::Command("nft table contains NUL".into()))?;
        let name = CString::new(target.name.as_str())
            .map_err(|_| PlatformError::Command("nft set contains NUL".into()))?;
        let set = std::ptr::NonNull::new(unsafe { nftnl::nftnl_sys::nftnl_set_alloc() })
            .ok_or_else(|| PlatformError::Command("libnftnl failed to allocate set".into()))?;
        unsafe {
            let ptr = set.as_ptr();
            nftnl::nftnl_sys::nftnl_set_set_u32(
                ptr,
                nftnl::nftnl_sys::NFTNL_SET_FAMILY as u16,
                table_family as u32,
            );
            nftnl::nftnl_sys::nftnl_set_set_str(
                ptr,
                nftnl::nftnl_sys::NFTNL_SET_TABLE as u16,
                table.as_ptr(),
            );
            nftnl::nftnl_sys::nftnl_set_set_str(
                ptr,
                nftnl::nftnl_sys::NFTNL_SET_NAME as u16,
                name.as_ptr(),
            );
        }
        Ok(Self {
            set,
            family: table_family,
            exclusive: true,
        })
    }

    fn new(
        target: &NftHealthySetTarget,
        table_family: nftnl::ProtoFamily,
        key_family: nftnl::ProtoFamily,
    ) -> Result<Self, PlatformError> {
        let set = Self::identity(target, table_family)?;
        let (key_type, key_len) = match key_family {
            nftnl::ProtoFamily::Ipv4 => (7, 4),
            nftnl::ProtoFamily::Ipv6 => (8, 16),
            _ => {
                return Err(PlatformError::Command(
                    "healthy set has invalid family".into(),
                ));
            }
        };
        unsafe {
            let ptr = set.set.as_ptr();
            // Match nftnl's named-set builder. The kernel accepts a zero
            // identifier for a named set, but requires the attribute to be
            // present in this netlink creation path. Keep it off identity
            // objects used for element updates: those messages identify the
            // set by table and name and reject an NFTA_SET_ID attribute.
            nftnl::nftnl_sys::nftnl_set_set_u32(ptr, nftnl::nftnl_sys::NFTNL_SET_ID as u16, 0);
            nftnl::nftnl_sys::nftnl_set_set_u32(
                ptr,
                nftnl::nftnl_sys::NFTNL_SET_FLAGS as u16,
                nftnl::nftnl_sys::libc::NFT_SET_INTERVAL as u32,
            );
            nftnl::nftnl_sys::nftnl_set_set_u32(
                ptr,
                nftnl::nftnl_sys::NFTNL_SET_KEY_TYPE as u16,
                key_type,
            );
            nftnl::nftnl_sys::nftnl_set_set_u32(
                ptr,
                nftnl::nftnl_sys::NFTNL_SET_KEY_LEN as u16,
                key_len,
            );
        }
        Ok(set)
    }

    fn for_elements(
        target: &NftHealthySetTarget,
        table_family: nftnl::ProtoFamily,
        key_family: nftnl::ProtoFamily,
    ) -> Result<Self, PlatformError> {
        let set = Self::identity(target, table_family)?;
        let key_type = match key_family {
            nftnl::ProtoFamily::Ipv4 => 7,
            nftnl::ProtoFamily::Ipv6 => 8,
            _ => {
                return Err(PlatformError::Command(
                    "healthy set has invalid family".into(),
                ));
            }
        };
        unsafe {
            nftnl::nftnl_sys::nftnl_set_set_u32(
                set.set.as_ptr(),
                nftnl::nftnl_sys::NFTNL_SET_KEY_TYPE as u16,
                key_type,
            );
            nftnl::nftnl_sys::nftnl_set_set_u32(
                set.set.as_ptr(),
                nftnl::nftnl_sys::NFTNL_SET_KEY_LEN as u16,
                match key_family {
                    nftnl::ProtoFamily::Ipv4 => 4,
                    nftnl::ProtoFamily::Ipv6 => 16,
                    _ => unreachable!(),
                },
            );
            nftnl::nftnl_sys::nftnl_set_set_u32(
                set.set.as_ptr(),
                nftnl::nftnl_sys::NFTNL_SET_FLAGS as u16,
                nftnl::nftnl_sys::libc::NFT_SET_INTERVAL as u32,
            );
        }
        Ok(set)
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawNftSet {
    fn drop(&mut self) {
        unsafe { nftnl::nftnl_sys::nftnl_set_free(self.set.as_ptr()) };
    }
}

#[cfg(target_os = "linux")]
unsafe impl nftnl::NlMsg for RawNftSet {
    unsafe fn write(&self, buf: *mut std::ffi::c_void, seq: u32, msg_type: nftnl::MsgType) {
        use nftnl::nftnl_sys::{self as sys, libc};
        let (message, flags) = match msg_type {
            nftnl::MsgType::Add => (
                libc::NFT_MSG_NEWSET,
                libc::NLM_F_CREATE
                    // libnftnl uses APPEND for NEWSET.  EXCL is rejected by
                    // some kernels for named nft set updates even when the
                    // set does not exist yet.
                    | if self.exclusive { libc::NLM_F_APPEND } else { 0 }
                    | libc::NLM_F_ACK,
            ),
            nftnl::MsgType::Del => (libc::NFT_MSG_DELSET, libc::NLM_F_ACK),
        };
        unsafe {
            let header = sys::nftnl_nlmsg_build_hdr(
                buf.cast(),
                message as u16,
                self.family as u16,
                flags as u16,
                seq,
            );
            sys::nftnl_set_nlmsg_build_payload(header, self.set.as_ptr());
        }
    }
}

#[cfg(target_os = "linux")]
struct RawNftElements {
    set: RawNftSet,
    clear_all: bool,
}

#[cfg(target_os = "linux")]
impl RawNftElements {
    fn new(
        target: &NftHealthySetTarget,
        family: nftnl::ProtoFamily,
        prefixes: &[IpNet],
    ) -> Result<Self, PlatformError> {
        use std::ffi::c_void;
        let set = RawNftSet::for_elements(target, nftnl::ProtoFamily::Inet, family)?;
        for prefix in prefixes {
            let family_matches = matches!(
                (family, prefix),
                (nftnl::ProtoFamily::Ipv4, IpNet::V4(_)) | (nftnl::ProtoFamily::Ipv6, IpNet::V6(_))
            );
            if !family_matches {
                return Err(PlatformError::Command(format!(
                    "{prefix} does not match nft set family"
                )));
            }
            let (start, end) = interval_bounds(prefix).ok_or_else(|| {
                PlatformError::Command(format!("{prefix} does not match nft set family"))
            })?;
            let element =
                std::ptr::NonNull::new(unsafe { nftnl::nftnl_sys::nftnl_set_elem_alloc() })
                    .ok_or_else(|| {
                        PlatformError::Command("libnftnl failed to allocate element".into())
                    })?;
            let interval_end = if start == end {
                None
            } else {
                Some(
                    std::ptr::NonNull::new(unsafe { nftnl::nftnl_sys::nftnl_set_elem_alloc() })
                        .ok_or_else(|| {
                            PlatformError::Command("libnftnl failed to allocate element".into())
                        })?,
                )
            };
            unsafe {
                nftnl::nftnl_sys::nftnl_set_elem_set(
                    element.as_ptr(),
                    nftnl::nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                    start.as_ptr().cast::<c_void>(),
                    start.len() as u32,
                );
                nftnl::nftnl_sys::nftnl_set_elem_add(set.set.as_ptr(), element.as_ptr());
                if let Some(interval_end) = interval_end {
                    nftnl::nftnl_sys::nftnl_set_elem_set(
                        interval_end.as_ptr(),
                        nftnl::nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                        end.as_ptr().cast::<c_void>(),
                        end.len() as u32,
                    );
                    nftnl::nftnl_sys::nftnl_set_elem_set_u32(
                        interval_end.as_ptr(),
                        nftnl::nftnl_sys::NFTNL_SET_ELEM_FLAGS as u16,
                        nftnl::nftnl_sys::libc::NFT_SET_ELEM_INTERVAL_END as u32,
                    );
                    nftnl::nftnl_sys::nftnl_set_elem_add(set.set.as_ptr(), interval_end.as_ptr());
                }
            }
        }
        Ok(Self {
            set,
            clear_all: false,
        })
    }

    fn clear(target: &NftHealthySetTarget) -> Result<Self, PlatformError> {
        Ok(Self {
            set: RawNftSet::identity(target, nftnl::ProtoFamily::Inet)?,
            clear_all: true,
        })
    }
}

#[cfg(target_os = "linux")]
unsafe impl nftnl::NlMsg for RawNftElements {
    unsafe fn write(&self, buf: *mut std::ffi::c_void, seq: u32, msg_type: nftnl::MsgType) {
        use nftnl::nftnl_sys::{self as sys, libc};
        let (message, flags) = match msg_type {
            nftnl::MsgType::Add => (
                libc::NFT_MSG_NEWSETELEM,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            ),
            nftnl::MsgType::Del if self.clear_all => (
                libc::NFT_MSG_DELSETELEM,
                libc::NLM_F_ROOT | libc::NLM_F_MATCH | libc::NLM_F_ACK,
            ),
            nftnl::MsgType::Del => (libc::NFT_MSG_DELSETELEM, libc::NLM_F_ACK),
        };
        unsafe {
            let header = sys::nftnl_nlmsg_build_hdr(
                buf.cast(),
                message as u16,
                self.set.family as u16,
                flags as u16,
                seq,
            );
            sys::nftnl_set_elems_nlmsg_build_payload(header, self.set.set.as_ptr());
        }
    }
}

#[cfg(target_os = "linux")]
fn interval_bounds(prefix: &IpNet) -> Option<(Vec<u8>, Vec<u8>)> {
    match prefix {
        IpNet::V4(prefix) => {
            let start = u32::from(prefix.network());
            let host_bits = 32 - u32::from(prefix.prefix_len());
            // nft interval end markers use an exclusive upper bound. A
            // full-address-space interval wraps its upper bound to zero.
            let size = if host_bits == 32 {
                0
            } else {
                1_u32 << host_bits
            };
            let end = start.wrapping_add(size);
            let start = start.to_be_bytes().to_vec();
            let end = end.to_be_bytes().to_vec();
            Some((start, end))
        }
        IpNet::V6(prefix) => {
            let start = u128::from(prefix.network());
            let host_bits = 128 - u32::from(prefix.prefix_len());
            let size = if host_bits == 128 {
                0
            } else {
                1_u128 << host_bits
            };
            let end = start.wrapping_add(size);
            Some((start.to_be_bytes().to_vec(), end.to_be_bytes().to_vec()))
        }
    }
}

#[cfg(target_os = "linux")]
fn canonicalize_prefixes(prefixes: &HashSet<IpNet>) -> HashSet<IpNet> {
    prefixes
        .iter()
        .copied()
        .filter(|prefix| {
            !prefixes.iter().any(|container| {
                container.prefix_len() < prefix.prefix_len()
                    && container.contains(&prefix.network())
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
struct PrefixSetDelta {
    desired: HashSet<IpNet>,
    add: Vec<IpNet>,
    remove: Vec<IpNet>,
}

#[cfg(target_os = "linux")]
fn prefix_set_delta(committed: &HashSet<IpNet>, desired: &HashSet<IpNet>) -> PrefixSetDelta {
    let desired = canonicalize_prefixes(desired);
    let add = desired.difference(committed).copied().collect::<Vec<_>>();
    let remove = committed.difference(&desired).copied().collect::<Vec<_>>();
    PrefixSetDelta {
        desired,
        add,
        remove,
    }
}

#[cfg(target_os = "linux")]
pub struct HealthyRouteSetManager {
    targets: NftHealthySetTargets,
    committed_v4: HashSet<IpNet>,
    committed_v6: HashSet<IpNet>,
}

#[cfg(target_os = "linux")]
struct SetMetadata {
    flags: u32,
    key_type: u32,
    key_len: u32,
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum NftMessageAction {
    Ignore,
    Create,
    Parse,
    Complete,
    Error(i32),
}

#[cfg(target_os = "linux")]
fn classify_nft_table_message(message_type: u16, error: Option<i32>) -> NftMessageAction {
    if message_type == nftnl::nftnl_sys::libc::NLMSG_ERROR as u16 {
        return match error {
            Some(0) => NftMessageAction::Ignore,
            Some(error) if error == -nftnl::nftnl_sys::libc::ENOENT => NftMessageAction::Create,
            Some(error) => NftMessageAction::Error(error),
            None => NftMessageAction::Ignore,
        };
    }
    if message_type == nftnl::nftnl_sys::libc::NLMSG_DONE as u16 {
        return NftMessageAction::Create;
    }
    if message_type == nftnl::nftnl_sys::libc::NFT_MSG_NEWTABLE as u16 {
        return NftMessageAction::Parse;
    }
    NftMessageAction::Ignore
}

#[cfg(target_os = "linux")]
fn classify_nft_set_message(message_type: u16, error: Option<i32>) -> NftMessageAction {
    if message_type == nftnl::nftnl_sys::libc::NLMSG_ERROR as u16 {
        return match error {
            Some(0) => NftMessageAction::Complete,
            Some(value) if value == -nftnl::nftnl_sys::libc::ENOENT => NftMessageAction::Complete,
            Some(value) => NftMessageAction::Error(value),
            None => NftMessageAction::Ignore,
        };
    }
    if message_type == nftnl::nftnl_sys::libc::NLMSG_DONE as u16 {
        return NftMessageAction::Complete;
    }
    if message_type == nftnl::nftnl_sys::libc::NFT_MSG_NEWSET as u16 {
        return NftMessageAction::Parse;
    }
    NftMessageAction::Ignore
}

#[cfg(target_os = "linux")]
fn classify_nft_elements_message(message_type: u16, error: Option<i32>) -> NftMessageAction {
    if message_type == nftnl::nftnl_sys::libc::NLMSG_ERROR as u16 {
        return match error {
            Some(0) => NftMessageAction::Complete,
            Some(value) if value == -nftnl::nftnl_sys::libc::ENOENT => NftMessageAction::Complete,
            Some(value) => NftMessageAction::Error(value),
            None => NftMessageAction::Ignore,
        };
    }
    if message_type == nftnl::nftnl_sys::libc::NLMSG_DONE as u16 {
        return NftMessageAction::Complete;
    }
    if message_type == nftnl::nftnl_sys::libc::NFT_MSG_NEWSETELEM as u16 {
        return NftMessageAction::Parse;
    }
    NftMessageAction::Ignore
}

#[cfg(target_os = "linux")]
fn ensure_nft_table(target: &NftHealthySetTarget) -> Result<(), PlatformError> {
    use std::ffi::{CStr, CString, c_char};
    use std::mem::size_of;

    let expected_name = CString::new(target.table.as_str())
        .map_err(|_| PlatformError::Command("nft table contains NUL".into()))?;
    let mut request = vec![0_u8; nftnl::nft_nlmsg_maxsize() as usize];
    let header = unsafe {
        nftnl::nftnl_sys::nftnl_nlmsg_build_hdr(
            request.as_mut_ptr().cast::<c_char>(),
            nftnl::nftnl_sys::libc::NFT_MSG_GETTABLE as u16,
            nftnl::ProtoFamily::Inet as u16,
            (nftnl::nftnl_sys::libc::NLM_F_ROOT
                | nftnl::nftnl_sys::libc::NLM_F_MATCH
                | nftnl::nftnl_sys::libc::NLM_F_ACK) as u16,
            1,
        )
    };
    let length = unsafe { (*header).nlmsg_len as usize };
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).map_err(netlink_error)?;
    socket.send(&request[..length]).map_err(netlink_error)?;
    let mut buffer = vec![0_u8; nftnl::nft_nlmsg_maxsize() as usize];
    loop {
        for message in socket.recv(&mut buffer).map_err(netlink_error)? {
            let message = message.map_err(netlink_error)?;
            let header = message.as_ptr().cast::<nftnl::nftnl_sys::libc::nlmsghdr>();
            let message_type = unsafe { (*header).nlmsg_type & 0xff };
            let error =
                (message_type == nftnl::nftnl_sys::libc::NLMSG_ERROR as u16).then(|| unsafe {
                    std::ptr::read_unaligned(
                        message
                            .as_ptr()
                            .add(size_of::<nftnl::nftnl_sys::libc::nlmsghdr>())
                            .cast::<i32>(),
                    )
                });
            match classify_nft_table_message(message_type, error) {
                NftMessageAction::Ignore => continue,
                NftMessageAction::Create => {
                    return create_nft_table(target, expected_name.as_c_str());
                }
                NftMessageAction::Error(error) => {
                    return Err(PlatformError::Command(format!(
                        "querying nft table {} failed with errno {}",
                        target.table, -error
                    )));
                }
                NftMessageAction::Parse => {}
                NftMessageAction::Complete => unreachable!(),
            }
            let parsed = std::ptr::NonNull::new(unsafe { nftnl::nftnl_sys::nftnl_table_alloc() })
                .ok_or_else(|| {
                PlatformError::Command("libnftnl failed to allocate table".into())
            })?;
            let matches = unsafe {
                let rc = nftnl::nftnl_sys::nftnl_table_nlmsg_parse(header, parsed.as_ptr());
                if rc < 0 {
                    nftnl::nftnl_sys::nftnl_table_free(parsed.as_ptr());
                    return Err(PlatformError::Command(format!(
                        "parsing nft table {} failed with code {rc}",
                        target.table
                    )));
                }
                let family = nftnl::nftnl_sys::nftnl_table_get_u32(
                    parsed.as_ptr(),
                    nftnl::nftnl_sys::NFTNL_TABLE_FAMILY as u16,
                );
                let name = nftnl::nftnl_sys::nftnl_table_get_str(
                    parsed.as_ptr(),
                    nftnl::nftnl_sys::NFTNL_TABLE_NAME as u16,
                );
                family == nftnl::ProtoFamily::Inet as u32
                    && !name.is_null()
                    && CStr::from_ptr(name) == expected_name.as_c_str()
            };
            unsafe { nftnl::nftnl_sys::nftnl_table_free(parsed.as_ptr()) };
            if matches {
                return Ok(());
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn create_nft_table(
    target: &NftHealthySetTarget,
    table_name: &std::ffi::CStr,
) -> Result<(), PlatformError> {
    let table = nftnl::Table::new(table_name, nftnl::ProtoFamily::Inet);
    let mut batch = nftnl::Batch::new();
    batch.add(&table, nftnl::MsgType::Add);
    send_linux_nft_batch(batch.finalize()).map_err(|error| {
        PlatformError::Command(format!("creating nft table {}: {error}", target.table))
    })
}

#[cfg(target_os = "linux")]
fn query_healthy_set(target: &NftHealthySetTarget) -> Result<Option<SetMetadata>, PlatformError> {
    use std::{mem::size_of, os::raw::c_char, ptr};

    let set = RawNftSet::identity(target, nftnl::ProtoFamily::Inet)?;
    let mut request = vec![0_u8; nftnl::nft_nlmsg_maxsize() as usize];
    let header = unsafe {
        nftnl::nftnl_sys::nftnl_nlmsg_build_hdr(
            request.as_mut_ptr().cast::<c_char>(),
            nftnl::nftnl_sys::libc::NFT_MSG_GETSET as u16,
            nftnl::ProtoFamily::Inet as u16,
            (nftnl::nftnl_sys::libc::NLM_F_REQUEST | nftnl::nftnl_sys::libc::NLM_F_ACK) as u16,
            1,
        )
    };
    unsafe { nftnl::nftnl_sys::nftnl_set_nlmsg_build_payload(header, set.set.as_ptr()) };
    let length = unsafe { (*header).nlmsg_len as usize };
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).map_err(netlink_error)?;
    socket.send(&request[..length]).map_err(netlink_error)?;
    let mut buffer = vec![0_u8; nftnl::nft_nlmsg_maxsize() as usize];
    loop {
        for message in socket.recv(&mut buffer).map_err(netlink_error)? {
            let message = message.map_err(netlink_error)?;
            let header = message.as_ptr().cast::<nftnl::nftnl_sys::libc::nlmsghdr>();
            let message_type = unsafe { (*header).nlmsg_type & 0xff };
            let error =
                (message_type == nftnl::nftnl_sys::libc::NLMSG_ERROR as u16).then(|| unsafe {
                    ptr::read_unaligned(
                        message
                            .as_ptr()
                            .add(size_of::<nftnl::nftnl_sys::libc::nlmsghdr>())
                            .cast::<i32>(),
                    )
                });
            match classify_nft_set_message(message_type, error) {
                NftMessageAction::Ignore => continue,
                NftMessageAction::Complete => return Ok(None),
                NftMessageAction::Error(error) => {
                    return Err(PlatformError::Command(format!(
                        "querying nft set {}:{} failed with errno {}",
                        target.table, target.name, -error
                    )));
                }
                NftMessageAction::Parse => {}
                NftMessageAction::Create => unreachable!(),
            }
            if message_type == nftnl::nftnl_sys::libc::NFT_MSG_NEWSET as u16 {
                let parsed = std::ptr::NonNull::new(unsafe { nftnl::nftnl_sys::nftnl_set_alloc() })
                    .ok_or_else(|| {
                        PlatformError::Command("libnftnl failed to allocate set".into())
                    })?;
                let result = unsafe {
                    let rc = nftnl::nftnl_sys::nftnl_set_nlmsg_parse(header, parsed.as_ptr());
                    if rc < 0 {
                        Err(PlatformError::Command(format!(
                            "parsing nft set {}:{} failed with code {rc}",
                            target.table, target.name
                        )))
                    } else {
                        Ok(SetMetadata {
                            flags: nftnl::nftnl_sys::nftnl_set_get_u32(
                                parsed.as_ptr(),
                                nftnl::nftnl_sys::NFTNL_SET_FLAGS as u16,
                            ),
                            key_type: nftnl::nftnl_sys::nftnl_set_get_u32(
                                parsed.as_ptr(),
                                nftnl::nftnl_sys::NFTNL_SET_KEY_TYPE as u16,
                            ),
                            key_len: nftnl::nftnl_sys::nftnl_set_get_u32(
                                parsed.as_ptr(),
                                nftnl::nftnl_sys::NFTNL_SET_KEY_LEN as u16,
                            ),
                        })
                    }
                };
                unsafe { nftnl::nftnl_sys::nftnl_set_free(parsed.as_ptr()) };
                return result.map(Some);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn query_healthy_set_elements(
    target: &NftHealthySetTarget,
    key_family: nftnl::ProtoFamily,
) -> Result<Vec<IpNet>, PlatformError> {
    use std::ffi::c_char;
    let set = RawNftSet::identity(target, nftnl::ProtoFamily::Inet)?;
    let mut request = vec![0_u8; nftnl::nft_nlmsg_maxsize() as usize];
    let header = unsafe {
        nftnl::nftnl_sys::nftnl_nlmsg_build_hdr(
            request.as_mut_ptr().cast::<c_char>(),
            nftnl::nftnl_sys::libc::NFT_MSG_GETSETELEM as u16,
            nftnl::ProtoFamily::Inet as u16,
            (nftnl::nftnl_sys::libc::NLM_F_ROOT
                | nftnl::nftnl_sys::libc::NLM_F_MATCH
                | nftnl::nftnl_sys::libc::NLM_F_ACK) as u16,
            2,
        )
    };
    unsafe { nftnl::nftnl_sys::nftnl_set_elems_nlmsg_build_payload(header, set.set.as_ptr()) };
    let length = unsafe { (*header).nlmsg_len as usize };
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).map_err(netlink_error)?;
    socket.send(&request[..length]).map_err(netlink_error)?;
    let mut buffer = vec![0_u8; nftnl::nft_nlmsg_maxsize() as usize];
    let mut prefixes = Vec::new();
    let mut pending_start: Option<Vec<u8>> = None;
    let mut pending_end: Option<Vec<u8>> = None;
    loop {
        for message in socket.recv(&mut buffer).map_err(netlink_error)? {
            let message = message.map_err(netlink_error)?;
            let header = message.as_ptr().cast::<nftnl::nftnl_sys::libc::nlmsghdr>();
            let message_type = unsafe { (*header).nlmsg_type & 0xff };
            let error =
                (message_type == nftnl::nftnl_sys::libc::NLMSG_ERROR as u16).then(|| unsafe {
                    *(message
                        .as_ptr()
                        .add(std::mem::size_of::<nftnl::nftnl_sys::libc::nlmsghdr>())
                        .cast::<i32>())
                });
            match classify_nft_elements_message(message_type, error) {
                NftMessageAction::Ignore => continue,
                NftMessageAction::Complete => {
                    finish_pending_interval(key_family, &mut prefixes, &mut pending_start);
                    return Ok(prefixes);
                }
                NftMessageAction::Error(error) => {
                    return Err(PlatformError::Command(format!(
                        "querying nft set {}:{} elements failed with errno {}",
                        target.table, target.name, -error
                    )));
                }
                NftMessageAction::Parse => {}
                NftMessageAction::Create => unreachable!(),
            }
            let parsed = std::ptr::NonNull::new(unsafe { nftnl::nftnl_sys::nftnl_set_alloc() })
                .ok_or_else(|| PlatformError::Command("libnftnl failed to allocate set".into()))?;
            let result = unsafe {
                let rc = nftnl::nftnl_sys::nftnl_set_elems_nlmsg_parse(header, parsed.as_ptr());
                if rc < 0 {
                    Err(PlatformError::Command(format!(
                        "parsing nft set {}:{} elements failed with code {rc}",
                        target.table, target.name
                    )))
                } else {
                    let iterator = nftnl::nftnl_sys::nftnl_set_elems_iter_create(parsed.as_ptr());
                    if iterator.is_null() {
                        Err(PlatformError::Command(
                            "libnftnl failed to iterate set".into(),
                        ))
                    } else {
                        let mut element = nftnl::nftnl_sys::nftnl_set_elems_iter_cur(iterator);
                        while !element.is_null() {
                            let mut start_len = 0_u32;
                            let mut end_len = 0_u32;
                            let start = nftnl::nftnl_sys::nftnl_set_elem_get(
                                element,
                                nftnl::nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                                &mut start_len,
                            );
                            let end = nftnl::nftnl_sys::nftnl_set_elem_get(
                                element,
                                nftnl::nftnl_sys::NFTNL_SET_ELEM_KEY_END as u16,
                                &mut end_len,
                            );
                            if !start.is_null() {
                                let start = std::slice::from_raw_parts(
                                    start.cast::<u8>(),
                                    start_len as usize,
                                );
                                let is_interval_end = nftnl::nftnl_sys::nftnl_set_elem_is_set(
                                    element,
                                    nftnl::nftnl_sys::NFTNL_SET_ELEM_FLAGS as u16,
                                ) && nftnl::nftnl_sys::nftnl_set_elem_get_u32(
                                    element,
                                    nftnl::nftnl_sys::NFTNL_SET_ELEM_FLAGS as u16,
                                )
                                    & nftnl::nftnl_sys::libc::NFT_SET_ELEM_INTERVAL_END as u32
                                    != 0;
                                let end = (!end.is_null()).then(|| {
                                    std::slice::from_raw_parts(end.cast::<u8>(), end_len as usize)
                                });
                                consume_healthy_set_element(
                                    key_family,
                                    start,
                                    end,
                                    is_interval_end,
                                    &mut prefixes,
                                    &mut pending_start,
                                    &mut pending_end,
                                );
                            }
                            element = nftnl::nftnl_sys::nftnl_set_elems_iter_next(iterator);
                        }
                        nftnl::nftnl_sys::nftnl_set_elems_iter_destroy(iterator);
                        Ok(())
                    }
                }
            };
            unsafe { nftnl::nftnl_sys::nftnl_set_free(parsed.as_ptr()) };
            result?;
        }
    }
}

#[cfg(target_os = "linux")]
fn consume_healthy_set_element(
    family: nftnl::ProtoFamily,
    start: &[u8],
    end: Option<&[u8]>,
    is_interval_end: bool,
    prefixes: &mut Vec<IpNet>,
    pending_start: &mut Option<Vec<u8>>,
    pending_end: &mut Option<Vec<u8>>,
) {
    if let Some(end) = end {
        if let Some(end) = inclusive_end_to_exclusive(family, end)
            && let Some(prefix) = interval_to_prefix(family, start, &end)
        {
            prefixes.push(prefix);
        }
    } else if is_interval_end {
        if let Some(pending_start) = pending_start.take()
            && let Some(prefix) = interval_to_prefix(family, &pending_start, start)
        {
            prefixes.push(prefix);
        } else {
            *pending_end = Some(start.to_vec());
        }
    } else if let Some(pending_end) = pending_end.take()
        && let Some(prefix) = interval_to_prefix(family, start, &pending_end)
    {
        prefixes.push(prefix);
    } else {
        if let Some(pending_start) = pending_start.take()
            && pending_start.iter().all(|byte| *byte == 0)
            && let Some(prefix) = interval_to_prefix(family, &pending_start, &pending_start)
        {
            prefixes.push(prefix);
        }
        *pending_start = Some(start.to_vec());
    }
}

#[cfg(target_os = "linux")]
fn finish_pending_interval(
    family: nftnl::ProtoFamily,
    prefixes: &mut Vec<IpNet>,
    pending_start: &mut Option<Vec<u8>>,
) {
    if let Some(start) = pending_start.take()
        && start.iter().all(|byte| *byte == 0)
        && let Some(prefix) = interval_to_prefix(family, &start, &start)
    {
        prefixes.push(prefix);
    }
}

#[cfg(target_os = "linux")]
fn inclusive_end_to_exclusive(family: nftnl::ProtoFamily, end: &[u8]) -> Option<Vec<u8>> {
    match family {
        nftnl::ProtoFamily::Ipv4 if end.len() == 4 => Some(
            u32::from_be_bytes(end.try_into().ok()?)
                .wrapping_add(1)
                .to_be_bytes()
                .to_vec(),
        ),
        nftnl::ProtoFamily::Ipv6 if end.len() == 16 => Some(
            u128::from_be_bytes(end.try_into().ok()?)
                .wrapping_add(1)
                .to_be_bytes()
                .to_vec(),
        ),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn interval_to_prefix(family: nftnl::ProtoFamily, start: &[u8], end: &[u8]) -> Option<IpNet> {
    match family {
        nftnl::ProtoFamily::Ipv4 if start.len() == 4 && end.len() == 4 => {
            let start = u32::from_be_bytes(start.try_into().ok()?);
            let end = u32::from_be_bytes(end.try_into().ok()?);
            let size = if start == 0 && end == 0 {
                1_u64 << 32
            } else if end >= start {
                u64::from(end - start)
            } else {
                (1_u64 << 32) - u64::from(start) + u64::from(end)
            };
            if !size.is_power_of_two() || u64::from(start) & (size - 1) != 0 {
                return None;
            }
            let host_bits = size.trailing_zeros();
            IpNet::new(std::net::Ipv4Addr::from(start).into(), 32 - host_bits as u8).ok()
        }
        nftnl::ProtoFamily::Ipv6 if start.len() == 16 && end.len() == 16 => {
            let start = u128::from_be_bytes(start.try_into().ok()?);
            let end = u128::from_be_bytes(end.try_into().ok()?);
            if start == 0 && end == 0 {
                return IpNet::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0).ok();
            }
            let (size, host_bits) = if end >= start {
                let size = end - start;
                (size, size.trailing_zeros())
            } else {
                let size = u128::MAX - start + 1 + end;
                (size, size.trailing_zeros())
            };
            (size.is_power_of_two() && start & (size - 1) == 0).then(|| {
                IpNet::new(
                    std::net::Ipv6Addr::from(start).into(),
                    128 - host_bits as u8,
                )
                .ok()
            })?
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
impl HealthyRouteSetManager {
    pub fn open(targets: NftHealthySetTargets) -> Result<Option<Self>, PlatformError> {
        if targets.v4.is_none() && targets.v6.is_none() {
            return Ok(None);
        }
        let mut manager = Self {
            targets,
            committed_v4: HashSet::new(),
            committed_v6: HashSet::new(),
        };
        manager.initialize()?;
        Ok(Some(manager))
    }

    fn clear_all_elements(&mut self) -> Result<(), PlatformError> {
        let mut batch = nftnl::Batch::new();
        for target in [self.targets.v4.as_ref(), self.targets.v6.as_ref()]
            .into_iter()
            .flatten()
        {
            batch.add(&RawNftElements::clear(target)?, nftnl::MsgType::Del);
        }
        send_linux_nft_batch(batch.finalize())?;
        self.committed_v4.clear();
        self.committed_v6.clear();
        Ok(())
    }

    fn initialize(&mut self) -> Result<(), PlatformError> {
        let mut batch = nftnl::Batch::new();
        let mut changed = false;
        for (target, family) in [
            (self.targets.v4.as_ref(), nftnl::ProtoFamily::Ipv4),
            (self.targets.v6.as_ref(), nftnl::ProtoFamily::Ipv6),
        ] {
            if let Some(target) = target {
                ensure_nft_table(target)?;
                match query_healthy_set(target)? {
                    None => {
                        batch.add(
                            &RawNftSet::new(target, nftnl::ProtoFamily::Inet, family)?,
                            nftnl::MsgType::Add,
                        );
                        changed = true;
                    }
                    Some(metadata) => {
                        query_healthy_set_elements(target, family)?;
                        let expected_type = if family == nftnl::ProtoFamily::Ipv4 {
                            7
                        } else {
                            8
                        };
                        let expected_len = if family == nftnl::ProtoFamily::Ipv4 {
                            4
                        } else {
                            16
                        };
                        if metadata.key_type != expected_type
                            || metadata.key_len != expected_len
                            || metadata.flags & nftnl::nftnl_sys::libc::NFT_SET_INTERVAL as u32 == 0
                        {
                            return Err(PlatformError::Command(format!(
                                "nft set {}:{} has incompatible type or flags",
                                target.table, target.name
                            )));
                        }
                    }
                }
            }
        }
        if changed {
            send_linux_nft_batch(batch.finalize()).map_err(|error| {
                PlatformError::Command(format!("creating healthy nft set: {error}"))
            })?;
        }
        // Startup is a full refresh boundary: do not carry stale elements
        // across daemon lifetimes. The current health snapshot is reconciled
        // by the caller after initialization completes.
        self.clear_all_elements()?;
        Ok(())
    }

    pub fn reconcile(&mut self, desired: &HashSet<IpNet>) -> Result<(), PlatformError> {
        let desired_v4 = desired
            .iter()
            .filter(|prefix| prefix.addr().is_ipv4())
            .copied()
            .collect::<HashSet<_>>();
        let desired_v6 = desired
            .iter()
            .filter(|prefix| prefix.addr().is_ipv6())
            .copied()
            .collect::<HashSet<_>>();
        let delta_v4 = prefix_set_delta(&self.committed_v4, &desired_v4);
        let delta_v6 = prefix_set_delta(&self.committed_v6, &desired_v6);
        let mut batch = nftnl::Batch::new();
        if let Some(target) = self.targets.v4.as_ref() {
            if !delta_v4.remove.is_empty() {
                batch.add(
                    &RawNftElements::new(target, nftnl::ProtoFamily::Ipv4, &delta_v4.remove)?,
                    nftnl::MsgType::Del,
                );
            }
            if !delta_v4.add.is_empty() {
                batch.add(
                    &RawNftElements::new(target, nftnl::ProtoFamily::Ipv4, &delta_v4.add)?,
                    nftnl::MsgType::Add,
                );
            }
        }
        if let Some(target) = self.targets.v6.as_ref() {
            if !delta_v6.remove.is_empty() {
                batch.add(
                    &RawNftElements::new(target, nftnl::ProtoFamily::Ipv6, &delta_v6.remove)?,
                    nftnl::MsgType::Del,
                );
            }
            if !delta_v6.add.is_empty() {
                batch.add(
                    &RawNftElements::new(target, nftnl::ProtoFamily::Ipv6, &delta_v6.add)?,
                    nftnl::MsgType::Add,
                );
            }
        }
        if delta_v4.add.is_empty()
            && delta_v4.remove.is_empty()
            && delta_v6.add.is_empty()
            && delta_v6.remove.is_empty()
        {
            return Ok(());
        }
        send_linux_nft_batch(batch.finalize())?;
        self.committed_v4 = delta_v4.desired;
        self.committed_v6 = delta_v6.desired;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for HealthyRouteSetManager {
    fn drop(&mut self) {
        if self.clear_all_elements().is_err() {
            tracing::warn!("failed to clear healthy nft set elements during shutdown");
            return;
        }
        let mut batch = nftnl::Batch::new();
        if self.targets.destroy_set
            && let Some(target) = self.targets.v4.as_ref()
            && let Ok(set) =
                RawNftSet::new(target, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Ipv4)
        {
            batch.add(&set, nftnl::MsgType::Del);
        }
        if self.targets.destroy_set
            && let Some(target) = self.targets.v6.as_ref()
            && let Ok(set) =
                RawNftSet::new(target, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Ipv6)
        {
            batch.add(&set, nftnl::MsgType::Del);
        }
        if self.targets.destroy_set
            && let Err(error) = send_linux_nft_batch(batch.finalize())
        {
            tracing::warn!(error = %error, "failed to delete configured healthy nft set");
        }
        if self.targets.destroy_table {
            let mut table_names = HashSet::new();
            for target in [self.targets.v4.as_ref(), self.targets.v6.as_ref()]
                .into_iter()
                .flatten()
            {
                table_names.insert(target.table.clone());
            }
            let mut table_batch = nftnl::Batch::new();
            for table_name in table_names {
                if let Ok(table_name) = std::ffi::CString::new(table_name) {
                    let table = nftnl::Table::new(table_name.as_c_str(), nftnl::ProtoFamily::Inet);
                    table_batch.add(&table, nftnl::MsgType::Del);
                }
            }
            if let Err(error) = send_linux_nft_batch(table_batch.finalize()) {
                tracing::warn!(error = %error, "failed to delete configured nft table");
            }
        }
    }
}

/// Marker for the nftables/PF resources owned by a Tinect Internet exit.
///
/// Host-wide IP forwarding is deliberately not included: it is a system
/// administrator-owned prerequisite, not a daemon lifecycle resource.
pub struct ExitNetworkState {
    #[cfg(target_os = "linux")]
    table_name: String,
}

/// Tinect-owned INPUT exceptions for traffic entering its TUN.
/// Kept separate from exit NAT because every local TUN needs it, including
/// nodes that do not provide an Internet exit.
pub struct TunInputFirewallState {
    #[cfg(target_os = "linux")]
    table_name: String,
}

/// Tinect-owned prerouting rules for direct fallback reinjection.
pub struct DirectFirewallState {
    #[cfg(target_os = "linux")]
    table_name: Option<String>,
}

/// Tinect-owned POSTROUTING masquerade for reinjected fallback packets.
///
/// Kept separate from [`ExitNetworkState`] so the fallback NAT can be installed
/// without an egress ACL, and placed behind the user's own nat rules so custom
/// SNAT/masquerade configurations keep precedence.
pub struct DirectNatState {
    #[cfg(target_os = "linux")]
    table_name: Option<String>,
}
/// Opaque TUN device handle. The dataplane reads and writes packets through
/// this type without ever naming the `tun` crate: only `platform` constructs
/// devices and resolves kernel interface names.
#[derive(Clone)]
pub struct TunDevice {
    inner: Arc<tun::AsyncDevice>,
}

impl TunDevice {
    /// Send one IP packet toward the kernel.
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(buf).await
    }

    /// Receive one IP packet from the kernel.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }

    /// Return the kernel-assigned interface name.
    pub fn name(&self) -> Result<String, PlatformError> {
        tun_name(&self.inner)
    }
}

/// Creates and configures the Layer-3 device itself. Route and firewall
/// manipulation remains separate, so teardown has a clear ownership boundary.
pub fn create_tun(config: &TunConfig) -> Result<TunDevice, PlatformError> {
    if unsafe { libc_geteuid() } != 0 {
        return Err(PlatformError::Permission);
    }
    let address = config
        .addresses
        .first()
        .ok_or_else(|| PlatformError::Command("TUN requires an address".into()))?;
    let mut tun_config = tun::configure();
    tun_config
        .address(address.addr())
        .netmask(address.netmask())
        .mtu(config.mtu)
        .up();
    #[cfg(not(target_os = "macos"))]
    tun_config.tun_name(&config.name);
    #[cfg(target_os = "macos")]
    {
        if !config.name.starts_with("utun") {
            return Err(PlatformError::Command(
                "macOS TUN name must be utunN (for example utun0)".into(),
            ));
        }
        tun_config.tun_name(&config.name);
        // `tun` defaults an unspecified macOS utun destination to
        // 10.0.0.255.  Besides making `ifconfig` misleading, that creates a
        // phantom point-to-point peer unrelated to the Overlay address.  A
        // Tinect utun is a routed multipoint interface, so use the local
        // address as its harmless P2P peer and let `route_imports` own every
        // usable route explicitly.
        tun_config.destination(address.addr());
        tun_config.platform_config(|platform| {
            platform.enable_routing(false);
        });
    }
    #[cfg(target_os = "linux")]
    tun_config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });
    let device = tun::create_as_async(&tun_config)
        .map(|device| TunDevice {
            inner: Arc::new(device),
        })
        .map_err(|error| PlatformError::Command(error.to_string()))?;
    // Best-effort: ask the kernel to segment to the TUN MTU instead of
    // handing userspace GSO super-packets. A fresh TUN reports
    // `generic-segmentation-offload: on`; when the ioctl is unsupported
    // (EOPNOTSUPP on some TUN drivers, which expect ethtool-netlink
    // instead) this only warns because the data plane segments TCP
    // super-packets in userspace (see `segment_tcp_gso`). The ioctl
    // path avoids an `ethtool` subprocess dependency where it works.
    #[cfg(target_os = "linux")]
    {
        let name = tun_name(&device.inner)?;
        if let Err(error) = disable_tun_offloads(&name) {
            tracing::warn!(tun = %name, error = %error, "TUN offloads could not be disabled; TCP super-packets will be segmented in userspace");
        }
    }
    Ok(device)
}

/// Best-effort disabling of GSO/GRO/TSO on a Linux TUN (see `create_tun`).
///
/// The legacy `SIOCETHTOOL` ioctl is unsupported by some TUN drivers
/// (EOPNOTSUPP); modern `ethtool` uses netlink for these knobs. Failure is
/// therefore non-fatal: the data plane must handle super-packets regardless.
#[cfg(target_os = "linux")]
fn disable_tun_offloads(name: &str) -> Result<(), PlatformError> {
    // Linux UAPI (`linux/ethtool.h`): ETHTOOL_SGSO=0x24, ETHTOOL_SGRO=0x2c,
    // ETHTOOL_STSO=0x1f. `libc` does not export these numbers.
    const ETHTOOL_SGSO: u32 = 0x0000_0024;
    const ETHTOOL_SGRO: u32 = 0x0000_002c;
    const ETHTOOL_STSO: u32 = 0x0000_001f;
    #[repr(C)]
    struct EthtoolValue {
        cmd: u32,
        data: u32,
    }
    fn set_one(name: &str, cmd: u32) -> Result<(), PlatformError> {
        // SAFETY: opens a datagram socket for a synchronous ETHTOOL ioctl,
        // issues exactly one `SIOCETHTOOL` with a stack `ethtool_value`,
        // then closes the socket. All pointers stay within their stack
        // frames for the duration of the call.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(PlatformError::Command(format!(
                    "disabling TUN offloads on {name}: socket failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let result = (|| {
                let mut value = EthtoolValue { cmd, data: 0 };
                let mut request: libc::ifreq = std::mem::zeroed();
                let name_bytes = name.as_bytes();
                if name_bytes.len() >= request.ifr_name.len() {
                    return Err(PlatformError::Command(format!(
                        "disabling TUN offloads on {name}: interface name too long"
                    )));
                }
                for (slot, byte) in request.ifr_name.iter_mut().zip(name_bytes.iter()) {
                    *slot = *byte as libc::c_char;
                }
                request.ifr_ifru.ifru_data = std::ptr::addr_of_mut!(value).cast::<libc::c_char>();
                if libc::ioctl(fd, libc::SIOCETHTOOL as _, &mut request) != 0 {
                    return Err(PlatformError::Command(format!(
                        "disabling TUN offloads on {name}: ethtool 0x{cmd:08x} failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                Ok(())
            })();
            libc::close(fd);
            result
        }
    }
    // Try every knob even if an earlier one is unsupported: TUN drivers differ
    // in which legacy ioctls they implement, and GRO/TSO are still worth
    // disabling when GSO is not.
    let mut first_error = None;
    for cmd in [ETHTOOL_SGSO, ETHTOOL_SGRO, ETHTOOL_STSO] {
        if let Err(error) = set_one(name, cmd)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

/// Return the kernel-assigned interface name. Linux may allocate a name when
/// the configuration leaves it empty, so callers must use this value for all
/// subsequent route, firewall, hook, and cleanup operations.
fn tun_name(device: &tun::AsyncDevice) -> Result<String, PlatformError> {
    use tun::AbstractDevice;

    device
        .tun_name()
        .map_err(|error| PlatformError::Command(format!("reading TUN name: {error}")))
}

/// Configure every address after the first one. The `tun` crate configures a
/// single address during device creation, while the public configuration
/// deliberately supports both IPv4 and IPv6 addresses on one interface.
pub async fn configure_tun_addresses(
    tun_name: &str,
    addresses: &[IpNet],
) -> Result<(), PlatformError> {
    if addresses.len() <= 1 {
        return Ok(());
    }
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => linux_configure_tun_addresses(tun_name, addresses).await,
        #[cfg(target_os = "macos")]
        "macos" => {
            for prefix in addresses.iter().skip(1) {
                match prefix.addr() {
                    IpAddr::V4(address) => {
                        let value = address.to_string();
                        let netmask = prefix.netmask().to_string();
                        run_checked(
                            "ifconfig",
                            &[tun_name, "inet", &value, "netmask", &netmask, "alias"],
                        )?;
                    }
                    IpAddr::V6(address) => {
                        let value = format!("{address}/{}", prefix.prefix_len());
                        run_checked("ifconfig", &[tun_name, "inet6", &value, "alias"])?;
                    }
                }
            }
            Ok(())
        }
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

#[cfg(target_os = "linux")]
async fn linux_configure_tun_addresses(
    tun_name: &str,
    addresses: &[IpNet],
) -> Result<(), PlatformError> {
    let (connection, handle, _) = new_connection().map_err(netlink_error)?;
    tokio::spawn(connection);
    let tun_index = handle
        .link()
        .get()
        .match_name(tun_name.to_owned())
        .execute()
        .try_next()
        .await
        .map_err(netlink_error)?
        .ok_or_else(|| PlatformError::Command(format!("TUN interface not found: {tun_name}")))?
        .header
        .index;
    for address in addresses.iter().skip(1) {
        handle
            .address()
            .add(tun_index, address.addr(), address.prefix_len())
            .execute()
            .await
            .map_err(netlink_error)?;
    }
    Ok(())
}

/// Adjusts an already-created TUN to the currently usable overlay MTU.
///
/// QUIC path discovery can lower the DATAGRAM limit after the TUN has been
/// created. Keeping the interface at its initial MTU would let the kernel
/// emit packets that the active circuit must drop. This operation is owned by
/// the platform layer because it changes host networking state.
pub async fn set_tun_mtu(name: &str, mtu: u16) -> Result<(), PlatformError> {
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => {
            let (connection, handle, _) = new_connection().map_err(netlink_error)?;
            tokio::spawn(connection);
            let link = handle
                .link()
                .get()
                .match_name(name.to_owned())
                .execute()
                .try_next()
                .await
                .map_err(netlink_error)?
                .ok_or_else(|| {
                    PlatformError::Command(format!("TUN interface not found: {name}"))
                })?;
            handle
                .link()
                .change(
                    LinkUnspec::new_with_index(link.header.index)
                        .mtu(u32::from(mtu))
                        .build(),
                )
                .execute()
                .await
                .map_err(netlink_error)
        }
        #[cfg(target_os = "macos")]
        "macos" => run_checked("ifconfig", &[name, "mtu", &mtu.to_string()]),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}
/// Installs the default local-delivery rule for a Tinect TUN. This uses a
/// dedicated nftables table so cleanup cannot affect host-owned rules.
pub fn apply_tun_input_firewall(_tun: &TunConfig) -> Result<TunInputFirewallState, PlatformError> {
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => {
            let table_name = linux_tun_input_table_name(&_tun.name);
            install_linux_tun_input_firewall(&_tun.name, &table_name)?;
            Ok(TunInputFirewallState { table_name })
        }
        #[cfg(target_os = "macos")]
        "macos" => Ok(TunInputFirewallState {}),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

pub fn cleanup_tun_input_firewall(_state: &TunInputFirewallState) -> Result<(), PlatformError> {
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => {
            let ipv4 = delete_linux_tun_input_table(nftnl::ProtoFamily::Ipv4, &_state.table_name);
            let ipv6 = delete_linux_tun_input_table(nftnl::ProtoFamily::Ipv6, &_state.table_name);
            ipv4.and(ipv6)
        }
        #[cfg(target_os = "macos")]
        "macos" => Ok(()),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

pub fn apply_direct_firewall(
    tun: &TunConfig,
    direct: Option<&DirectConfig>,
) -> Result<DirectFirewallState, PlatformError> {
    #[cfg(not(target_os = "linux"))]
    let _ = (tun, direct);
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => {
            let owned_table_name = linux_direct_table_name(&tun.name);
            // A process crash leaves nftables objects behind. Reconcile this
            // whole daemon-owned table instead of appending duplicate ordered
            // rules, which could make an old marker rule clear DSCP before a
            // new loop guard evaluates it.
            let _ = delete_linux_direct_table(&owned_table_name);
            let table_name =
                match direct.and_then(|config| config.fwmark.map(|fwmark| (config, fwmark))) {
                    Some((config, fwmark)) => {
                        install_linux_direct_firewall(
                            &tun.name,
                            &owned_table_name,
                            config.dscp,
                            fwmark,
                        )?;
                        Some(owned_table_name)
                    }
                    None => None,
                };
            Ok(DirectFirewallState { table_name })
        }
        #[cfg(target_os = "macos")]
        "macos" => Ok(DirectFirewallState {}),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

pub fn cleanup_direct_firewall(state: &DirectFirewallState) -> Result<(), PlatformError> {
    #[cfg(not(target_os = "linux"))]
    let _ = state;
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => state
            .table_name
            .as_deref()
            .map_or(Ok(()), delete_linux_direct_table),
        #[cfg(target_os = "macos")]
        "macos" => Ok(()),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

/// Installs the directional conntrack-zone plumbing and, with
/// `managed_routes` enabled, the owned POSTROUTING masquerade for direct
/// fallback reinjection.
///
/// The zone rules are always installed when `direct` is configured.
/// The data plane deletes the first-pass zone-zero flow through ctnetlink
/// before reinjection. Assigning the reinjected original direction to an
/// isolated zone ensures it is treated as a NAT first packet even if a late
/// first-pass skb confirms its old flow. This also makes
/// `managed_routes: false` usable with operator-owned masquerade.
///
/// With `managed_routes` enabled the daemon additionally takes ownership of
/// the basic NAT step: reinjected fallback packets carry either a TUN source
/// address or a node-local FakeIP source anchor, so without masquerade their
/// replies cannot come back. Those rules run at priority 150 (after the
/// conventional srcnat chains), so an operator's own SNAT/masquerade rules
/// still take precedence and only unhandled fallback packets hit this
/// fallback.
pub fn apply_direct_nat(
    tun: &TunConfig,
    direct: Option<&DirectConfig>,
    managed_routes: bool,
) -> Result<DirectNatState, PlatformError> {
    #[cfg(not(target_os = "linux"))]
    let _ = (tun, direct, managed_routes);
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => {
            let owned_table_name = linux_direct_nat_table_name(&tun.name);
            // See the firewall reconciliation above. The zone table must also
            // be rebuilt so a crash/restart cannot accumulate duplicate zone
            // and masquerade rules.
            let _ = delete_linux_direct_nat_table(&owned_table_name);
            let table_name = match direct {
                Some(config) => {
                    install_linux_direct_nat(
                        tun,
                        &owned_table_name,
                        config.dscp,
                        config.fwmark,
                        config.conntrack_zone,
                        managed_routes,
                    )?;
                    Some(owned_table_name)
                }
                _ => None,
            };
            Ok(DirectNatState { table_name })
        }
        #[cfg(target_os = "macos")]
        "macos" => Ok(DirectNatState {}),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

pub fn cleanup_direct_nat(state: &DirectNatState) -> Result<(), PlatformError> {
    #[cfg(not(target_os = "linux"))]
    let _ = state;
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => state.table_name.as_deref().map_or(Ok(()), |table_name| {
            delete_linux_direct_nat_table(table_name)
        }),
        #[cfg(target_os = "macos")]
        "macos" => Ok(()),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

pub fn apply_exit_network(
    tun: &TunConfig,
    forwarded_exit: bool,
) -> Result<ExitNetworkState, PlatformError> {
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => {
            if forwarded_exit {
                require_ip_forwarding(&["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"])?;
            }
            let table_name = linux_exit_table_name(&tun.name);
            install_linux_exit_firewall(tun, forwarded_exit, &table_name)?;
            Ok(ExitNetworkState { table_name })
        }
        #[cfg(target_os = "macos")]
        "macos" => {
            if forwarded_exit {
                require_ip_forwarding(&["net.inet.ip.forwarding", "net.inet6.ip6.forwarding"])?;
            }
            if let Err(error) = install_macos_exit_firewall(tun) {
                let _ = cleanup_exit_network(&ExitNetworkState {
                    #[cfg(target_os = "linux")]
                    table_name: linux_exit_table_name(&tun.name),
                });
                return Err(error);
            }
            Ok(ExitNetworkState {
                #[cfg(target_os = "linux")]
                table_name: linux_exit_table_name(&tun.name),
            })
        }
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

pub fn cleanup_exit_network(_state: &ExitNetworkState) -> Result<(), PlatformError> {
    match std::env::consts::OS {
        #[cfg(target_os = "linux")]
        "linux" => {
            let ipv4 = delete_linux_exit_table(nftnl::ProtoFamily::Ipv4, &_state.table_name);
            let ipv6 = delete_linux_exit_table(nftnl::ProtoFamily::Ipv6, &_state.table_name);
            ipv4.and(ipv6)
        }
        #[cfg(target_os = "macos")]
        "macos" => cleanup_macos_exit_firewall(),
        other => Err(PlatformError::Unsupported(other.into())),
    }
}

#[cfg(target_os = "macos")]
fn install_macos_exit_firewall(tun: &TunConfig) -> Result<(), PlatformError> {
    use pfctl::{
        AnchorKind, Endpoint, Ip, NatEndpoint, NatRuleAction, NatRuleBuilder, PfCtl, RulesetKind,
    };

    let mut pf = PfCtl::new().map_err(|error| PlatformError::Command(error.to_string()))?;
    pf.try_add_anchor(PF_ANCHOR, AnchorKind::Nat)
        .map_err(|error| PlatformError::Command(error.to_string()))?;
    pf.flush_rules(PF_ANCHOR, RulesetKind::Nat)
        .map_err(|error| PlatformError::Command(error.to_string()))?;

    for prefix in &tun.addresses {
        let prefix = prefix
            .to_string()
            .parse::<pfctl::ipnetwork::IpNetwork>()
            .map_err(|error| PlatformError::Command(error.to_string()))?;
        let rule = NatRuleBuilder::default()
            .action(NatRuleAction::Nat {
                nat_to: NatEndpoint::interface_address("egress"),
            })
            .interface("egress")
            .from(Endpoint::from(Ip::from(prefix)))
            .build()
            .map_err(|error| PlatformError::Command(error.to_string()))?;
        pf.add_nat_rule(PF_ANCHOR, &rule)
            .map_err(|error| PlatformError::Command(error.to_string()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cleanup_macos_exit_firewall() -> Result<(), PlatformError> {
    use pfctl::{AnchorKind, PfCtl, RulesetKind};

    let mut pf = PfCtl::new().map_err(|error| PlatformError::Command(error.to_string()))?;
    let flush = pf
        .flush_rules(PF_ANCHOR, RulesetKind::Nat)
        .map_err(|error| PlatformError::Command(error.to_string()));
    let remove = pf
        .try_remove_anchor(PF_ANCHOR, AnchorKind::Nat)
        .map_err(|error| PlatformError::Command(error.to_string()));
    flush.and(remove)
}

#[cfg(target_os = "linux")]
fn linux_owned_table_name(prefix: &str, tun_name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(tun_name.len() * 2);
    for byte in tun_name.bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    let suffix = if encoded.is_empty() { "tun" } else { &encoded };
    format!("{prefix}_{suffix}")
}

#[cfg(target_os = "linux")]
fn linux_exit_table_name(tun_name: &str) -> String {
    linux_owned_table_name("tinect_exit", tun_name)
}

#[cfg(target_os = "linux")]
fn linux_tun_input_table_name(tun_name: &str) -> String {
    linux_owned_table_name("tinect_input", tun_name)
}

#[cfg(target_os = "linux")]
fn linux_direct_table_name(tun_name: &str) -> String {
    linux_owned_table_name("tinect_direct", tun_name)
}

#[cfg(target_os = "linux")]
fn linux_direct_nat_table_name(tun_name: &str) -> String {
    linux_owned_table_name("tinect_direct_nat", tun_name)
}

#[cfg(target_os = "linux")]
struct NftPayloadStore {
    offset: u32,
    length: u32,
    checksum: Option<(u32, u32)>,
}

#[cfg(target_os = "linux")]
impl NftPayloadStore {
    fn network(offset: u32, length: u32, checksum: Option<(u32, u32)>) -> Self {
        Self {
            offset,
            length,
            checksum,
        }
    }
}

#[cfg(target_os = "linux")]
impl nftnl::expr::Expression for NftPayloadStore {
    fn to_expr(&self, _rule: &nftnl::Rule) -> std::ptr::NonNull<nftnl::nftnl_sys::nftnl_expr> {
        let expression = unsafe { nftnl::nftnl_sys::nftnl_expr_alloc(c"payload".as_ptr()) };
        let expression = std::ptr::NonNull::new(expression).expect("nftnl payload allocation");
        unsafe {
            let expression = expression.as_ptr();
            nftnl::nftnl_sys::nftnl_expr_set_u32(
                expression,
                nftnl::nftnl_sys::NFTNL_EXPR_PAYLOAD_BASE as u16,
                nftnl::nftnl_sys::libc::NFT_PAYLOAD_NETWORK_HEADER as u32,
            );
            nftnl::nftnl_sys::nftnl_expr_set_u32(
                expression,
                nftnl::nftnl_sys::NFTNL_EXPR_PAYLOAD_OFFSET as u16,
                self.offset,
            );
            nftnl::nftnl_sys::nftnl_expr_set_u32(
                expression,
                nftnl::nftnl_sys::NFTNL_EXPR_PAYLOAD_LEN as u16,
                self.length,
            );
            nftnl::nftnl_sys::nftnl_expr_set_u32(
                expression,
                nftnl::nftnl_sys::NFTNL_EXPR_PAYLOAD_SREG as u16,
                nftnl::nftnl_sys::libc::NFT_REG_1 as u32,
            );
            if let Some((checksum_type, checksum_offset)) = self.checksum {
                nftnl::nftnl_sys::nftnl_expr_set_u32(
                    expression,
                    nftnl::nftnl_sys::NFTNL_EXPR_PAYLOAD_CSUM_TYPE as u16,
                    checksum_type,
                );
                nftnl::nftnl_sys::nftnl_expr_set_u32(
                    expression,
                    nftnl::nftnl_sys::NFTNL_EXPR_PAYLOAD_CSUM_OFFSET as u16,
                    checksum_offset,
                );
            }
        }
        expression
    }
}

/// `ct original zone set reg 1`.  nftnl does not expose the zone/direction
/// variant, so use its raw expression API while retaining the safe Rule owner.
#[cfg(target_os = "linux")]
struct NftCtOriginalZoneSet;

#[cfg(target_os = "linux")]
impl nftnl::expr::Expression for NftCtOriginalZoneSet {
    fn to_expr(&self, _rule: &nftnl::Rule) -> std::ptr::NonNull<nftnl::nftnl_sys::nftnl_expr> {
        let expression = unsafe { nftnl::nftnl_sys::nftnl_expr_alloc(c"ct".as_ptr()) };
        let expression = std::ptr::NonNull::new(expression).expect("nftnl ct allocation");
        unsafe {
            nftnl::nftnl_sys::nftnl_expr_set_u32(
                expression.as_ptr(),
                nftnl::nftnl_sys::NFTNL_EXPR_CT_SREG as u16,
                nftnl::nftnl_sys::libc::NFT_REG_1 as u32,
            );
            nftnl::nftnl_sys::nftnl_expr_set_u32(
                expression.as_ptr(),
                nftnl::nftnl_sys::NFTNL_EXPR_CT_KEY as u16,
                nftnl::nftnl_sys::libc::NFT_CT_ZONE as u32,
            );
            nftnl::nftnl_sys::nftnl_expr_set_u8(
                expression.as_ptr(),
                nftnl::nftnl_sys::NFTNL_EXPR_CT_DIR as u16,
                0, // IP_CT_DIR_ORIGINAL
            );
        }
        expression
    }
}

#[cfg(target_os = "linux")]
fn install_linux_direct_firewall(
    tun_name: &str,
    table_name: &str,
    dscp: u8,
    fwmark: u32,
) -> Result<(), PlatformError> {
    send_linux_nft_batch(
        build_linux_direct_firewall(tun_name, table_name, dscp, fwmark)?.finalize(),
    )
}

#[cfg(target_os = "linux")]
fn build_linux_direct_firewall(
    tun_name: &str,
    table_name: &str,
    dscp: u8,
    fwmark: u32,
) -> Result<nftnl::Batch, PlatformError> {
    use nftnl::{
        Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table, nft_expr,
    };

    let tun_name = CString::new(tun_name)
        .map_err(|_| PlatformError::Command("TUN name contains a NUL byte".into()))?;
    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let table = Table::new(table_name.as_c_str(), ProtoFamily::Inet);
    let mut chain = Chain::new(c"prerouting", &table);
    chain.set_hook(Hook::PreRouting, -150);
    chain.set_type(ChainType::Filter);
    chain.set_policy(Policy::Accept);
    let mut forward = Chain::new(c"forward", &table);
    forward.set_hook(Hook::Forward, -150);
    forward.set_type(ChainType::Filter);
    forward.set_policy(Policy::Accept);
    let mut output = Chain::new(c"output", &table);
    output.set_hook(Hook::Out, -150);
    output.set_type(ChainType::Filter);
    output.set_policy(Policy::Accept);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&chain, MsgType::Add);

    // The mark is reserved by this feature. For every non-zero mark this
    // guard is deliberately first. A daemon reinjection always writes a fresh
    // skb whose mark is zero, and the prerouting rule clears DSCP before a
    // marked packet could be delivered back to the TUN fd, so a prerouting
    // check alone can never see the loop: the marked packet must be caught
    // after the routing decision, before it is transmitted back into this
    // TUN. The forward and output chains therefore drop any packet carrying
    // the reserved mark whose next hop is this TUN, whether it is being
    // forwarded or generated locally. Mark zero is the kernel default, so it
    // cannot distinguish an unmarked packet from one carrying the configured
    // mark; no safe kernel-side loop guard exists for that value without also
    // dropping ordinary unmarked TUN traffic.
    if fwmark != 0 {
        let mut loop_guard = Rule::new(&chain);
        loop_guard.add_expr(&nft_expr!(meta iifname));
        loop_guard.add_expr(&nft_expr!(cmp == tun_name.as_c_str()));
        loop_guard.add_expr(&nft_expr!(meta mark));
        loop_guard.add_expr(&nft_expr!(cmp == fwmark));
        loop_guard.add_expr(&nft_expr!(counter));
        loop_guard.add_expr(&nft_expr!(verdict drop));
        batch.add(&loop_guard, MsgType::Add);
        batch.add(&forward, MsgType::Add);
        add_linux_loop_guard_rule(&mut batch, &forward, tun_name.as_c_str(), fwmark);
        batch.add(&output, MsgType::Add);
        add_linux_loop_guard_rule(&mut batch, &output, tun_name.as_c_str(), fwmark);
    }

    let mut ipv4_rule = Rule::new(&chain);
    ipv4_rule.add_expr(&nft_expr!(meta iifname));
    ipv4_rule.add_expr(&nft_expr!(cmp == tun_name.as_c_str()));
    ipv4_rule.add_expr(&nft_expr!(meta nfproto));
    ipv4_rule.add_expr(&nft_expr!(cmp == 2_u8));
    // libnftnl's raw payload fields use byte offsets and lengths here, even
    // though the public enum names them as bit offsets. IPv4 DSCP/ECN is the
    // second byte of the network header.
    ipv4_rule.add_expr(&nft_expr!(payload_raw nh 1, 1));
    ipv4_rule.add_expr(&nft_expr!(bitwise mask 0xfc_u8, xor 0_u8));
    ipv4_rule.add_expr(&nft_expr!(cmp == (dscp << 2)));
    ipv4_rule.add_expr(&nft_expr!(counter));
    ipv4_rule.add_expr(&nft_expr!(immediate data fwmark));
    ipv4_rule.add_expr(&nft_expr!(meta mark set));
    ipv4_rule.add_expr(&nft_expr!(payload_raw nh 0, 2));
    ipv4_rule.add_expr(&nft_expr!(bitwise mask 0x03ff_u16, xor 0_u16));
    ipv4_rule.add_expr(&NftPayloadStore::network(0, 2, Some((1, 10))));
    batch.add(&ipv4_rule, MsgType::Add);

    let mut ipv6_rule = Rule::new(&chain);
    ipv6_rule.add_expr(&nft_expr!(meta iifname));
    ipv6_rule.add_expr(&nft_expr!(cmp == tun_name.as_c_str()));
    ipv6_rule.add_expr(&nft_expr!(meta nfproto));
    ipv6_rule.add_expr(&nft_expr!(cmp == 10_u8));
    ipv6_rule.add_expr(&nft_expr!(payload_raw nh 0, 2));
    ipv6_rule.add_expr(&nft_expr!(bitwise mask 0xc00f_u16, xor 0_u16));
    ipv6_rule.add_expr(&nft_expr!(cmp == ipv6_dscp_value(dscp)));
    ipv6_rule.add_expr(&nft_expr!(counter));
    ipv6_rule.add_expr(&nft_expr!(immediate data fwmark));
    ipv6_rule.add_expr(&nft_expr!(meta mark set));
    ipv6_rule.add_expr(&nft_expr!(payload_raw nh 0, 2));
    ipv6_rule.add_expr(&nft_expr!(bitwise mask 0x3ff0_u16, xor 0_u16));
    ipv6_rule.add_expr(&NftPayloadStore::network(0, 2, None));
    batch.add(&ipv6_rule, MsgType::Add);
    Ok(batch)
}

#[cfg(target_os = "linux")]
fn add_linux_loop_guard_rule(
    batch: &mut nftnl::Batch,
    chain: &nftnl::Chain,
    tun_name: &std::ffi::CStr,
    fwmark: u32,
) {
    use nftnl::{MsgType, Rule, nft_expr};

    let mut loop_guard = Rule::new(chain);
    loop_guard.add_expr(&nft_expr!(meta oifname));
    loop_guard.add_expr(&nft_expr!(cmp == tun_name));
    loop_guard.add_expr(&nft_expr!(meta mark));
    loop_guard.add_expr(&nft_expr!(cmp == fwmark));
    loop_guard.add_expr(&nft_expr!(counter));
    loop_guard.add_expr(&nft_expr!(verdict drop));
    batch.add(&loop_guard, MsgType::Add);
}

#[cfg(target_os = "linux")]
fn ipv6_dscp_value(dscp: u8) -> u16 {
    (u16::from(dscp & 0x03) << 14) | u16::from(dscp >> 2)
}

#[cfg(target_os = "linux")]
fn delete_linux_direct_table(table_name: &str) -> Result<(), PlatformError> {
    use nftnl::{Batch, MsgType, ProtoFamily, Table};

    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let table = Table::new(table_name.as_c_str(), ProtoFamily::Inet);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);
    send_linux_nft_batch(batch.finalize())
}

/// Owned NAT plumbing for reinjected fallback packets.
///
/// A fallback packet crosses the kernel stack twice with the same tuple.  The
/// data plane deletes the first-pass zone-zero entry through ctnetlink before
/// reinjection, and the raw rule below places the reinjected original
/// direction in a dedicated zone.  Replies deliberately retain zone zero, so
/// they can find the NAT entry without requiring an ingress-interface rule.
///
/// The POSTROUTING chain runs at priority 150, after the conventional srcnat
/// chains, so an operator's own SNAT/masquerade rules are evaluated first and
/// this only acts as a fallback for packets they chose not to handle. With a
/// non-zero fwmark the reinjected packet is identified by that mark;
/// otherwise it keeps the configured TUN source address (or the node-local
/// FakeIP source anchor), which ordinary underlay traffic never has.
#[cfg(target_os = "linux")]
fn install_linux_direct_nat(
    tun: &TunConfig,
    table_name: &str,
    dscp: u8,
    fwmark: Option<u32>,
    conntrack_zone: u16,
    install_masquerade: bool,
) -> Result<(), PlatformError> {
    send_linux_nft_batch(
        build_linux_direct_nat(
            tun,
            table_name,
            dscp,
            fwmark,
            conntrack_zone,
            install_masquerade,
        )?
        .finalize(),
    )
}

#[cfg(target_os = "linux")]
fn build_linux_direct_nat(
    tun: &TunConfig,
    table_name: &str,
    dscp: u8,
    fwmark: Option<u32>,
    conntrack_zone: u16,
    install_masquerade: bool,
) -> Result<nftnl::Batch, PlatformError> {
    use nftnl::{
        Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table, nft_expr,
    };

    let tun_name = CString::new(tun.name.as_str())
        .map_err(|_| PlatformError::Command("TUN name contains a NUL byte".into()))?;
    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let table = Table::new(table_name.as_c_str(), ProtoFamily::Inet);
    let mut raw_prerouting = Chain::new(c"prerouting", &table);
    // Run before conventional raw chains as well as conntrack (-200), so a
    // reinjected packet cannot acquire a zone-zero entry first.
    raw_prerouting.set_hook(Hook::PreRouting, -310);
    raw_prerouting.set_type(ChainType::Filter);
    raw_prerouting.set_policy(Policy::Accept);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&raw_prerouting, MsgType::Add);

    let mut ipv4_zone = Rule::new(&raw_prerouting);
    ipv4_zone.add_expr(&nft_expr!(meta iifname));
    ipv4_zone.add_expr(&nft_expr!(cmp == tun_name.as_c_str()));
    ipv4_zone.add_expr(&nft_expr!(meta nfproto));
    ipv4_zone.add_expr(&nft_expr!(cmp == 2_u8));
    ipv4_zone.add_expr(&nft_expr!(payload_raw nh 1, 1));
    ipv4_zone.add_expr(&nft_expr!(bitwise mask 0xfc_u8, xor 0_u8));
    ipv4_zone.add_expr(&nft_expr!(cmp == dscp << 2));
    ipv4_zone.add_expr(&nft_expr!(immediate data conntrack_zone));
    ipv4_zone.add_expr(&NftCtOriginalZoneSet);
    batch.add(&ipv4_zone, MsgType::Add);

    let mut ipv6_zone = Rule::new(&raw_prerouting);
    ipv6_zone.add_expr(&nft_expr!(meta iifname));
    ipv6_zone.add_expr(&nft_expr!(cmp == tun_name.as_c_str()));
    ipv6_zone.add_expr(&nft_expr!(meta nfproto));
    ipv6_zone.add_expr(&nft_expr!(cmp == 10_u8));
    ipv6_zone.add_expr(&nft_expr!(payload_raw nh 0, 2));
    ipv6_zone.add_expr(&nft_expr!(bitwise mask 0xc00f_u16, xor 0_u16));
    ipv6_zone.add_expr(&nft_expr!(cmp == ipv6_dscp_value(dscp)));
    ipv6_zone.add_expr(&nft_expr!(immediate data conntrack_zone));
    ipv6_zone.add_expr(&NftCtOriginalZoneSet);
    batch.add(&ipv6_zone, MsgType::Add);

    if install_masquerade {
        let mut postrouting = Chain::new(c"postrouting", &table);
        postrouting.set_hook(Hook::PostRouting, 150);
        postrouting.set_type(ChainType::Nat);
        postrouting.set_policy(Policy::Accept);
        batch.add(&postrouting, MsgType::Add);
        if let Some(fwmark) = fwmark.filter(|&mark| mark != 0) {
            for nfproto in [2_u8, 10_u8] {
                let mut rule = Rule::new(&postrouting);
                rule.add_expr(&nft_expr!(meta nfproto));
                rule.add_expr(&nft_expr!(cmp == nfproto));
                rule.add_expr(&nft_expr!(meta mark));
                rule.add_expr(&nft_expr!(cmp == fwmark));
                rule.add_expr(&nft_expr!(meta oifname));
                rule.add_expr(&nft_expr!(cmp != tun_name.as_c_str()));
                rule.add_expr(&nft_expr!(masquerade));
                batch.add(&rule, MsgType::Add);
            }
        } else {
            for prefix in &tun.addresses {
                let mut rule = Rule::new(&postrouting);
                match prefix {
                    IpNet::V4(prefix) => {
                        rule.add_expr(&nft_expr!(meta nfproto));
                        rule.add_expr(&nft_expr!(cmp == 2_u8));
                        rule.add_expr(&nft_expr!(payload ipv4 saddr));
                        rule.add_expr(&nft_expr!(cmp == prefix.addr()));
                    }
                    IpNet::V6(prefix) => {
                        rule.add_expr(&nft_expr!(meta nfproto));
                        rule.add_expr(&nft_expr!(cmp == 10_u8));
                        rule.add_expr(&nft_expr!(payload ipv6 saddr));
                        rule.add_expr(&nft_expr!(cmp == prefix.addr()));
                    }
                }
                rule.add_expr(&nft_expr!(meta oifname));
                rule.add_expr(&nft_expr!(cmp != tun_name.as_c_str()));
                rule.add_expr(&nft_expr!(masquerade));
                batch.add(&rule, MsgType::Add);
            }
        }
    }
    Ok(batch)
}

#[cfg(target_os = "linux")]
fn delete_linux_direct_nat_table(table_name: &str) -> Result<(), PlatformError> {
    use nftnl::{Batch, MsgType, ProtoFamily, Table};

    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let table = Table::new(table_name.as_c_str(), ProtoFamily::Inet);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);
    send_linux_nft_batch(batch.finalize())
}

#[cfg(target_os = "linux")]
fn install_linux_exit_firewall(
    tun: &TunConfig,
    forwarded_exit: bool,
    table_name: &str,
) -> Result<(), PlatformError> {
    send_linux_nft_batch(build_linux_exit_firewall(tun, forwarded_exit, table_name)?.finalize())
}

#[cfg(target_os = "linux")]
fn build_linux_exit_firewall(
    tun: &TunConfig,
    forwarded_exit: bool,
    table_name: &str,
) -> Result<nftnl::Batch, PlatformError> {
    use nftnl::{
        Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table, nft_expr,
    };

    let tun_name = CString::new(tun.name.as_str())
        .map_err(|_| PlatformError::Command("TUN name contains a NUL byte".into()))?;
    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let mut batch = Batch::new();
    let ipv4 = Table::new(table_name.as_c_str(), ProtoFamily::Ipv4);
    let ipv6 = Table::new(table_name.as_c_str(), ProtoFamily::Ipv6);
    batch.add(&ipv4, MsgType::Add);
    batch.add(&ipv6, MsgType::Add);

    let mut ipv4_forward = Chain::new(c"forward", &ipv4);
    ipv4_forward.set_hook(Hook::Forward, 0);
    ipv4_forward.set_type(ChainType::Filter);
    let mut ipv6_forward = Chain::new(c"forward", &ipv6);
    ipv6_forward.set_hook(Hook::Forward, 0);
    ipv6_forward.set_type(ChainType::Filter);
    batch.add(&ipv4_forward, MsgType::Add);
    batch.add(&ipv6_forward, MsgType::Add);

    let mut ipv4_nat = Chain::new(c"postrouting", &ipv4);
    ipv4_nat.set_hook(Hook::PostRouting, 100);
    ipv4_nat.set_type(ChainType::Nat);
    ipv4_nat.set_policy(Policy::Accept);
    let mut ipv6_nat = Chain::new(c"postrouting", &ipv6);
    ipv6_nat.set_hook(Hook::PostRouting, 100);
    ipv6_nat.set_type(ChainType::Nat);
    ipv6_nat.set_policy(Policy::Accept);
    batch.add(&ipv4_nat, MsgType::Add);
    batch.add(&ipv6_nat, MsgType::Add);

    if forwarded_exit {
        for chain in [&ipv4_forward, &ipv6_forward] {
            let mut rule = Rule::new(chain);
            rule.add_expr(&nft_expr!(meta iifname));
            rule.add_expr(&nft_expr!(cmp == tun_name.as_c_str()));
            rule.add_expr(&nft_expr!(meta oifname));
            rule.add_expr(&nft_expr!(cmp != tun_name.as_c_str()));
            rule.add_expr(&nft_expr!(verdict accept));
            batch.add(&rule, MsgType::Add);
        }
    }
    // Keep the ingress-interface rule for encrypted exit traffic.  Local
    // fallback packets are reinjected after route selection, so they no
    // longer have the TUN as their ingress interface; the source-prefix rules
    // below cover that second path.
    for chain in [&ipv4_nat, &ipv6_nat] {
        let mut rule = Rule::new(chain);
        rule.add_expr(&nft_expr!(meta iifname));
        rule.add_expr(&nft_expr!(cmp == tun_name.as_c_str()));
        rule.add_expr(&nft_expr!(meta oifname));
        rule.add_expr(&nft_expr!(cmp != tun_name.as_c_str()));
        rule.add_expr(&nft_expr!(masquerade));
        batch.add(&rule, MsgType::Add);
    }
    for prefix in &tun.addresses {
        let chain = if prefix.addr().is_ipv4() {
            &ipv4_nat
        } else {
            &ipv6_nat
        };
        // The configured TUN address is the common source for both encrypted
        // exits and raw local fallback packets.  Keep an exact-address rule in
        // addition to the prefix rule below: it avoids architecture-specific
        // netlink byte-order handling from making a host-prefix masquerade
        // miss.
        let mut exact_rule = Rule::new(chain);
        match prefix {
            IpNet::V4(prefix) => {
                exact_rule.add_expr(&nft_expr!(payload ipv4 saddr));
                exact_rule.add_expr(&nft_expr!(cmp == prefix.addr()));
            }
            IpNet::V6(prefix) => {
                exact_rule.add_expr(&nft_expr!(payload ipv6 saddr));
                exact_rule.add_expr(&nft_expr!(cmp == prefix.addr()));
            }
        }
        exact_rule.add_expr(&nft_expr!(meta oifname));
        exact_rule.add_expr(&nft_expr!(cmp != tun_name.as_c_str()));
        exact_rule.add_expr(&nft_expr!(masquerade));
        batch.add(&exact_rule, MsgType::Add);
        let mut rule = Rule::new(chain);
        match prefix {
            IpNet::V4(prefix) => {
                rule.add_expr(&nft_expr!(payload ipv4 saddr));
                rule.add_expr(&nft_expr!(
                    bitwise mask prefix.netmask(),
                    xor std::net::Ipv4Addr::UNSPECIFIED
                ));
                rule.add_expr(&nft_expr!(cmp == prefix.network()));
            }
            IpNet::V6(prefix) => {
                rule.add_expr(&nft_expr!(payload ipv6 saddr));
                rule.add_expr(&nft_expr!(
                    bitwise mask prefix.netmask(),
                    xor std::net::Ipv6Addr::UNSPECIFIED
                ));
                rule.add_expr(&nft_expr!(cmp == prefix.network()));
            }
        }
        rule.add_expr(&nft_expr!(meta oifname));
        rule.add_expr(&nft_expr!(cmp != tun_name.as_c_str()));
        rule.add_expr(&nft_expr!(masquerade));
        batch.add(&rule, MsgType::Add);
    }
    Ok(batch)
}

#[cfg(target_os = "linux")]
fn install_linux_tun_input_firewall(tun_name: &str, table_name: &str) -> Result<(), PlatformError> {
    send_linux_nft_batch(build_linux_tun_input_firewall(tun_name, table_name)?.finalize())
}

#[cfg(target_os = "linux")]
fn build_linux_tun_input_firewall(
    tun_name: &str,
    table_name: &str,
) -> Result<nftnl::Batch, PlatformError> {
    use nftnl::{
        Batch, Chain, ChainType, Hook, MsgType, Policy, ProtoFamily, Rule, Table, nft_expr,
    };

    let tun_name_c = CString::new(tun_name)
        .map_err(|_| PlatformError::Command("TUN name contains a NUL byte".into()))?;
    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let mut batch = Batch::new();
    let ipv4 = Table::new(table_name.as_c_str(), ProtoFamily::Ipv4);
    let ipv6 = Table::new(table_name.as_c_str(), ProtoFamily::Ipv6);
    batch.add(&ipv4, MsgType::Add);
    batch.add(&ipv6, MsgType::Add);

    let mut ipv4_input = Chain::new(c"input", &ipv4);
    // Run before host-owned INPUT chains, so accepting the TUN packet here
    // cannot be undone by a later base chain. This replaces the former
    // textual `nft insert rule ... INPUT` path without inspecting host rules.
    ipv4_input.set_hook(Hook::In, -200);
    ipv4_input.set_type(ChainType::Filter);
    ipv4_input.set_policy(Policy::Accept);
    let mut ipv6_input = Chain::new(c"input", &ipv6);
    ipv6_input.set_hook(Hook::In, -200);
    ipv6_input.set_type(ChainType::Filter);
    ipv6_input.set_policy(Policy::Accept);
    batch.add(&ipv4_input, MsgType::Add);
    batch.add(&ipv6_input, MsgType::Add);

    for chain in [&ipv4_input, &ipv6_input] {
        let mut rule = Rule::new(chain);
        rule.add_expr(&nft_expr!(meta iifname));
        rule.add_expr(&nft_expr!(cmp == tun_name_c.as_c_str()));
        rule.add_expr(&nft_expr!(verdict accept));
        batch.add(&rule, MsgType::Add);
    }
    Ok(batch)
}

#[cfg(target_os = "linux")]
fn delete_linux_exit_table(
    family: nftnl::ProtoFamily,
    table_name: &str,
) -> Result<(), PlatformError> {
    use nftnl::{Batch, MsgType, Table};

    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let table = Table::new(table_name.as_c_str(), family);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);
    send_linux_nft_batch(batch.finalize())
}

#[cfg(target_os = "linux")]
fn delete_linux_tun_input_table(
    family: nftnl::ProtoFamily,
    table_name: &str,
) -> Result<(), PlatformError> {
    use nftnl::{Batch, MsgType, Table};

    let table_name = CString::new(table_name)
        .map_err(|_| PlatformError::Command("nft table name contains a NUL byte".into()))?;
    let table = Table::new(table_name.as_c_str(), family);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);
    send_linux_nft_batch(batch.finalize())
}

/// Send a finalized libnftnl transaction to NETLINK_NETFILTER and validate
/// every ACK.  No `nft` executable or textual ruleset parser is involved.
#[cfg(target_os = "linux")]
fn send_linux_nft_batch(batch: nftnl::FinalizedBatch) -> Result<(), PlatformError> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).map_err(netlink_error)?;
    let port_id = socket.portid();
    socket.send_all(&batch).map_err(netlink_error)?;
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut sequences = batch.sequence_numbers();
    while !sequences.is_empty() {
        for message in socket.recv(&mut buffer).map_err(netlink_error)? {
            let message = message.map_err(netlink_error)?;
            let sequence = sequences
                .next()
                .ok_or_else(|| PlatformError::Command("unexpected nf_tables ACK".into()))?;
            mnl::cb_run(message, sequence, port_id).map_err(netlink_error)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn netlink_error(error: impl std::fmt::Display) -> PlatformError {
    PlatformError::Command(format!("rtnetlink: {error}"))
}

/// Routes are configured through the kernel's stable rtnetlink ABI rather
/// than by parsing or executing the `ip` utility.  Besides making minimal
/// images work, this preserves IPv4/IPv6 default-route information separately.
#[cfg(target_os = "linux")]
async fn linux_install_overlay_routes(
    tun_name: &str,
    prefixes: &[IpNet],
    underlay: &[IpAddr],
) -> Result<routes::UnderlayRouteOwnership, PlatformError> {
    use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
    use std::net::{Ipv4Addr, Ipv6Addr};

    let (connection, handle, _) = new_connection().map_err(netlink_error)?;
    tokio::spawn(connection);
    let tun_index = handle
        .link()
        .get()
        .match_name(tun_name.to_owned())
        .execute()
        .try_next()
        .await
        .map_err(netlink_error)?
        .ok_or_else(|| PlatformError::Command(format!("TUN interface not found: {tun_name}")))?
        .header
        .index as u32;

    let mut ipv4_default = None;
    let mut ipv6_default = None;
    let mut existing_host_routes = HashSet::new();
    let mut routes = handle
        .route()
        .get(rtnetlink::packet_route::route::RouteMessage::default())
        .execute();
    while let Some(route) = routes.try_next().await.map_err(netlink_error)? {
        if route.header.table != 254 {
            continue;
        }
        let mut gateway = None;
        let mut output_interface = None;
        let mut destination = None;
        for attribute in route.attributes {
            match attribute {
                RouteAttribute::Gateway(RouteAddress::Inet(address)) => {
                    gateway = Some(IpAddr::V4(address))
                }
                RouteAttribute::Gateway(RouteAddress::Inet6(address)) => {
                    gateway = Some(IpAddr::V6(address))
                }
                RouteAttribute::Destination(RouteAddress::Inet(address)) => {
                    destination = Some(IpAddr::V4(address))
                }
                RouteAttribute::Destination(RouteAddress::Inet6(address)) => {
                    destination = Some(IpAddr::V6(address))
                }
                RouteAttribute::Oif(index) => output_interface = Some(index),
                _ => {}
            }
        }
        if matches!(
            (route.header.destination_prefix_length, destination),
            (32, Some(IpAddr::V4(_))) | (128, Some(IpAddr::V6(_)))
        ) {
            existing_host_routes.insert(destination.expect("matched a host destination"));
        }
        if route.header.destination_prefix_length != 0 {
            continue;
        }
        match (gateway, output_interface) {
            (Some(IpAddr::V4(gateway)), Some(output_interface)) => {
                ipv4_default = Some((gateway, output_interface));
            }
            (Some(IpAddr::V6(gateway)), Some(output_interface)) => {
                ipv6_default = Some((gateway, output_interface));
            }
            _ => {}
        }
    }

    let mut planned_underlay = routes::underlay_routes(underlay, ipv4_default, ipv6_default);
    planned_underlay.retain(|route| !existing_host_routes.contains(&route.endpoint));
    planned_underlay.sort_unstable_by_key(|route| route.endpoint);
    planned_underlay.dedup_by_key(|route| route.endpoint);
    let mut installed_underlay = Vec::new();
    for route in planned_underlay {
        match (route.endpoint, route.gateway) {
            (IpAddr::V4(endpoint), IpAddr::V4(gateway)) => {
                if let Err(error) = handle
                    .route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .destination_prefix(endpoint, 32)
                            .gateway(gateway)
                            .output_interface(route.output_interface)
                            .build(),
                    )
                    .execute()
                    .await
                {
                    linux_rollback_installed_routes(&handle, tun_index, &[], &installed_underlay)
                        .await;
                    return Err(netlink_error(error));
                }
            }
            (IpAddr::V6(endpoint), IpAddr::V6(gateway)) => {
                if let Err(error) = handle
                    .route()
                    .add(
                        RouteMessageBuilder::<Ipv6Addr>::new()
                            .destination_prefix(endpoint, 128)
                            .gateway(gateway)
                            .output_interface(route.output_interface)
                            .build(),
                    )
                    .execute()
                    .await
                {
                    linux_rollback_installed_routes(&handle, tun_index, &[], &installed_underlay)
                        .await;
                    return Err(netlink_error(error));
                }
            }
            _ => unreachable!("underlay route preserves address family"),
        }
        installed_underlay.push(route);
    }

    let mut installed_prefixes = Vec::new();
    for prefix in prefixes {
        let result = match prefix.addr() {
            IpAddr::V4(address) => {
                handle
                    .route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .destination_prefix(address, prefix.prefix_len())
                            .output_interface(tun_index)
                            .build(),
                    )
                    .replace()
                    .execute()
                    .await
            }
            IpAddr::V6(address) => {
                handle
                    .route()
                    .add(
                        RouteMessageBuilder::<Ipv6Addr>::new()
                            .destination_prefix(address, prefix.prefix_len())
                            .output_interface(tun_index)
                            .build(),
                    )
                    .replace()
                    .execute()
                    .await
            }
        };
        if let Err(error) = result {
            linux_rollback_installed_routes(
                &handle,
                tun_index,
                &installed_prefixes,
                &installed_underlay,
            )
            .await;
            return Err(netlink_error(error));
        }
        installed_prefixes.push(*prefix);
    }
    Ok(routes::UnderlayRouteOwnership {
        routes: installed_underlay
            .into_iter()
            .map(|route| routes::OwnedUnderlayRoute {
                endpoint: route.endpoint,
                gateway: route.gateway.to_string(),
                output_interface: route.output_interface,
            })
            .collect(),
    })
}

#[cfg(target_os = "linux")]
async fn linux_rollback_installed_routes(
    handle: &rtnetlink::Handle,
    tun_index: u32,
    prefixes: &[IpNet],
    underlay: &[routes::UnderlayRoute],
) {
    use std::net::{Ipv4Addr, Ipv6Addr};
    for prefix in prefixes.iter().rev() {
        let result = match prefix.addr() {
            IpAddr::V4(address) => {
                handle
                    .route()
                    .del(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .destination_prefix(address, prefix.prefix_len())
                            .output_interface(tun_index)
                            .build(),
                    )
                    .execute()
                    .await
            }
            IpAddr::V6(address) => {
                handle
                    .route()
                    .del(
                        RouteMessageBuilder::<Ipv6Addr>::new()
                            .destination_prefix(address, prefix.prefix_len())
                            .output_interface(tun_index)
                            .build(),
                    )
                    .execute()
                    .await
            }
        };
        let _ = result;
    }
    for route in underlay.iter().rev() {
        let result = match (route.endpoint, route.gateway) {
            (IpAddr::V4(endpoint), IpAddr::V4(gateway)) => {
                handle
                    .route()
                    .del(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .destination_prefix(endpoint, 32)
                            .gateway(gateway)
                            .output_interface(route.output_interface)
                            .build(),
                    )
                    .execute()
                    .await
            }
            (IpAddr::V6(endpoint), IpAddr::V6(gateway)) => {
                handle
                    .route()
                    .del(
                        RouteMessageBuilder::<Ipv6Addr>::new()
                            .destination_prefix(endpoint, 128)
                            .gateway(gateway)
                            .output_interface(route.output_interface)
                            .build(),
                    )
                    .execute()
                    .await
            }
            _ => continue,
        };
        let _ = result;
    }
}

#[cfg(target_os = "linux")]
async fn linux_cleanup_underlay_routes(
    underlay: &[routes::OwnedUnderlayRoute],
) -> Result<(), PlatformError> {
    let (connection, handle, _) = new_connection().map_err(netlink_error)?;
    tokio::spawn(connection);
    let underlay = underlay
        .iter()
        .map(|route| {
            Ok(routes::UnderlayRoute {
                endpoint: route.endpoint,
                gateway: route.gateway.parse().map_err(|error| {
                    PlatformError::Command(format!("invalid owned underlay gateway: {error}"))
                })?,
                output_interface: route.output_interface,
            })
        })
        .collect::<Result<Vec<_>, PlatformError>>()?;
    linux_rollback_installed_routes(&handle, 0, &[], &underlay).await;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn linux_cleanup_overlay_routes(
    tun_name: &str,
    prefixes: &[IpNet],
) -> Result<(), PlatformError> {
    let (connection, handle, _) = new_connection().map_err(netlink_error)?;
    tokio::spawn(connection);
    let Some(link) = handle
        .link()
        .get()
        .match_name(tun_name.to_owned())
        .execute()
        .try_next()
        .await
        .map_err(netlink_error)?
    else {
        return Ok(());
    };
    let tun_index = link.header.index;
    for prefix in prefixes {
        let result = match prefix.addr() {
            IpAddr::V4(address) => {
                handle
                    .route()
                    .del(
                        RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                            .destination_prefix(address, prefix.prefix_len())
                            .output_interface(tun_index)
                            .build(),
                    )
                    .execute()
                    .await
            }
            IpAddr::V6(address) => {
                handle
                    .route()
                    .del(
                        RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                            .destination_prefix(address, prefix.prefix_len())
                            .output_interface(tun_index)
                            .build(),
                    )
                    .execute()
                    .await
            }
        };
        // Routes may already be absent after a partial setup failure.
        let _ = result;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn run_checked(command: &str, args: &[&str]) -> Result<(), PlatformError> {
    let status = Command::new(command)
        .args(args)
        .status()
        .map_err(|e| PlatformError::Command(e.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(PlatformError::Command(format!(
            "{command} {}",
            args.join(" ")
        )))
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod generic_tests {
    use super::*;

    #[test]
    fn empty_network_plan_command_returns_an_error() {
        let error = run_plan(&[Vec::new()]).unwrap_err();
        assert!(error.to_string().contains("empty command"));
    }

    #[test]
    fn create_tun_requires_root_privileges() {
        if unsafe { libc_geteuid() } == 0 {
            return;
        }
        let result = create_tun(&TunConfig {
            enabled: true,
            name: "tinectcov0".into(),
            addresses: vec!["100.64.0.1/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        });
        assert!(matches!(result, Err(PlatformError::Permission)));
    }

    #[test]
    fn create_tun_requires_an_address() {
        if unsafe { libc_geteuid() } != 0 {
            return;
        }
        let result = create_tun(&TunConfig {
            enabled: true,
            name: "tinectcov0".into(),
            addresses: Vec::new(),
            mtu: 1280,
            clamp_mss: true,
        });
        let Err(error) = result else {
            panic!("create_tun without addresses must fail");
        };
        assert!(error.to_string().contains("requires an address"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn quicp_rst_guard_is_unsupported_off_linux() {
        let error = install_quicp_rst_guard(45678, Some(7)).unwrap_err();
        assert!(error.to_string().contains("requires Linux"));
        cleanup_quicp_rst_guard(45678).unwrap();
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    fn tun() -> TunConfig {
        TunConfig {
            enabled: true,
            name: "utun9".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        }
    }

    #[test]
    fn tun_input_and_direct_firewall_states_are_noops() {
        let direct = DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: Some(0x100),
            conntrack_zone: 32123,
            routes: Vec::new(),
        };
        let input = apply_tun_input_firewall(&tun()).unwrap();
        cleanup_tun_input_firewall(&input).unwrap();
        let firewall = apply_direct_firewall(&tun(), Some(&direct)).unwrap();
        cleanup_direct_firewall(&firewall).unwrap();
        let no_firewall = apply_direct_firewall(&tun(), None).unwrap();
        cleanup_direct_firewall(&no_firewall).unwrap();
        let nat = apply_direct_nat(&tun(), Some(&direct), true).unwrap();
        cleanup_direct_nat(&nat).unwrap();
        let no_nat = apply_direct_nat(&tun(), None, false).unwrap();
        cleanup_direct_nat(&no_nat).unwrap();
    }

    #[tokio::test]
    async fn tun_address_alias_and_mtu_fail_for_missing_interface() {
        let v4_alias: [IpNet; 2] = [
            "100.64.0.1/32".parse().unwrap(),
            "192.0.2.1/32".parse().unwrap(),
        ];
        assert!(
            configure_tun_addresses("utuncov0", &v4_alias)
                .await
                .is_err()
        );
        let v6_alias: [IpNet; 2] = [
            "100.64.0.1/32".parse().unwrap(),
            "2001:db8::1/128".parse().unwrap(),
        ];
        assert!(
            configure_tun_addresses("utuncov0", &v6_alias)
                .await
                .is_err()
        );
        assert!(set_tun_mtu("utuncov0", 1280).await.is_err());
    }

    #[test]
    fn exit_network_install_failure_is_rolled_back_without_privileges() {
        if unsafe { libc_geteuid() } == 0 {
            // As root the pf anchor install would succeed and mutate host
            // firewall state; only the unprivileged failure path is tested.
            return;
        }
        assert!(apply_exit_network(&tun(), false).is_err());
        assert!(apply_exit_network(&tun(), true).is_err());
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn unmanaged_routes_are_omitted_from_the_network_plan() {
        let tun = TunConfig {
            enabled: true,
            name: "tinect0".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let plan = network_plan(&tun, false, false, None, None, false).unwrap();
        assert!(
            plan.iter()
                .all(|command| !command.iter().any(|argument| argument == "overlay-routes"))
        );
    }

    #[test]
    fn direct_fwmark_is_a_libnftnl_plan_step() {
        let tun = TunConfig {
            enabled: true,
            name: "tinect0".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let plan =
            network_plan(&tun, false, false, Some((Some(0x100), 32123)), None, false).unwrap();
        assert!(plan.iter().any(|command| {
            command
                == &vec![
                    String::from("libnftnl/libmnl"),
                    String::from("install"),
                    String::from("direct-fallback-prerouting-mark"),
                ]
        }));
        assert!(plan.iter().any(|command| {
            command
                == &vec![
                    String::from("libnftnl/libmnl"),
                    String::from("install"),
                    String::from("direct-fallback-conntrack-zone"),
                ]
        }));
        assert!(plan.iter().any(|command| {
            command
                == &vec![
                    String::from("ctnetlink"),
                    String::from("flush"),
                    String::from("direct-fallback-zone=32123"),
                ]
        }));
        assert!(
            plan.iter()
                .all(|command| { !command.first().is_some_and(|binary| binary == "nft") })
        );

        let zero_mark_plan =
            network_plan(&tun, false, false, Some((Some(0), 32123)), None, false).unwrap();
        assert!(zero_mark_plan.iter().any(|command| {
            command
                .iter()
                .any(|argument| argument == "direct-fallback-prerouting-mark")
        }));
    }

    #[test]
    fn direct_without_fwmark_has_no_firewall_plan_step() {
        let tun = TunConfig {
            enabled: true,
            name: "tinect0".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let plan = network_plan(&tun, false, false, None, None, false).unwrap();
        assert!(plan.iter().all(|command| {
            !command
                .iter()
                .any(|argument| argument == "direct-fallback-prerouting-mark")
        }));
    }

    #[test]
    fn direct_masquerade_is_a_libnftnl_plan_step() {
        let tun = TunConfig {
            enabled: true,
            name: "tinect0".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let plan =
            network_plan(&tun, true, false, Some((Some(0x100), 32123)), None, false).unwrap();
        assert!(plan.iter().any(|command| {
            command
                == &vec![
                    String::from("libnftnl/libmnl"),
                    String::from("install"),
                    String::from("direct-fallback-masquerade"),
                ]
        }));

        let disabled =
            network_plan(&tun, false, false, Some((Some(0x100), 32123)), None, false).unwrap();
        assert!(disabled.iter().all(|command| {
            !command
                .iter()
                .any(|argument| argument == "direct-fallback-masquerade")
        }));
    }

    #[test]
    fn direct_without_fwmark_has_no_owned_firewall() {
        let state = apply_direct_firewall(
            &TunConfig {
                enabled: true,
                name: "tinect0".into(),
                addresses: vec!["100.64.0.10/32".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            Some(&DirectConfig {
                fallback: true,
                dscp: 46,
                fwmark: None,
                conntrack_zone: 32123,
                routes: Vec::new(),
            }),
        )
        .unwrap();
        assert!(state.table_name.is_none());
        cleanup_direct_firewall(&state).unwrap();
    }

    #[test]
    fn network_plan_lists_post_up_without_executing_it() {
        let tun = TunConfig {
            enabled: true,
            name: "tinect0".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let hooks = vec!["touch should-not-run".into(), "echo second".into()];
        let plan = network_plan(&tun, false, false, None, Some(&hooks), false).unwrap();
        assert_eq!(
            plan.last(),
            Some(&vec!["/bin/sh".into(), "-ec".into(), "echo second".into()])
        );
    }

    #[test]
    fn fake_tcp_socket_mark_is_configurable() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _guard = runtime.enter();
        let (socket, _) =
            quicp::RawTcpSocket::open("127.0.0.1:0".parse().unwrap(), Some(18)).unwrap();
        assert_eq!(socket.socket_mark().unwrap(), 18);
    }

    #[test]
    fn raw_tcp_socket_covers_families_source_selection_and_polling() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _guard = runtime.enter();
        let (socket, local) =
            quicp::RawTcpSocket::open("0.0.0.0:0".parse().unwrap(), None).unwrap();
        assert_ne!(local.port(), 0);
        assert!(
            socket
                .source_addr_for("127.0.0.1:443".parse().unwrap(), local.port())
                .is_ok()
        );
        assert!(
            socket
                .source_addr_for("[::1]:443".parse().unwrap(), local.port())
                .is_err()
        );
        assert!(socket.try_send(&[], "[::1]:443".parse().unwrap()).is_err());
        let _ = socket.try_recv().unwrap();
        runtime.block_on(async {
            std::future::poll_fn(|cx| socket.poll_writable(cx))
                .await
                .unwrap();
        });

        let (socket6, local6) =
            quicp::RawTcpSocket::open("[::1]:0".parse().unwrap(), None).unwrap();
        assert!(local6.is_ipv6());
        assert!(
            socket6
                .source_addr_for("[::1]:443".parse().unwrap(), local6.port())
                .is_ok()
        );
        assert!(
            socket6
                .source_addr_for("127.0.0.1:443".parse().unwrap(), local6.port())
                .is_err()
        );
        assert!(
            socket6
                .try_send(&[], "127.0.0.1:443".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn quicp_rst_guard_install_cleanup_and_error_paths() {
        if unsafe { libc::geteuid() } == 0 {
            if std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none() {
                return;
            }
            let _network_namespace = crate::test_support::NetworkNamespace::enter();
            install_quicp_rst_guard(45678, Some(7)).unwrap();
            cleanup_quicp_rst_guard(45678).unwrap();
            install_quicp_rst_guard(45679, None).unwrap();
            cleanup_quicp_rst_guard(45679).unwrap();
            return;
        }
        // Without CAP_NET_ADMIN the kernel rejects the batch, and the guard
        // install must roll back through the cleanup path before failing.
        assert!(install_quicp_rst_guard(45678, Some(7)).is_err());
        assert!(cleanup_quicp_rst_guard(45678).is_err());
    }

    #[test]
    fn quicp_raw_socket_open_requires_netlink_privileges() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // Port zero reserves an ephemeral UDP port first; the rst-guard
        // install then fails and the error is propagated as `io::Error`.
        let error = quicp::RawTcpSocket::open("127.0.0.1:0".parse().unwrap(), None);
        assert!(error.is_err());
    }

    #[test]
    fn healthy_set_manager_open_propagates_netlink_errors_without_privileges() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let targets = NftHealthySetTargets {
            v4: Some(NftHealthySetTarget {
                table: "tinect_cov_open".into(),
                name: "v4".into(),
            }),
            ..NftHealthySetTargets::default()
        };
        let result = HealthyRouteSetManager::open(targets);
        assert!(matches!(result, Err(PlatformError::Command(_))));
    }

    #[test]
    fn healthy_set_manager_drop_tolerates_netlink_failures() {
        // The named table does not exist, so every teardown batch fails; Drop
        // must log and continue instead of panicking. This is safe as root:
        // deleting absent sets and tables changes no host state.
        let manager = HealthyRouteSetManager {
            targets: NftHealthySetTargets {
                v4: Some(NftHealthySetTarget {
                    table: "tinect_cov_drop".into(),
                    name: "v4".into(),
                }),
                v6: Some(NftHealthySetTarget {
                    table: "tinect_cov_drop".into(),
                    name: "v6".into(),
                }),
                destroy_set: true,
                destroy_table: true,
            },
            committed_v4: HashSet::new(),
            committed_v6: HashSet::new(),
        };
        drop(manager);
    }

    #[test]
    fn healthy_set_manager_rejects_existing_sets_with_incompatible_types() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let target = NftHealthySetTarget {
            table: "tinect_cov_mixed".into(),
            name: "mixed".into(),
        };
        let v4_owner = HealthyRouteSetManager::open(NftHealthySetTargets {
            v4: Some(target.clone()),
            ..NftHealthySetTargets::default()
        })
        .unwrap()
        .unwrap();
        // The same set viewed as an IPv6 target has the wrong key type.
        let error = HealthyRouteSetManager::open(NftHealthySetTargets {
            v6: Some(target.clone()),
            ..NftHealthySetTargets::default()
        })
        .err()
        .unwrap();
        assert!(error.to_string().contains("incompatible"));
        let cleanup = HealthyRouteSetManager::open(NftHealthySetTargets {
            v4: Some(target),
            destroy_set: true,
            destroy_table: true,
            ..NftHealthySetTargets::default()
        })
        .unwrap()
        .unwrap();
        drop(cleanup);
        drop(v4_owner);
    }

    #[test]
    fn direct_firewall_and_nat_without_config_own_no_tables() {
        let tun = TunConfig {
            enabled: true,
            name: "tinectcov0".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let firewall = apply_direct_firewall(&tun, None).unwrap();
        assert!(firewall.table_name.is_none());
        cleanup_direct_firewall(&firewall).unwrap();
        let nat = apply_direct_nat(&tun, None, true).unwrap();
        assert!(nat.table_name.is_none());
        cleanup_direct_nat(&nat).unwrap();
    }

    #[test]
    fn healthy_set_manager_reconciles_and_destroys_kernel_sets() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let targets = NftHealthySetTargets {
            v4: Some(NftHealthySetTarget {
                table: "tinect_cov_healthy".into(),
                name: "v4".into(),
            }),
            v6: Some(NftHealthySetTarget {
                table: "tinect_cov_healthy".into(),
                name: "v6".into(),
            }),
            destroy_set: true,
            destroy_table: true,
        };
        let mut manager = HealthyRouteSetManager::open(targets).unwrap().unwrap();
        let initial = HashSet::from([
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);
        manager.reconcile(&initial).unwrap();
        manager.reconcile(&initial).unwrap();
        let changed = HashSet::from(["192.0.2.1/32".parse().unwrap()]);
        manager.reconcile(&changed).unwrap();
    }

    #[test]
    fn healthy_set_manager_reopens_and_reads_existing_kernel_sets() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let targets = NftHealthySetTargets {
            v4: Some(NftHealthySetTarget {
                table: "tinect_cov_reopen".into(),
                name: "v4".into(),
            }),
            v6: Some(NftHealthySetTarget {
                table: "tinect_cov_reopen".into(),
                name: "v6".into(),
            }),
            destroy_set: false,
            destroy_table: false,
        };
        {
            let mut manager = HealthyRouteSetManager::open(targets.clone())
                .unwrap()
                .unwrap();
            manager
                .reconcile(&HashSet::from(["192.0.2.0/24".parse().unwrap()]))
                .unwrap();
        }
        // Reopening sees the set created by the first manager instead of
        // rebuilding it: this exercises the element-query path.
        {
            let mut reopened = HealthyRouteSetManager::open(targets.clone())
                .unwrap()
                .unwrap();
            reopened
                .reconcile(&HashSet::from([
                    "192.0.2.0/24".parse().unwrap(),
                    "2001:db8::/32".parse().unwrap(),
                ]))
                .unwrap();
            reopened.reconcile(&HashSet::new()).unwrap();
        }
        // Destroy the owned sets and tables so the namespace leaves no state.
        let cleanup = HealthyRouteSetManager::open(NftHealthySetTargets {
            destroy_set: true,
            destroy_table: true,
            ..targets
        })
        .unwrap()
        .unwrap();
        drop(cleanup);
    }

    #[test]
    fn apply_exit_network_installs_and_cleans_owned_tables() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let tun = TunConfig {
            enabled: true,
            name: "tinectcovexit".into(),
            addresses: vec![
                "100.64.0.10/32".parse().unwrap(),
                "fd74::10/128".parse().unwrap(),
            ],
            mtu: 1280,
            clamp_mss: true,
        };
        let state = apply_exit_network(&tun, false).unwrap();
        cleanup_exit_network(&state).unwrap();

        // The forwarded-exit preflight reads per-namespace sysctls; enable them
        // only inside the isolated namespace so the host is untouched.
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").unwrap();
        let forwarding_state = apply_exit_network(&tun, true).unwrap();
        cleanup_exit_network(&forwarding_state).unwrap();
    }

    /// Opt-in because it needs CAP_NET_ADMIN. Run inside an isolated network
    /// namespace; the transaction itself must receive kernel ACKs for every
    /// table, chain and rule before this test can succeed.
    #[test]
    fn nftnl_exit_firewall_transaction_is_accepted_by_kernel() {
        if unsafe { libc_geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        install_linux_exit_firewall(
            &TunConfig {
                enabled: true,
                name: "lo".into(),
                addresses: vec!["127.0.0.1/8".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            true,
            &linux_exit_table_name("lo"),
        )
        .unwrap();
        cleanup_exit_network(&ExitNetworkState {
            table_name: linux_exit_table_name("lo"),
        })
        .unwrap();
        let state = apply_tun_input_firewall(&TunConfig {
            enabled: true,
            name: "lo".into(),
            addresses: vec!["127.0.0.1/8".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();
        cleanup_tun_input_firewall(&state).unwrap();

        let direct_config = DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: Some(0x100),
            conntrack_zone: 32123,
            routes: Vec::new(),
        };
        let direct_state = apply_direct_firewall(
            &TunConfig {
                enabled: true,
                name: "lo".into(),
                addresses: vec!["127.0.0.1/8".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            Some(&direct_config),
        )
        .unwrap();
        assert!(direct_state.table_name.is_some());
        // nf_tables accepts duplicate table/chain/rule adds (NLM_F_EXCL only
        // rejects existing rule handles), so re-applying the same owned
        // configuration is idempotent rather than an error; ownership cleanup
        // still removes the whole table afterwards.
        let second_state = apply_direct_firewall(
            &TunConfig {
                enabled: true,
                name: "lo".into(),
                addresses: vec!["127.0.0.1/8".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            Some(&direct_config),
        )
        .unwrap();
        assert!(second_state.table_name.is_some());
        assert_eq!(direct_state.table_name, second_state.table_name);
        cleanup_direct_firewall(&direct_state).unwrap();

        let zero_config = DirectConfig {
            fallback: true,
            dscp: 0,
            fwmark: Some(0),
            conntrack_zone: 32123,
            routes: Vec::new(),
        };
        let zero_state = apply_direct_firewall(
            &TunConfig {
                enabled: true,
                name: "lo".into(),
                addresses: vec!["127.0.0.1/8".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            Some(&zero_config),
        )
        .unwrap();
        cleanup_direct_firewall(&zero_state).unwrap();

        let nat_config = DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: Some(0x100),
            conntrack_zone: 32123,
            routes: Vec::new(),
        };
        let nat_state = apply_direct_nat(
            &TunConfig {
                enabled: true,
                name: "lo".into(),
                addresses: vec!["127.0.0.1/8".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            Some(&nat_config),
            true,
        )
        .unwrap();
        assert!(nat_state.table_name.is_some());
        cleanup_direct_nat(&nat_state).unwrap();

        // Without managed_routes the daemon still owns the directional-zone
        // table, but it leaves masquerade to the operator.
        let unmanaged = apply_direct_nat(
            &TunConfig {
                enabled: true,
                name: "lo".into(),
                addresses: vec!["127.0.0.1/8".parse().unwrap()],
                mtu: 1280,
                clamp_mss: true,
            },
            Some(&nat_config),
            false,
        )
        .unwrap();
        assert!(unmanaged.table_name.is_some());
        cleanup_direct_nat(&unmanaged).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let ownership = install_overlay_routes(
                "lo",
                &[
                    "192.0.2.0/24".parse().unwrap(),
                    "2001:db8::/32".parse().unwrap(),
                ],
                &[],
            )
            .await
            .unwrap();
            assert!(ownership.routes.is_empty());
            cleanup_underlay_routes(&ownership).await.unwrap();
            cleanup_overlay_routes(
                "lo",
                &[
                    "192.0.2.0/24".parse().unwrap(),
                    "2001:db8::/32".parse().unwrap(),
                ],
            )
            .await
            .unwrap();
        });
    }

    #[test]
    fn disabled_tun_has_no_network_plan() {
        let tun = TunConfig {
            enabled: false,
            name: String::new(),
            addresses: Vec::new(),
            mtu: 1280,
            clamp_mss: true,
        };
        assert!(
            network_plan(
                &tun,
                true,
                false,
                None,
                Some(&["touch should-not-run".into()]),
                true,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn nft_table_names_are_isolated_per_tun() {
        assert_eq!(
            linux_tun_input_table_name("tinect0"),
            "tinect_input_74696e65637430"
        );
        assert_eq!(
            linux_exit_table_name("tinect0"),
            "tinect_exit_74696e65637430"
        );
        assert_ne!(
            linux_tun_input_table_name("tinect0"),
            linux_tun_input_table_name("tinect1")
        );
        assert_eq!(linux_exit_table_name(""), "tinect_exit_tun");
        assert_eq!(
            linux_direct_table_name("tinect0"),
            "tinect_direct_74696e65637430"
        );
        assert_eq!(
            linux_direct_nat_table_name("tinect0"),
            "tinect_direct_nat_74696e65637430"
        );
        assert_ne!(
            linux_direct_table_name("tinect0"),
            linux_direct_table_name("tinect1")
        );
        assert_ne!(
            linux_direct_nat_table_name("tinect0"),
            linux_direct_nat_table_name("tinect1")
        );
    }

    #[test]
    fn interval_bounds_use_exclusive_endpoints_and_wrap_at_the_limit() {
        let v4: IpNet = "192.168.191.1/32".parse().unwrap();
        let (v4_start, v4_end) = interval_bounds(&v4).unwrap();
        assert_eq!(v4_start, [192, 168, 191, 1]);
        assert_eq!(v4_end, [192, 168, 191, 2]);

        let v4_max: IpNet = "255.255.255.255/32".parse().unwrap();
        let (v4_max_start, v4_max_end) = interval_bounds(&v4_max).unwrap();
        assert_eq!(v4_max_start, [255, 255, 255, 255]);
        assert_eq!(v4_max_end, [0, 0, 0, 0]);

        let v4_all: IpNet = "0.0.0.0/0".parse().unwrap();
        let (v4_all_start, v4_all_end) = interval_bounds(&v4_all).unwrap();
        assert_eq!(v4_all_start, [0, 0, 0, 0]);
        assert_eq!(v4_all_end, [0, 0, 0, 0]);

        let v6: IpNet = "2001:db8::1/128".parse().unwrap();
        let (v6_start, v6_end) = interval_bounds(&v6).unwrap();
        assert_eq!(
            v6_start,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]
        );
        assert_eq!(
            v6_end,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,]
        );

        let v6_all: IpNet = "::/0".parse().unwrap();
        let (v6_all_start, v6_all_end) = interval_bounds(&v6_all).unwrap();
        assert_eq!(v6_all_start, [0; 16]);
        assert_eq!(v6_all_end, [0; 16]);

        let v6_max: IpNet = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
            .parse()
            .unwrap();
        let (v6_max_start, v6_max_end) = interval_bounds(&v6_max).unwrap();
        assert_eq!(v6_max_start, [0xff; 16]);
        assert_eq!(v6_max_end, [0; 16]);
    }

    #[test]
    fn interval_to_prefix_decodes_exclusive_endpoints() {
        assert_eq!(
            interval_to_prefix(
                nftnl::ProtoFamily::Ipv4,
                &[192, 168, 191, 1],
                &[192, 168, 191, 2],
            ),
            Some("192.168.191.1/32".parse().unwrap())
        );
        assert_eq!(
            interval_to_prefix(
                nftnl::ProtoFamily::Ipv4,
                &[255, 255, 255, 255],
                &[0, 0, 0, 0],
            ),
            Some("255.255.255.255/32".parse().unwrap())
        );
        assert_eq!(
            interval_to_prefix(nftnl::ProtoFamily::Ipv4, &[0, 0, 0, 0], &[0, 0, 0, 0],),
            Some("0.0.0.0/0".parse().unwrap())
        );
        assert_eq!(
            interval_to_prefix(nftnl::ProtoFamily::Ipv6, &[0; 16], &[0; 16]),
            Some("::/0".parse().unwrap())
        );
        assert_eq!(
            interval_to_prefix(
                nftnl::ProtoFamily::Ipv6,
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
            None
        );
        assert_eq!(
            interval_to_prefix(
                nftnl::ProtoFamily::Ipv4,
                &[192, 168, 191, 1],
                &[192, 168, 191, 3],
            ),
            None
        );
        assert_eq!(
            interval_to_prefix(nftnl::ProtoFamily::Ipv4, &[0; 3], &[0; 3]),
            None
        );
    }

    #[test]
    fn canonicalize_prefixes_removes_nested_members() {
        let prefixes = [
            "0.0.0.0/0",
            "192.168.191.1/32",
            "192.168.191.20/32",
            "2001:db8::/32",
            "2001:db8::1/128",
        ]
        .into_iter()
        .map(|prefix| prefix.parse().unwrap())
        .collect::<HashSet<IpNet>>();

        assert_eq!(
            canonicalize_prefixes(&prefixes),
            ["0.0.0.0/0", "2001:db8::/32"]
                .into_iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect::<HashSet<IpNet>>()
        );
    }

    #[test]
    fn canonicalize_prefixes_keeps_sibling_members() {
        let prefixes = ["192.0.2.0/25", "192.0.2.128/25"]
            .into_iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect::<HashSet<IpNet>>();

        assert_eq!(canonicalize_prefixes(&prefixes), prefixes);
    }

    #[test]
    fn prefix_set_delta_handles_nested_prefix_lifecycle() {
        let set = |prefixes: &[&str]| {
            prefixes
                .iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect::<HashSet<IpNet>>()
        };
        let empty = set(&[]);
        let default_and_specific = set(&["0.0.0.0/0", "192.168.191.1/32"]);
        let specific_only = set(&["192.168.191.1/32"]);

        let first = prefix_set_delta(&empty, &default_and_specific);
        assert_eq!(first.desired, set(&["0.0.0.0/0"]));
        assert_eq!(
            first.add.into_iter().collect::<HashSet<_>>(),
            set(&["0.0.0.0/0"])
        );
        assert!(first.remove.is_empty());

        let unchanged = prefix_set_delta(&first.desired, &set(&["0.0.0.0/0"]));
        assert!(unchanged.add.is_empty());
        assert!(unchanged.remove.is_empty());

        let specific = prefix_set_delta(&first.desired, &specific_only);
        assert_eq!(specific.desired, specific_only);
        assert_eq!(
            specific.add.into_iter().collect::<HashSet<_>>(),
            specific_only
        );
        assert_eq!(
            specific.remove.into_iter().collect::<HashSet<_>>(),
            set(&["0.0.0.0/0"])
        );

        let cleared = prefix_set_delta(&specific.desired, &empty);
        assert!(cleared.desired.is_empty());
        assert!(cleared.add.is_empty());
        assert_eq!(
            cleared.remove.into_iter().collect::<HashSet<_>>(),
            specific_only
        );
    }

    #[test]
    fn nft_read_only_queries_report_absent_objects_or_privilege_errors() {
        // These netlink queries never mutate kernel state, so they are safe
        // at any privilege level: without CAP_NET_ADMIN the kernel answers
        // EPERM, and with privileges the absent objects report as missing.
        let target = NftHealthySetTarget {
            table: "tinect_cov_query".into(),
            name: "v4".into(),
        };
        match query_healthy_set(&target) {
            Ok(metadata) => assert!(metadata.is_none()),
            Err(error) => assert!(matches!(error, PlatformError::Command(_))),
        }
        match query_healthy_set_elements(&target, nftnl::ProtoFamily::Ipv4) {
            Ok(prefixes) => assert!(prefixes.is_empty()),
            Err(error) => assert!(matches!(error, PlatformError::Command(_))),
        }
    }

    #[test]
    fn ensure_nft_table_fails_without_netlink_privileges() {
        if unsafe { libc::geteuid() } == 0 {
            // With privileges the missing table would be created on the host;
            // only the unprivileged failure path is exercised here.
            return;
        }
        let target = NftHealthySetTarget {
            table: "tinect_cov_ensure".into(),
            name: "v4".into(),
        };
        let error = ensure_nft_table(&target).unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
    }

    #[test]
    fn direct_firewall_and_nat_install_fail_without_netlink_privileges() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tun = TunConfig {
            enabled: true,
            name: "tinectcov0".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let direct = DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: Some(0x100),
            conntrack_zone: 32123,
            routes: Vec::new(),
        };
        // An environment with CAP_NET_ADMIN but a non-root euid would still
        // install the owned tables; remove them again immediately in that
        // case instead of failing the test.
        match apply_direct_firewall(&tun, Some(&direct)) {
            Ok(state) => cleanup_direct_firewall(&state).unwrap(),
            Err(error) => assert!(matches!(error, PlatformError::Command(_))),
        }
        match apply_direct_nat(&tun, Some(&direct), true) {
            Ok(state) => cleanup_direct_nat(&state).unwrap(),
            Err(error) => assert!(matches!(error, PlatformError::Command(_))),
        }
    }

    /// Dumps main-table routes the way `linux_install_overlay_routes` sees
    /// them: (destination prefix length, destination, gateway, interface).
    async fn main_table_routes(
        handle: &rtnetlink::Handle,
    ) -> Vec<(u8, Option<IpAddr>, Option<IpAddr>, Option<u32>)> {
        use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};

        let mut result = Vec::new();
        let mut routes = handle
            .route()
            .get(rtnetlink::packet_route::route::RouteMessage::default())
            .execute();
        while let Some(route) = routes.try_next().await.unwrap() {
            if route.header.table != 254 {
                continue;
            }
            let mut gateway = None;
            let mut destination = None;
            let mut output_interface = None;
            for attribute in route.attributes {
                match attribute {
                    RouteAttribute::Gateway(RouteAddress::Inet(address)) => {
                        gateway = Some(IpAddr::V4(address))
                    }
                    RouteAttribute::Gateway(RouteAddress::Inet6(address)) => {
                        gateway = Some(IpAddr::V6(address))
                    }
                    RouteAttribute::Destination(RouteAddress::Inet(address)) => {
                        destination = Some(IpAddr::V4(address))
                    }
                    RouteAttribute::Destination(RouteAddress::Inet6(address)) => {
                        destination = Some(IpAddr::V6(address))
                    }
                    RouteAttribute::Oif(index) => output_interface = Some(index),
                    _ => {}
                }
            }
            result.push((
                route.header.destination_prefix_length,
                destination,
                gateway,
                output_interface,
            ));
        }
        result
    }

    async fn test_link_index(handle: &rtnetlink::Handle, name: &str) -> u32 {
        handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute()
            .try_next()
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("link {name} must exist in the test namespace"))
            .header
            .index
    }

    async fn add_default_route(handle: &rtnetlink::Handle, gateway: IpAddr, index: u32) {
        match gateway {
            IpAddr::V4(gateway) => handle
                .route()
                .add(
                    RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                        .gateway(gateway)
                        .output_interface(index)
                        .build(),
                )
                .execute()
                .await
                .unwrap(),
            IpAddr::V6(gateway) => handle
                .route()
                .add(
                    RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                        .gateway(gateway)
                        .output_interface(index)
                        .build(),
                )
                .execute()
                .await
                .unwrap(),
        }
    }

    fn delete_nft_table(name: &str) {
        let name = CString::new(name).unwrap();
        let table = nftnl::Table::new(name.as_c_str(), nftnl::ProtoFamily::Inet);
        let mut batch = nftnl::Batch::new();
        batch.add(&table, nftnl::MsgType::Del);
        send_linux_nft_batch(batch.finalize()).unwrap();
    }

    #[tokio::test]
    async fn overlay_routes_pin_underlay_gateways_and_release_owned_routes() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let device = create_tun(&TunConfig {
            enabled: true,
            name: "tincovrt1".into(),
            addresses: vec!["10.99.0.1/24".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();
        configure_tun_addresses(
            "tincovrt1",
            &[
                "10.99.0.1/24".parse().unwrap(),
                "fd99::1/64".parse().unwrap(),
            ],
        )
        .await
        .unwrap();

        let (connection, handle, _) = new_connection().unwrap();
        let task = tokio::spawn(connection);
        let index = test_link_index(&handle, "tincovrt1").await;
        add_default_route(&handle, "10.99.0.2".parse().unwrap(), index).await;
        add_default_route(&handle, "fd99::2".parse().unwrap(), index).await;
        // An administrator-owned host route must be detected and left alone.
        handle
            .route()
            .add(
                RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                    .destination_prefix("198.51.100.7".parse().unwrap(), 32)
                    .gateway("10.99.0.2".parse().unwrap())
                    .output_interface(index)
                    .build(),
            )
            .execute()
            .await
            .unwrap();

        let prefixes: Vec<IpNet> = vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let underlay: Vec<IpAddr> = vec![
            "203.0.113.10".parse().unwrap(),
            "2001:db8::99".parse().unwrap(),
            "198.51.100.7".parse().unwrap(),
        ];
        let ownership = install_overlay_routes("tincovrt1", &prefixes, &underlay)
            .await
            .unwrap();
        let owned = ownership
            .routes
            .iter()
            .map(|route| route.endpoint)
            .collect::<HashSet<_>>();
        assert_eq!(
            owned,
            HashSet::from([
                "203.0.113.10".parse().unwrap(),
                "2001:db8::99".parse().unwrap(),
            ])
        );
        let routes = main_table_routes(&handle).await;
        assert!(routes.contains(&(
            32,
            Some("203.0.113.10".parse().unwrap()),
            Some("10.99.0.2".parse().unwrap()),
            Some(index)
        )));
        assert!(routes.contains(&(
            128,
            Some("2001:db8::99".parse().unwrap()),
            Some("fd99::2".parse().unwrap()),
            Some(index)
        )));
        assert!(routes.contains(&(24, Some("192.0.2.0".parse().unwrap()), None, Some(index))));
        assert!(routes.contains(&(32, Some("2001:db8::".parse().unwrap()), None, Some(index))));

        // A second install sees the pinned host routes and owns nothing new.
        let second = install_overlay_routes("tincovrt1", &prefixes, &underlay)
            .await
            .unwrap();
        assert!(second.routes.is_empty());

        // Rollback deletes the overlay prefixes; an entry whose endpoint and
        // gateway families disagree is skipped defensively.
        let mixed = routes::UnderlayRoute {
            endpoint: "192.0.2.222".parse().unwrap(),
            gateway: "2001:db8::1".parse().unwrap(),
            output_interface: index,
        };
        linux_rollback_installed_routes(&handle, index, &prefixes, &[mixed]).await;
        let routes = main_table_routes(&handle).await;
        assert!(!routes.contains(&(24, Some("192.0.2.0".parse().unwrap()), None, Some(index))));
        assert!(!routes.contains(&(32, Some("2001:db8::".parse().unwrap()), None, Some(index))));

        cleanup_underlay_routes(&ownership).await.unwrap();
        let routes = main_table_routes(&handle).await;
        assert!(!routes.contains(&(
            32,
            Some("203.0.113.10".parse().unwrap()),
            Some("10.99.0.2".parse().unwrap()),
            Some(index)
        )));
        assert!(!routes.contains(&(
            128,
            Some("2001:db8::99".parse().unwrap()),
            Some("fd99::2".parse().unwrap()),
            Some(index)
        )));
        // The pre-existing administrator route survives cleanup.
        assert!(routes.contains(&(
            32,
            Some("198.51.100.7".parse().unwrap()),
            Some("10.99.0.2".parse().unwrap()),
            Some(index)
        )));

        // Overlay cleanup tolerates absent routes. A completely absent
        // interface is answered by the kernel with ENODEV before an empty
        // link listing could be observed.
        cleanup_overlay_routes("tincovrt1", &prefixes)
            .await
            .unwrap();
        let error = cleanup_overlay_routes("tincovnone", &prefixes)
            .await
            .unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
        drop(device);
        task.abort();
    }

    #[tokio::test]
    async fn overlay_route_install_rolls_back_underlay_when_v6_gateway_is_unreachable() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let device = create_tun(&TunConfig {
            enabled: true,
            name: "tincovrb1".into(),
            addresses: vec!["10.97.0.1/24".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();
        configure_tun_addresses(
            "tincovrb1",
            &[
                "10.97.0.1/24".parse().unwrap(),
                "fd97::1/64".parse().unwrap(),
            ],
        )
        .await
        .unwrap();

        let (connection, handle, _) = new_connection().unwrap();
        let task = tokio::spawn(connection);
        let index = test_link_index(&handle, "tincovrb1").await;
        add_default_route(&handle, "10.97.0.2".parse().unwrap(), index).await;
        add_default_route(&handle, "fd97::2".parse().unwrap(), index).await;
        // Removing the only address covering the IPv6 gateway keeps the
        // default route in the table but makes new routes through it
        // unreachable.
        handle
            .address()
            .del(
                rtnetlink::AddressMessageBuilder::<std::net::Ipv6Addr>::new()
                    .index(index)
                    .address("fd97::1".parse().unwrap(), 64)
                    .build(),
            )
            .execute()
            .await
            .unwrap();

        let prefixes: Vec<IpNet> = vec!["192.0.2.0/24".parse().unwrap()];
        let underlay: Vec<IpAddr> = vec![
            "203.0.113.10".parse().unwrap(),
            "2001:db8::77".parse().unwrap(),
        ];
        let error = install_overlay_routes("tincovrb1", &prefixes, &underlay)
            .await
            .unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
        // The IPv4 underlay route installed before the failure was rolled
        // back, and no overlay prefix was installed.
        let routes = main_table_routes(&handle).await;
        assert!(!routes.contains(&(
            32,
            Some("203.0.113.10".parse().unwrap()),
            Some("10.97.0.2".parse().unwrap()),
            Some(index)
        )));
        assert!(!routes.contains(&(24, Some("192.0.2.0".parse().unwrap()), None, Some(index))));
        drop(device);
        task.abort();
    }

    #[tokio::test]
    async fn overlay_route_install_rolls_back_when_v4_underlay_gateway_is_unreachable() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let device = create_tun(&TunConfig {
            enabled: true,
            name: "tincovrb2".into(),
            addresses: vec!["10.96.0.1/24".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();

        let (connection, handle, _) = new_connection().unwrap();
        let task = tokio::spawn(connection);
        let index = test_link_index(&handle, "tincovrb2").await;
        add_default_route(&handle, "10.96.0.2".parse().unwrap(), index).await;
        // Deleting the connected route without touching the address keeps the
        // default route in the table but makes its gateway unreachable. The
        // delete must carry the exact kernel message, so fetch it first.
        let mut routes = handle
            .route()
            .get(rtnetlink::packet_route::route::RouteMessage::default())
            .execute();
        let mut connected = None;
        while let Some(route) = routes.try_next().await.unwrap() {
            let is_connected = route.header.destination_prefix_length == 24
                && route.attributes.iter().any(|attribute| {
                    matches!(
                        attribute,
                        rtnetlink::packet_route::route::RouteAttribute::Destination(
                            rtnetlink::packet_route::route::RouteAddress::Inet(address)
                        ) if *address == std::net::Ipv4Addr::new(10, 96, 0, 0)
                    )
                });
            if is_connected {
                connected = Some(route);
            }
        }
        handle
            .route()
            .del(connected.expect("the TUN connected route must exist"))
            .execute()
            .await
            .unwrap();

        let prefixes: Vec<IpNet> = vec!["192.0.2.0/24".parse().unwrap()];
        let underlay: Vec<IpAddr> = vec!["203.0.113.10".parse().unwrap()];
        let error = install_overlay_routes("tincovrb2", &prefixes, &underlay)
            .await
            .unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
        let routes = main_table_routes(&handle).await;
        assert!(!routes.contains(&(
            32,
            Some("203.0.113.10".parse().unwrap()),
            Some("10.96.0.2".parse().unwrap()),
            Some(index)
        )));
        drop(device);
        task.abort();
    }

    #[tokio::test]
    async fn overlay_route_install_rolls_back_prefixes_when_an_overlay_add_fails() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let device = create_tun(&TunConfig {
            enabled: true,
            name: "tincovrb3".into(),
            addresses: vec!["10.95.0.1/24".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        })
        .unwrap();

        let (connection, handle, _) = new_connection().unwrap();
        let task = tokio::spawn(connection);
        let index = test_link_index(&handle, "tincovrb3").await;
        add_default_route(&handle, "10.95.0.2".parse().unwrap(), index).await;
        // With IPv6 disabled on the TUN the kernel rejects the IPv6 overlay
        // route after the IPv4 underlay and overlay routes were installed.
        std::fs::write("/proc/sys/net/ipv6/conf/tincovrb3/disable_ipv6", "1").unwrap();

        let prefixes: Vec<IpNet> = vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let underlay: Vec<IpAddr> = vec!["203.0.113.10".parse().unwrap()];
        let error = install_overlay_routes("tincovrb3", &prefixes, &underlay)
            .await
            .unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
        // Both the installed overlay prefix and the underlay host route were
        // rolled back.
        let routes = main_table_routes(&handle).await;
        assert!(!routes.contains(&(24, Some("192.0.2.0".parse().unwrap()), None, Some(index))));
        assert!(!routes.contains(&(
            32,
            Some("203.0.113.10".parse().unwrap()),
            Some("10.95.0.2".parse().unwrap()),
            Some(index)
        )));
        drop(device);
        task.abort();
    }

    #[test]
    fn ensure_nft_table_parses_existing_tables_before_deciding() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let first = NftHealthySetTarget {
            table: "tinect_cov_exist".into(),
            name: "v4".into(),
        };
        ensure_nft_table(&first).unwrap();
        // The second pass parses the dumped table and matches it by name.
        ensure_nft_table(&first).unwrap();
        // A dumped table with a different name is parsed and skipped before
        // the missing one is created.
        let second = NftHealthySetTarget {
            table: "tinect_cov_other".into(),
            name: "v4".into(),
        };
        ensure_nft_table(&second).unwrap();
        delete_nft_table("tinect_cov_exist");
        delete_nft_table("tinect_cov_other");
    }

    #[test]
    fn nft_kernel_rejects_overlong_table_and_set_names() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let long = "a".repeat(300);
        let error = ensure_nft_table(&NftHealthySetTarget {
            table: long.clone(),
            name: "v4".into(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("creating nft table"));

        let error = HealthyRouteSetManager::open(NftHealthySetTargets {
            v4: Some(NftHealthySetTarget {
                table: "tinect_cov_long".into(),
                name: long,
            }),
            ..NftHealthySetTargets::default()
        })
        .err()
        .unwrap();
        // The kernel rejects the overlong set name already when the set is
        // queried, before the creation batch is ever sent.
        assert!(error.to_string().contains("querying nft set"));
        // The table created before the failed query must not linger.
        delete_nft_table("tinect_cov_long");
    }

    #[test]
    fn healthy_set_element_queries_round_trip_kernel_state() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let targets = NftHealthySetTargets {
            v4: Some(NftHealthySetTarget {
                table: "tinect_cov_elems".into(),
                name: "v4".into(),
            }),
            v6: Some(NftHealthySetTarget {
                table: "tinect_cov_elems".into(),
                name: "v6".into(),
            }),
            destroy_set: true,
            destroy_table: true,
        };
        let mut manager = HealthyRouteSetManager::open(targets).unwrap().unwrap();
        let desired: HashSet<IpNet> = [
            "192.0.2.0/24",
            "198.51.100.7/32",
            "2001:db8::/32",
            "2001:db9::1/128",
        ]
        .into_iter()
        .map(|prefix| prefix.parse().unwrap())
        .collect();
        manager.reconcile(&desired).unwrap();

        let expected_v4: HashSet<IpNet> = ["192.0.2.0/24", "198.51.100.7/32"]
            .into_iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect();
        let queried_v4 = query_healthy_set_elements(
            manager.targets.v4.as_ref().unwrap(),
            nftnl::ProtoFamily::Ipv4,
        )
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(queried_v4, expected_v4);

        let expected_v6: HashSet<IpNet> = ["2001:db8::/32", "2001:db9::1/128"]
            .into_iter()
            .map(|prefix| prefix.parse().unwrap())
            .collect();
        let queried_v6 = query_healthy_set_elements(
            manager.targets.v6.as_ref().unwrap(),
            nftnl::ProtoFamily::Ipv6,
        )
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(queried_v6, expected_v6);

        // Drop clears the elements and destroys the owned sets and table.
        drop(manager);
        let target = NftHealthySetTarget {
            table: "tinect_cov_elems".into(),
            name: "v4".into(),
        };
        assert!(query_healthy_set(&target).unwrap().is_none());
    }

    #[test]
    fn healthy_set_drop_tolerates_a_set_still_referenced_by_a_rule() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let target = NftHealthySetTarget {
            table: "tinect_cov_busy".into(),
            name: "v4".into(),
        };
        let manager = HealthyRouteSetManager::open(NftHealthySetTargets {
            v4: Some(target.clone()),
            ..NftHealthySetTargets::default()
        })
        .unwrap()
        .unwrap();
        // destroy_set is disabled, so the set survives this drop.
        drop(manager);

        // Reference the set from a rule so the kernel rejects its deletion.
        let table_name = CString::new(target.table.as_str()).unwrap();
        let table = nftnl::Table::new(table_name.as_c_str(), nftnl::ProtoFamily::Inet);
        let mut chain = nftnl::Chain::new(c"input", &table);
        chain.set_hook(nftnl::Hook::In, 0);
        chain.set_type(nftnl::ChainType::Filter);
        chain.set_policy(nftnl::Policy::Accept);
        let mut rule = nftnl::Rule::new(&chain);
        rule.add_expr(&nftnl::nft_expr!(payload ipv4 daddr));
        let set =
            nftnl::set::Set::<std::net::Ipv4Addr>::new(c"v4", 1, &table, nftnl::ProtoFamily::Inet);
        rule.add_expr(&nftnl::nft_expr!(lookup & set));
        let mut batch = nftnl::Batch::new();
        batch.add(&table, nftnl::MsgType::Add);
        batch.add(&chain, nftnl::MsgType::Add);
        batch.add(&rule, nftnl::MsgType::Add);
        send_linux_nft_batch(batch.finalize()).unwrap();

        // The element flush succeeds, the busy set deletion fails and is
        // logged, and the table deletion removes the rule, chain and set.
        let teardown = HealthyRouteSetManager {
            targets: NftHealthySetTargets {
                v4: Some(target.clone()),
                destroy_set: true,
                destroy_table: true,
                ..NftHealthySetTargets::default()
            },
            committed_v4: HashSet::new(),
            committed_v6: HashSet::new(),
        };
        drop(teardown);
        assert!(query_healthy_set(&target).unwrap().is_none());
    }

    #[test]
    fn quicp_rst_guard_install_rolls_back_when_the_kernel_rejects_the_batch() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        let port = 45680_u16;
        // A regular chain named "output" conflicts with the guard's base
        // chain, so the kernel rejects the guard's batch.
        let table_name = CString::new(quicp_rst_table_name(port)).unwrap();
        let table = nftnl::Table::new(table_name.as_c_str(), nftnl::ProtoFamily::Inet);
        let chain = nftnl::Chain::new(c"output", &table);
        let mut batch = nftnl::Batch::new();
        batch.add(&table, nftnl::MsgType::Add);
        batch.add(&chain, nftnl::MsgType::Add);
        send_linux_nft_batch(batch.finalize()).unwrap();

        let error = install_quicp_rst_guard(port, None).unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
        // The failed install ran its rollback: the whole table is gone, so
        // deleting it again reports the missing table as an error.
        assert!(cleanup_quicp_rst_guard(port).is_err());
    }

    #[tokio::test]
    async fn tun_mutations_report_missing_interfaces() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        // rtnetlink resolves the interface by name, so a missing TUN surfaces
        // as the kernel's ENODEV answer rather than an empty link listing.
        let error = set_tun_mtu("tincovnone", 1400).await.unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
        let addresses: Vec<IpNet> = vec![
            "100.64.0.1/32".parse().unwrap(),
            "192.0.2.1/32".parse().unwrap(),
        ];
        let error = configure_tun_addresses("tincovnone", &addresses)
            .await
            .unwrap_err();
        assert!(matches!(error, PlatformError::Command(_)));
    }

    #[test]
    fn direct_firewall_and_nat_propagate_builder_rejection() {
        if unsafe { libc::geteuid() } != 0
            || std::env::var_os("TINECT_RUN_NETFILTER_TESTS").is_none()
        {
            return;
        }
        let _network_namespace = crate::test_support::NetworkNamespace::enter();
        // A NUL in the TUN name makes the nft batch builders reject the
        // install; apply must propagate that instead of ignoring it.
        let tun = TunConfig {
            enabled: true,
            name: "bad\0tun".into(),
            addresses: vec!["100.64.0.10/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        let direct = DirectConfig {
            fallback: true,
            dscp: 46,
            fwmark: Some(0x100),
            conntrack_zone: 32123,
            routes: Vec::new(),
        };
        assert!(apply_direct_firewall(&tun, Some(&direct)).is_err());
        assert!(apply_direct_nat(&tun, Some(&direct), true).is_err());
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod lifecycle_hook_tests {
    use super::*;

    #[test]
    fn lifecycle_hook_receives_the_tun_name() {
        run_lifecycle_hooks(
            &["false".into(), "[ \"$TINECT_TUN\" = tinect-test ]".into()],
            "tinect-test",
            "test",
        )
        .unwrap_err();
    }

    #[test]
    fn forwarding_requirement_accepts_enabled_values() {
        assert!(validate_ip_forwarding("net.ipv4.ip_forward", "1").is_ok());
    }

    #[test]
    fn forwarding_requirement_rejects_disabled_values() {
        let error = validate_ip_forwarding("net.ipv4.ip_forward", "0").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Internet exit requires net.ipv4.ip_forward=1")
        );
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(test, target_os = "linux"))]
mod builder_tests {
    use super::*;

    #[test]
    fn nft_netlink_message_classifiers_cover_terminal_and_ignored_messages() {
        let error = nftnl::nftnl_sys::libc::NLMSG_ERROR as u16;
        let done = nftnl::nftnl_sys::libc::NLMSG_DONE as u16;
        assert_eq!(
            classify_nft_table_message(error, Some(0)),
            NftMessageAction::Ignore
        );
        assert_eq!(
            classify_nft_table_message(error, Some(-nftnl::nftnl_sys::libc::ENOENT)),
            NftMessageAction::Create
        );
        assert_eq!(
            classify_nft_table_message(error, Some(-libc::EPERM)),
            NftMessageAction::Error(-libc::EPERM)
        );
        assert_eq!(
            classify_nft_table_message(error, None),
            NftMessageAction::Ignore
        );
        assert_eq!(
            classify_nft_table_message(done, None),
            NftMessageAction::Create
        );
        assert_eq!(
            classify_nft_table_message(nftnl::nftnl_sys::libc::NFT_MSG_NEWTABLE as u16, None),
            NftMessageAction::Parse
        );
        assert_eq!(
            classify_nft_table_message(0xffff, None),
            NftMessageAction::Ignore
        );

        for classify in [classify_nft_set_message, classify_nft_elements_message] {
            assert_eq!(classify(error, Some(0)), NftMessageAction::Complete);
            assert_eq!(
                classify(error, Some(-nftnl::nftnl_sys::libc::ENOENT)),
                NftMessageAction::Complete
            );
            assert_eq!(
                classify(error, Some(-libc::EINVAL)),
                NftMessageAction::Error(-libc::EINVAL)
            );
            assert_eq!(classify(error, None), NftMessageAction::Ignore);
            assert_eq!(classify(done, None), NftMessageAction::Complete);
        }
        assert_eq!(
            classify_nft_set_message(nftnl::nftnl_sys::libc::NFT_MSG_NEWSET as u16, None),
            NftMessageAction::Parse
        );
        assert_eq!(
            classify_nft_elements_message(nftnl::nftnl_sys::libc::NFT_MSG_NEWSETELEM as u16, None,),
            NftMessageAction::Parse
        );
        assert_eq!(
            classify_nft_set_message(0xffff, None),
            NftMessageAction::Ignore
        );
        assert_eq!(
            classify_nft_elements_message(0xffff, None),
            NftMessageAction::Ignore
        );
    }

    #[test]
    fn nft_rule_builders_cover_mark_and_address_family_variants_without_kernel_io() {
        let tun = TunConfig {
            enabled: true,
            name: "tinect0".into(),
            addresses: vec![
                "100.64.0.10/32".parse().unwrap(),
                "fd74:696e:6563:7400::10/128".parse().unwrap(),
            ],
            mtu: 1280,
            clamp_mss: true,
        };
        for fwmark in [0, 0x100] {
            let _ = build_linux_direct_firewall(
                &tun.name,
                &linux_direct_table_name(&tun.name),
                46,
                fwmark,
            )
            .unwrap()
            .finalize();
        }
        for (fwmark, install_masquerade) in [(Some(0x100), true), (Some(0), true), (None, false)] {
            let _ = build_linux_direct_nat(
                &tun,
                &linux_direct_nat_table_name(&tun.name),
                46,
                fwmark,
                32123,
                install_masquerade,
            )
            .unwrap()
            .finalize();
        }
        for forwarded_exit in [false, true] {
            let _ =
                build_linux_exit_firewall(&tun, forwarded_exit, &linux_exit_table_name(&tun.name))
                    .unwrap()
                    .finalize();
        }
        let _ = build_linux_tun_input_firewall(&tun.name, &linux_tun_input_table_name(&tun.name))
            .unwrap()
            .finalize();
        assert_eq!(ipv6_dscp_value(0), 0);
        assert_eq!(ipv6_dscp_value(46), 0x800b);
    }

    #[test]
    fn nft_rule_builders_reject_nul_names_before_allocation() {
        assert!(build_linux_direct_firewall("bad\0name", "table", 1, 1).is_err());
        assert!(build_linux_direct_firewall("tun", "bad\0table", 1, 1).is_err());
        assert!(
            build_linux_direct_nat(
                &TunConfig {
                    enabled: true,
                    name: "bad\0tun".into(),
                    addresses: vec!["100.64.0.10/32".parse().unwrap()],
                    mtu: 1280,
                    clamp_mss: true,
                },
                "table",
                1,
                None,
                1,
                false,
            )
            .is_err()
        );
        assert!(
            build_linux_exit_firewall(
                &TunConfig {
                    enabled: true,
                    name: "tun".into(),
                    addresses: vec!["100.64.0.10/32".parse().unwrap()],
                    mtu: 1280,
                    clamp_mss: true,
                },
                false,
                "bad\0table",
            )
            .is_err()
        );
        assert!(build_linux_tun_input_firewall("bad\0tun", "table").is_err());
        assert!(build_linux_tun_input_firewall("tun", "bad\0table").is_err());
    }

    #[test]
    fn shell_command_helpers_report_success_and_failures() {
        run_checked("true", &[]).unwrap();
        assert!(run_checked("false", &[]).is_err());
        assert!(run_checked("command-that-does-not-exist", &[]).is_err());
        run_plan(&[vec!["true".into()]]).unwrap();
        assert!(run_plan(&[vec!["false".into()]]).is_err());
    }

    #[test]
    fn healthy_set_netlink_builders_cover_families_and_invalid_identifiers() {
        let v4 = NftHealthySetTarget {
            table: "tinect".into(),
            name: "healthy_v4".into(),
        };
        let v6 = NftHealthySetTarget {
            table: "tinect".into(),
            name: "healthy_v6".into(),
        };
        RawNftSet::identity(&v4, nftnl::ProtoFamily::Inet).unwrap();
        RawNftSet::new(&v4, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Ipv4).unwrap();
        RawNftSet::for_elements(&v4, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Ipv4).unwrap();
        RawNftSet::new(&v6, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Ipv6).unwrap();
        RawNftSet::for_elements(&v6, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Ipv6).unwrap();
        assert!(RawNftSet::new(&v4, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Inet).is_err());
        assert!(
            RawNftSet::for_elements(&v4, nftnl::ProtoFamily::Inet, nftnl::ProtoFamily::Inet)
                .is_err()
        );

        RawNftElements::new(
            &v4,
            nftnl::ProtoFamily::Ipv4,
            &["192.0.2.0/24".parse().unwrap()],
        )
        .unwrap();
        RawNftElements::new(
            &v6,
            nftnl::ProtoFamily::Ipv6,
            &["2001:db8::/32".parse().unwrap()],
        )
        .unwrap();
        assert!(
            RawNftElements::new(
                &v4,
                nftnl::ProtoFamily::Ipv4,
                &["2001:db8::/32".parse().unwrap()],
            )
            .is_err()
        );
        RawNftElements::clear(&v4).unwrap();
        assert!(
            RawNftSet::identity(
                &NftHealthySetTarget {
                    table: "bad\0table".into(),
                    name: "healthy".into(),
                },
                nftnl::ProtoFamily::Inet,
            )
            .is_err()
        );
    }

    #[test]
    fn nft_raw_messages_cover_interval_and_destroy_paths_without_kernel_io() {
        use nftnl::{Batch, MsgType, ProtoFamily};

        let target = NftHealthySetTarget {
            table: "tinect".into(),
            name: "healthy".into(),
        };
        let mut identity = RawNftSet::identity(&target, ProtoFamily::Inet).unwrap();
        identity.exclusive = false;
        let named_v4 = RawNftSet::new(&target, ProtoFamily::Inet, ProtoFamily::Ipv4).unwrap();
        let elements_v4 = RawNftElements::new(
            &target,
            ProtoFamily::Ipv4,
            &[
                "192.0.2.0/24".parse().unwrap(),
                "192.0.2.1/32".parse().unwrap(),
            ],
        )
        .unwrap();
        let elements_v6 = RawNftElements::new(
            &target,
            ProtoFamily::Ipv6,
            &["2001:db8::1/128".parse().unwrap()],
        )
        .unwrap();
        let clear = RawNftElements::clear(&target).unwrap();

        let mut batch = Batch::new();
        batch.add(&identity, MsgType::Add);
        batch.add(&identity, MsgType::Del);
        batch.add(&named_v4, MsgType::Add);
        batch.add(&named_v4, MsgType::Del);
        batch.add(&elements_v4, MsgType::Add);
        batch.add(&elements_v4, MsgType::Del);
        batch.add(&elements_v6, MsgType::Add);
        batch.add(&clear, MsgType::Del);
        let finalized = batch.finalize();
        assert!(!finalized.sequence_numbers().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn nft_interval_helpers_cover_wrapping_and_pending_boundaries() {
        use nftnl::ProtoFamily;

        assert_eq!(
            inclusive_end_to_exclusive(ProtoFamily::Ipv4, &[255, 255, 255, 255]),
            Some(vec![0, 0, 0, 0])
        );
        assert_eq!(
            inclusive_end_to_exclusive(ProtoFamily::Ipv6, &[0xff; 16]),
            Some(vec![0; 16])
        );
        assert!(inclusive_end_to_exclusive(ProtoFamily::Ipv4, &[0; 3]).is_none());
        assert!(inclusive_end_to_exclusive(ProtoFamily::Inet, &[0; 4]).is_none());

        let prefix: IpNet = "2001:db8::1/128".parse().unwrap();
        let (start, end) = interval_bounds(&prefix).unwrap();
        assert_eq!(
            interval_to_prefix(ProtoFamily::Ipv6, &start, &end),
            Some(prefix)
        );

        let mut prefixes = Vec::new();
        let mut pending = Some(vec![0; 4]);
        finish_pending_interval(ProtoFamily::Ipv4, &mut prefixes, &mut pending);
        assert_eq!(prefixes, vec!["0.0.0.0/0".parse().unwrap()]);
        let mut non_zero_pending = Some(vec![1, 0, 0, 0]);
        finish_pending_interval(ProtoFamily::Ipv4, &mut prefixes, &mut non_zero_pending);
        assert!(non_zero_pending.is_none());
        finish_pending_interval(ProtoFamily::Ipv4, &mut prefixes, &mut None);
    }

    #[test]
    fn direct_nat_builder_covers_source_address_masquerade_rules() {
        let tun = TunConfig {
            enabled: true,
            name: "tinect0".into(),
            addresses: vec![
                "100.64.0.10/32".parse().unwrap(),
                "fd74:696e:6563:7400::10/128".parse().unwrap(),
            ],
            mtu: 1280,
            clamp_mss: true,
        };
        let _ = build_linux_direct_nat(
            &tun,
            &linux_direct_nat_table_name(&tun.name),
            46,
            None,
            32123,
            true,
        )
        .unwrap()
        .finalize();
    }

    #[test]
    fn healthy_set_manager_without_targets_is_a_noop() {
        assert!(
            HealthyRouteSetManager::open(NftHealthySetTargets::default())
                .unwrap()
                .is_none()
        );
        let mut manager = HealthyRouteSetManager {
            targets: NftHealthySetTargets::default(),
            committed_v4: HashSet::new(),
            committed_v6: HashSet::new(),
        };
        manager.reconcile(&HashSet::new()).unwrap();
    }

    #[tokio::test]
    async fn linux_platform_wrappers_validate_inputs_before_kernel_io() {
        assert!(install_linux_direct_firewall("tun", "bad\0table", 0, 0).is_err());
        assert!(
            install_linux_direct_nat(
                &TunConfig {
                    enabled: true,
                    name: "tun".into(),
                    addresses: vec!["100.64.0.1/32".parse().unwrap()],
                    mtu: 1280,
                    clamp_mss: true,
                },
                "bad\0table",
                0,
                None,
                1,
                false,
            )
            .is_err()
        );
        assert!(
            install_linux_exit_firewall(
                &TunConfig {
                    enabled: true,
                    name: "tun".into(),
                    addresses: vec!["100.64.0.1/32".parse().unwrap()],
                    mtu: 1280,
                    clamp_mss: true,
                },
                false,
                "bad\0table",
            )
            .is_err()
        );
        assert!(install_linux_tun_input_firewall("bad\0tun", "table").is_err());
        assert!(delete_linux_direct_nat_table("bad\0table").is_err());
        assert!(delete_linux_exit_table(nftnl::ProtoFamily::Ipv4, "bad\0table").is_err());
        assert!(delete_linux_tun_input_table(nftnl::ProtoFamily::Ipv6, "bad\0table").is_err());

        let tun = TunConfig {
            enabled: true,
            name: "unused".into(),
            addresses: vec!["100.64.0.1/32".parse().unwrap()],
            mtu: 1280,
            clamp_mss: true,
        };
        configure_tun_addresses("unused", &[]).await.unwrap();
        configure_tun_addresses("unused", &tun.addresses)
            .await
            .unwrap();
        assert!(
            apply_tun_input_firewall(&TunConfig {
                name: "bad\0tun".into(),
                ..tun.clone()
            })
            .is_err()
        );
        assert!(
            apply_exit_network(
                &TunConfig {
                    name: "bad\0tun".into(),
                    ..tun.clone()
                },
                false,
            )
            .is_err()
        );
        assert!(
            cleanup_tun_input_firewall(&TunInputFirewallState {
                table_name: "bad\0table".into(),
            })
            .is_err()
        );
        assert!(
            cleanup_exit_network(&ExitNetworkState {
                table_name: "bad\0table".into(),
            })
            .is_err()
        );

        let multiple_addresses = [
            "100.64.0.1/32".parse().unwrap(),
            "2001:db8::1/128".parse().unwrap(),
        ];
        let missing =
            configure_tun_addresses("definitely-no-such-tinect-link", &multiple_addresses)
                .await
                .unwrap_err();
        assert!(!missing.to_string().is_empty());
        let missing = set_tun_mtu("definitely-no-such-tinect-link", 1280)
            .await
            .unwrap_err();
        assert!(!missing.to_string().is_empty());
        assert!(
            install_overlay_routes("definitely-no-such-tinect-link", &[], &[])
                .await
                .is_err()
        );
        assert!(
            cleanup_overlay_routes("definitely-no-such-tinect-link", &[])
                .await
                .is_err()
        );

        let invalid_owned = routes::UnderlayRouteOwnership {
            routes: vec![routes::OwnedUnderlayRoute {
                endpoint: "192.0.2.1".parse().unwrap(),
                gateway: "not-an-ip".into(),
                output_interface: 0,
            }],
        };
        assert!(cleanup_underlay_routes(&invalid_owned).await.is_err());
    }

    #[test]
    fn quicp_raw_socket_rejects_link_local_scope_ids() {
        let error =
            quicp::RawTcpSocket::open("[fe80::1%3]:1234".parse().unwrap(), None).unwrap_err();
        assert!(error.to_string().contains("link-local scope"));
    }

    #[test]
    fn nft_interval_helpers_cover_ipv6_wrapping_and_misaligned_ranges() {
        use nftnl::ProtoFamily;

        let max: IpNet = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
            .parse()
            .unwrap();
        let (start, end) = interval_bounds(&max).unwrap();
        assert_eq!(end, vec![0; 16]);
        assert_eq!(
            interval_to_prefix(ProtoFamily::Ipv6, &start, &end),
            Some(max)
        );

        assert!(
            interval_to_prefix(
                ProtoFamily::Ipv6,
                &[0; 16],
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
            )
            .is_none()
        );
        assert!(interval_to_prefix(ProtoFamily::Inet, &[0; 4], &[0; 4]).is_none());
    }

    #[test]
    fn nft_set_builders_reject_nul_in_set_names() {
        let bad_name = NftHealthySetTarget {
            table: "tinect".into(),
            name: "bad\0name".into(),
        };
        assert!(RawNftSet::identity(&bad_name, nftnl::ProtoFamily::Inet).is_err());
        assert!(RawNftElements::clear(&bad_name).is_err());
    }

    #[test]
    fn nft_interval_helpers_cover_zero_size_and_wrapped_ipv4_ranges() {
        use nftnl::ProtoFamily;

        // A zero-length interval (start == end with a non-zero start) is not
        // a decodable prefix.
        assert!(interval_to_prefix(ProtoFamily::Ipv4, &[0, 0, 0, 1], &[0, 0, 0, 1]).is_none());
        assert!(interval_to_prefix(ProtoFamily::Ipv4, &[0, 0, 0, 1], &[0, 0, 0, 3]).is_none());
        // A wrapped interval can still decode to an aligned prefix.
        assert_eq!(
            interval_to_prefix(ProtoFamily::Ipv4, &[128, 0, 0, 0], &[0, 0, 0, 0]),
            Some("128.0.0.0/1".parse().unwrap())
        );
        assert!(inclusive_end_to_exclusive(ProtoFamily::Ipv6, &[0; 15]).is_none());
    }

    #[test]
    fn healthy_set_element_decoder_handles_interval_orderings() {
        use nftnl::ProtoFamily;

        let family = ProtoFamily::Ipv4;
        let mut prefixes = Vec::new();
        let mut pending_start = None;
        let mut pending_end = None;
        consume_healthy_set_element(
            family,
            &[192, 0, 2, 0],
            Some(&[192, 0, 2, 255]),
            false,
            &mut prefixes,
            &mut pending_start,
            &mut pending_end,
        );
        assert_eq!(prefixes, vec!["192.0.2.0/24".parse().unwrap()]);

        // Invalid paired endpoints do not disturb pending interval state.
        consume_healthy_set_element(
            family,
            &[1, 2, 3],
            Some(&[1, 2, 4]),
            false,
            &mut prefixes,
            &mut pending_start,
            &mut pending_end,
        );
        pending_start = Some(vec![192, 0, 2, 0]);
        consume_healthy_set_element(
            family,
            &[192, 0, 3, 0],
            None,
            true,
            &mut prefixes,
            &mut pending_start,
            &mut pending_end,
        );
        assert!(pending_start.is_none());

        // End-before-start ordering is retained until the matching start
        // arrives, and an all-zero pending start represents the default route.
        consume_healthy_set_element(
            family,
            &[0, 0, 2, 0],
            None,
            true,
            &mut prefixes,
            &mut pending_start,
            &mut pending_end,
        );
        assert_eq!(pending_end, Some(vec![0, 0, 2, 0]));
        consume_healthy_set_element(
            family,
            &[0, 0, 0, 0],
            None,
            false,
            &mut prefixes,
            &mut pending_start,
            &mut pending_end,
        );
        pending_start = Some(vec![0; 4]);
        consume_healthy_set_element(
            family,
            &[0, 0, 0, 1],
            None,
            false,
            &mut prefixes,
            &mut pending_start,
            &mut pending_end,
        );
        assert!(prefixes.contains(&"0.0.0.0/0".parse().unwrap()));
    }

    #[test]
    fn nft_elements_builder_encodes_default_route_without_interval_end() {
        let target = NftHealthySetTarget {
            table: "tinect".into(),
            name: "healthy".into(),
        };
        // A default-route interval wraps its exclusive upper bound to zero,
        // so the start marker alone represents the whole address space and no
        // interval-end element is emitted.
        RawNftElements::new(
            &target,
            nftnl::ProtoFamily::Ipv4,
            &["0.0.0.0/0".parse().unwrap()],
        )
        .unwrap();
        RawNftElements::new(
            &target,
            nftnl::ProtoFamily::Ipv6,
            &["::/0".parse().unwrap()],
        )
        .unwrap();
    }
}
