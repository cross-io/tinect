//! Helpers for tests that need real Linux network resources.

use std::{fs::File, io, os::fd::AsRawFd};

const IFREQ_NAME_LEN: usize = 16;
const IFREQ_SIZE: usize = 40;
const IFREQ_FLAGS_OFFSET: usize = IFREQ_NAME_LEN;

/// Isolates one privileged test from the network state of its test siblings.
///
/// The guard must live for the complete test. Tokio's default `#[tokio::test]`
/// runtime is single-threaded, so all tasks spawned by these tests stay in the
/// namespace until the guard restores the caller's namespace.
pub(crate) struct NetworkNamespace {
    original: File,
}

impl NetworkNamespace {
    pub(crate) fn enter() -> Self {
        let original = File::open("/proc/self/ns/net")
            .expect("open the current network namespace before entering the test namespace");
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            panic!(
                "create a private network namespace: {}",
                io::Error::last_os_error()
            );
        }

        if let Err(error) = set_loopback_up() {
            let _ = restore_namespace(&original);
            panic!("enable loopback in the test network namespace: {error}");
        }

        Self { original }
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        if let Err(error) = restore_namespace(&self.original) {
            if std::thread::panicking() {
                eprintln!("restore the test network namespace while unwinding: {error}");
            } else {
                panic!("restore the test network namespace: {error}");
            }
        }
    }
}

fn restore_namespace(original: &File) -> io::Result<()> {
    let result = unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_loopback_up() -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| {
        let mut request = [0_u8; IFREQ_SIZE];
        request[..2].copy_from_slice(b"lo");
        ioctl(fd, &mut request, libc::SIOCGIFFLAGS)?;

        let flags =
            i16::from_ne_bytes([request[IFREQ_FLAGS_OFFSET], request[IFREQ_FLAGS_OFFSET + 1]]);
        let flags = flags | libc::IFF_UP as i16;
        request[IFREQ_FLAGS_OFFSET..IFREQ_FLAGS_OFFSET + 2].copy_from_slice(&flags.to_ne_bytes());
        ioctl(fd, &mut request, libc::SIOCSIFFLAGS)
    })();

    unsafe {
        libc::close(fd);
    }
    result
}

fn ioctl(
    fd: libc::c_int,
    request: &mut [u8; IFREQ_SIZE],
    operation: libc::c_ulong,
) -> io::Result<()> {
    let result = unsafe { libc::ioctl(fd, operation, request.as_mut_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
