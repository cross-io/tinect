//! Local Unix-socket management server and its bounded request lifecycle.

use super::{DaemonState, ManagementOpcode, encode_routes, encode_status};
use crate::wire::Writer;
use std::{io, path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{RwLock, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

const MAX_MANAGEMENT_CONNECTIONS: usize = 64;
const MANAGEMENT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Serves binary requests over a local Unix socket without a shutdown source.
/// Daemons should call [`serve_until_cancelled`] so in-flight client requests
/// stop with the rest of the daemon.
pub async fn serve(path: impl AsRef<Path>, state: Arc<RwLock<DaemonState>>) -> io::Result<()> {
    serve_until_cancelled(path, state, CancellationToken::new()).await
}

/// Serves binary local-management requests until `cancellation` is triggered.
/// Each client is bounded both in count and total request time, so an owner of
/// the local socket cannot leave detached reads alive after daemon shutdown.
pub async fn serve_until_cancelled(
    path: impl AsRef<Path>,
    state: Arc<RwLock<DaemonState>>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.file_type().is_socket() || metadata.uid() != unsafe { geteuid() } {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace a status path not owned by this daemon",
                ));
            }
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    // The management interface can return topology and decrypted packet
    // captures. Keep it restricted to the daemon owner even when that owner
    // is root; deployments that need delegation should provide it through a
    // separately authenticated management boundary.
    #[cfg(unix)]
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let permits = Arc::new(Semaphore::new(MAX_MANAGEMENT_CONNECTIONS));
    let mut clients = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            completed = clients.join_next(), if !clients.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "management client task failed");
                }
                continue;
            }
            accepted = listener.accept() => accepted?,
        };
        let (stream, _) = accepted;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let cancellation = cancellation.clone();
        clients.spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = cancellation.cancelled() => {}
                _ = tokio::time::timeout(MANAGEMENT_REQUEST_TIMEOUT, handle_client(stream, state)) => {}
            }
        });
    }
    while clients.join_next().await.is_some() {}
    Ok(())
}

async fn handle_client(mut stream: UnixStream, state: Arc<RwLock<DaemonState>>) {
    let mut header = [0; 3];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let Ok(opcode) = ManagementOpcode::try_from(header[0]) else {
        return;
    };
    // Pull a fresh status snapshot before answering so the reply is not
    // limited to whatever a polling task last sampled.
    super::request_status_refresh(&state).await;
    let mut body = vec![0; usize::from(u16::from_be_bytes([header[1], header[2]]))];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }
    let reply = match opcode {
        ManagementOpcode::Status => encode_status(&state.read().await.status),
        ManagementOpcode::Routes => encode_routes(&state.read().await.routes),
        ManagementOpcode::Topology => {
            let mut out = Writer::new();
            out.string(&state.read().await.topology_dot)
                .map(|_| out.finish())
        }
        ManagementOpcode::Pcap => Ok(state.read().await.observability.pcap()),
    };
    if let Ok(reply) = reply {
        for chunk in reply.chunks(u16::MAX as usize) {
            let mut frame = Vec::with_capacity(4 + chunk.len());
            frame.extend_from_slice(&[opcode as u8, 0]);
            frame.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            frame.extend_from_slice(chunk);
            if stream.write_all(&frame).await.is_err() {
                return;
            }
        }
    }
}

#[cfg(unix)]
unsafe fn geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        observability::{Observability, TrafficCounters},
        status::Status,
    };
    use std::collections::BTreeMap;

    fn state() -> Arc<RwLock<DaemonState>> {
        Arc::new(RwLock::new(DaemonState {
            status: Status {
                node: "test".into(),
                node_identity: None,
                links: Vec::new(),
                circuits: Vec::new(),
                flow_count: 0,
                topology_nodes: 0,
                topology_generation: 0,
                supervised_tasks: 0,
                shutting_down: false,
                last_shutdown_error: None,
                circuit_traffic: BTreeMap::<String, TrafficCounters>::new(),
                acl_rejections: BTreeMap::new(),
            },
            routes: Vec::new(),
            observability: Arc::new(Observability::new(0)),
            topology_dot: "digraph tinect {}\n".into(),
            status_refresh_requested: Arc::new(tokio::sync::Notify::new()),
            status_refresh_done: Arc::new(tokio::sync::Notify::new()),
            status_refresh_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }))
    }

    #[tokio::test]
    async fn cancellation_stops_the_management_listener() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.sock");
        let cancellation = CancellationToken::new();
        let listener_path = path.clone();
        let listener_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_until_cancelled(listener_path, state(), listener_cancellation).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("management listener starts");
        let _client = UnixStream::connect(&path).await.unwrap();
        // Keep a request body pending while shutdown starts. The listener must
        // cancel and join this accepted handler before returning.
        tokio::task::yield_now().await;
        cancellation.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("cancellation stops listener and its accepted clients")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn management_handlers_return_each_supported_opcode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.sock");
        let cancellation = CancellationToken::new();
        let listener_path = path.clone();
        let listener_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_until_cancelled(listener_path, state(), listener_cancellation).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("management listener starts");

        for opcode in [
            ManagementOpcode::Status,
            ManagementOpcode::Routes,
            ManagementOpcode::Topology,
            ManagementOpcode::Pcap,
        ] {
            let mut client = UnixStream::connect(&path).await.unwrap();
            client.write_all(&[opcode as u8, 0, 0]).await.unwrap();
            let mut header = [0_u8; 4];
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.read_exact(&mut header),
            )
            .await
            .expect("management response header")
            .unwrap();
            assert_eq!(header[0], opcode as u8);
            assert_eq!(header[1], 0);
            let body_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut body = vec![0_u8; body_len];
            client.read_exact(&mut body).await.unwrap();
        }

        cancellation.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("management listener stops")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_management_opcode_is_dropped_without_a_reply() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.sock");
        let cancellation = CancellationToken::new();
        let listener_path = path.clone();
        let listener_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_until_cancelled(listener_path, state(), listener_cancellation).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("management listener starts");

        let mut client = UnixStream::connect(&path).await.unwrap();
        client.write_all(&[0xff, 0, 0]).await.unwrap();
        let mut response = [0_u8; 1];
        assert!(client.read_exact(&mut response).await.is_err());

        cancellation.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("management listener stops")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn refuses_to_replace_a_regular_management_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.sock");
        std::fs::write(&path, b"not a socket").unwrap();
        let error = serve(&path, state()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }

    #[tokio::test]
    async fn malformed_clients_are_dropped_without_stalling_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.sock");
        let cancellation = CancellationToken::new();
        let listener_path = path.clone();
        let listener_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_until_cancelled(listener_path, state(), listener_cancellation).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        // A client may disconnect before a complete management header or its
        // declared body arrives.  Both reads are terminal for that client,
        // not fatal to the listener.
        let mut partial = UnixStream::connect(&path).await.unwrap();
        partial
            .write_all(&[ManagementOpcode::Status as u8])
            .await
            .unwrap();
        drop(partial);
        let mut truncated = UnixStream::connect(&path).await.unwrap();
        truncated
            .write_all(&[ManagementOpcode::Status as u8, 0, 4, 1, 2])
            .await
            .unwrap();
        drop(truncated);
        tokio::task::yield_now().await;

        cancellation.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn listener_reports_unusable_parent_directory() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("parent");
        std::fs::write(&parent, b"regular file").unwrap();
        let error = serve(parent.join("status.sock"), state())
            .await
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::AlreadyExists
                | io::ErrorKind::NotADirectory
                | io::ErrorKind::PermissionDenied
        ));
    }
}
