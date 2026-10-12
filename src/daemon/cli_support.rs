//! Local management CLI parsing and presentation helpers.
//!
//! They are deliberately separate from the daemon lifecycle: these commands
//! only query a local Unix socket or render a static configuration fallback.

use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tinect::{config::Config, identity, observability::Observability, runtime, status};

/// Locates a running daemon. A configuration file remains useful because
/// read-only commands can fall back to a deterministic static snapshot when
/// the daemon is not running. Without an explicit target, a single running
/// daemon in the platform default socket directory is selected automatically.
#[derive(clap::Args)]
pub(crate) struct DaemonTargetArgs {
    /// Configuration file; preserves static fallback for status and routes.
    #[arg(value_name = "CONFIG", conflicts_with_all = ["socket", "node"])]
    pub(crate) config: Option<PathBuf>,
    /// Exact local Unix management socket path.
    #[arg(long, value_name = "PATH", conflicts_with = "node")]
    pub(crate) socket: Option<PathBuf>,
    /// Node ID; derives the platform default management socket path.
    #[arg(long, value_name = "ID")]
    pub(crate) node: Option<String>,
}

pub(crate) enum DaemonTarget {
    Config(Box<Config>),
    Socket(String),
}

pub(crate) fn resolve_daemon_target(target: DaemonTargetArgs) -> Result<DaemonTarget> {
    match (target.config, target.socket, target.node) {
        (Some(config), None, None) => Ok(DaemonTarget::Config(Box::new(Config::load(config)?))),
        (None, Some(socket), None) => Ok(DaemonTarget::Socket(socket.display().to_string())),
        (None, None, Some(node)) => {
            if node.is_empty()
                || node == "."
                || node == ".."
                || node.contains('/')
                || node.contains('\0')
                || node.chars().any(char::is_control)
            {
                anyhow::bail!(
                    "--node must be a non-empty node ID without path separators, dot paths, NUL bytes, or control characters"
                )
            }
            Ok(DaemonTarget::Socket(Config::default_status_socket(&node)))
        }
        (None, None, None) => Ok(DaemonTarget::Socket(discover_daemon_socket()?)),
        _ => anyhow::bail!("provide at most one of CONFIG, --socket, or --node"),
    }
}

fn discover_daemon_socket() -> Result<String> {
    discover_daemon_socket_in(Path::new(Config::default_status_socket_dir()))
}

pub(crate) fn discover_daemon_socket_in(directory: &Path) -> Result<String> {
    let entries = std::fs::read_dir(directory).with_context(|| {
        format!(
            "no daemon target was supplied and cannot read {}",
            directory.display()
        )
    })?;
    let mut sockets = Vec::new();
    for entry in entries {
        let entry = entry?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if std::fs::symlink_metadata(entry.path())?
                .file_type()
                .is_socket()
            {
                sockets.push(entry.path());
            }
        }
        #[cfg(not(unix))]
        let _ = entry;
    }
    sockets.sort();
    match sockets.as_slice() {
        [socket] => Ok(socket.display().to_string()),
        [] => anyhow::bail!(
            "no running daemon socket found in {}; provide CONFIG, --node, or --socket",
            directory.display()
        ),
        _ => anyhow::bail!(
            "multiple daemon sockets found in {}: {}; provide --node or --socket",
            directory.display(),
            sockets
                .iter()
                .map(|socket| socket.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub(crate) async fn print_daemon_reply(socket: String, command: &str) -> Result<()> {
    let reply = status::request(socket, command)
        .await
        .context("requesting daemon status")?;
    print!("{}", decode_daemon_reply(command, &reply)?);
    Ok(())
}

pub(crate) fn load_identity_argument(
    key_path: Option<PathBuf>,
    secret: Option<String>,
) -> Result<ed25519_dalek::SigningKey> {
    match (key_path, secret) {
        (Some(path), None) => identity::load_secret(path).context("loading private key"),
        (None, Some(secret)) => identity::decode_secret(&secret).context("decoding private key"),
        (None, None) | (Some(_), Some(_)) => {
            anyhow::bail!("provide exactly one of --key or --secret")
        }
    }
}

/// Prefer a live daemon snapshot, but keep read-only CLI commands useful
/// before the daemon is started. JSON is only CLI presentation, never socket wire data.
pub(crate) async fn print_daemon_or_fallback<T>(
    socket: String,
    command: &str,
    fallback: T,
) -> Result<()>
where
    T: Serialize,
{
    match status::request(socket, command).await {
        Ok(reply) => print!("{}", decode_daemon_reply(command, &reply)?),
        Err(_) => println!("{}", serde_json::to_string_pretty(&fallback)?),
    }
    Ok(())
}

pub(crate) fn decode_topology_reply(reply: &[u8]) -> Result<String> {
    let mut input = tinect::wire::Reader::new(reply);
    let dot = input.string().context("decoding topology response")?;
    input.finish().context("decoding topology response")?;
    Ok(dot)
}

fn decode_daemon_reply(command: &str, reply: &[u8]) -> Result<String> {
    match command.trim() {
        "status" => Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(
                &status::decode_status(reply).context("decoding status response")?
            )?
        )),
        "routes" => Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(
                &status::decode_routes(reply).context("decoding routes response")?
            )?
        )),
        "topology" => decode_topology_reply(reply),
        _ => anyhow::bail!("unsupported daemon response"),
    }
}

pub(crate) fn static_state(config: &Config) -> status::DaemonState {
    runtime::initial_daemon_state(config, Arc::new(Observability::new(0)))
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_socket_target_does_not_touch_the_filesystem() {
        let target = resolve_daemon_target(DaemonTargetArgs {
            config: None,
            socket: Some(PathBuf::from("/run/tinect.sock")),
            node: None,
        })
        .unwrap();
        assert!(matches!(target, DaemonTarget::Socket(path) if path == "/run/tinect.sock"));
        assert!(
            resolve_daemon_target(DaemonTargetArgs {
                config: None,
                socket: Some(PathBuf::from("/run/tinect.sock")),
                node: Some("edge".into()),
            })
            .is_err()
        );
    }

    #[test]
    fn daemon_socket_discovery_reports_missing_directory_and_multiple_sockets() {
        let missing = tempfile::tempdir().unwrap().path().join("missing");
        assert!(discover_daemon_socket_in(&missing).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::net::UnixListener;
            let directory = tempfile::tempdir().unwrap();
            let _first = UnixListener::bind(directory.path().join("a.sock")).unwrap();
            let _second = UnixListener::bind(directory.path().join("b.sock")).unwrap();
            let error = discover_daemon_socket_in(directory.path()).unwrap_err();
            assert!(error.to_string().contains("multiple daemon sockets"));
        }
    }

    #[test]
    fn management_replies_decode_by_command_and_reject_unknown_or_trailing_data() {
        let status = status::Status {
            node: "edge".into(),
            node_identity: None,
            links: Vec::new(),
            circuits: Vec::new(),
            flow_count: 0,
            topology_nodes: 1,
            topology_generation: 2,
            supervised_tasks: 0,
            shutting_down: false,
            last_shutdown_error: None,
            circuit_traffic: Default::default(),
            acl_rejections: Default::default(),
        };
        let encoded_status = status::encode_status(&status).unwrap();
        let rendered = decode_daemon_reply("status\n", &encoded_status).unwrap();
        assert!(rendered.contains("\"node\": \"edge\""));

        let routes = vec![status::RouteStatus {
            selector: "10.0.0.0/8".into(),
            entries: 1,
            candidates: vec!["edge".into()],
        }];
        let encoded_routes = status::encode_routes(&routes).unwrap();
        assert!(
            decode_daemon_reply("routes", &encoded_routes)
                .unwrap()
                .contains("10.0.0.0/8")
        );

        let mut writer = tinect::wire::Writer::new();
        writer.string("digraph topology {}").unwrap();
        let topology = writer.finish();
        assert_eq!(
            decode_daemon_reply("topology", &topology).unwrap(),
            "digraph topology {}"
        );
        assert!(decode_daemon_reply("unknown", &[]).is_err());
        let mut trailing = topology;
        trailing.push(1);
        assert!(decode_topology_reply(&trailing).is_err());
    }

    #[test]
    fn static_state_is_side_effect_free_and_preserves_node_identity() {
        let config = crate::daemon::test_support::minimal_config();
        let state = static_state(&config);
        assert_eq!(state.status.node, "a");
        assert!(state.status.links.is_empty());
        assert!(state.routes.is_empty());
    }
}
