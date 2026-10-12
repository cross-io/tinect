use anyhow::{Context, Result, anyhow};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::lookup_host;

use crate::config::DnsServer;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared resolver for all configuration-controlled hostnames.
///
/// Each configured server gets its own cached resolver so the outer loop can
/// enforce the documented server ordering. A single resolver uses UDP with
/// TCP fallback for truncated responses.
#[derive(Clone)]
pub struct DnsResolver {
    custom: Arc<Vec<TokioResolver>>,
}

impl DnsResolver {
    pub fn new(servers: &[DnsServer]) -> Result<Self> {
        let mut custom = Vec::with_capacity(servers.len());
        for server in servers {
            let mut name_server = NameServerConfig::udp_and_tcp(server.ip());
            for connection in &mut name_server.connections {
                connection.port = server.port();
            }
            let mut config = ResolverConfig::default();
            config.add_name_server(name_server);
            let mut options = ResolverOpts::default();
            options.timeout = DNS_QUERY_TIMEOUT;
            options.attempts = 1;
            options.use_hosts_file = ResolveHosts::Never;
            let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()
                .context("building custom DNS resolver")?;
            custom.push(resolver);
        }
        Ok(Self {
            custom: Arc::new(custom),
        })
    }

    /// Resolve an address-bearing target, preserving resolver answer order.
    /// Literal IP addresses bypass DNS entirely. Configured servers are tried
    /// in order, followed by the operating-system resolver.
    pub async fn resolve_socket_addrs(&self, target: &str) -> Result<Vec<SocketAddr>> {
        if let Ok(address) = target.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err(anyhow!("target port must be within 1..=65535: {target}"));
            }
            return Ok(vec![address]);
        }
        let (host, port) = split_host_port(target)?;
        let mut custom_errors = Vec::new();
        for resolver in self.custom.iter() {
            match resolver.lookup_ip(host).await {
                Ok(lookup) => {
                    let addresses =
                        deduplicate_socket_addrs(lookup.iter().map(|ip| SocketAddr::new(ip, port)));
                    if !addresses.is_empty() {
                        return Ok(addresses);
                    }
                    custom_errors.push(format!("custom DNS returned no addresses for {host}"));
                }
                Err(error) => custom_errors.push(error.to_string()),
            }
        }

        let system = lookup_host(target)
            .await
            .with_context(|| format!("resolving {target} with the system resolver"))?;
        let addresses = deduplicate_socket_addrs(system);
        if addresses.is_empty() {
            let detail = if custom_errors.is_empty() {
                String::new()
            } else {
                format!("; custom DNS errors: {}", custom_errors.join(" | "))
            };
            return Err(anyhow!(
                "hostname resolved to no addresses: {target}{detail}"
            ));
        }
        Ok(addresses)
    }
}

/// Validate the syntax of a configuration-controlled address without doing
/// DNS or network I/O. Listening sockets intentionally have a separate
/// parser because port 0 is meaningful there; remote peer endpoints never
/// accept an ephemeral port.
pub(crate) fn validate_socket_target(target: &str) -> Result<()> {
    if let Ok(address) = target.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(anyhow!("target port must be within 1..=65535: {target}"));
        }
        return Ok(());
    }
    split_host_port(target).map(|_| ())
}

fn deduplicate_socket_addrs(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect()
}

fn split_host_port(target: &str) -> Result<(&str, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid bracketed target: {target}"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("target must include a port: {target}"))?
            .parse::<u16>()
            .with_context(|| format!("invalid port in target: {target}"))?;
        if host.is_empty() {
            return Err(anyhow!("target hostname must not be empty: {target}"));
        }
        return validate_host_port(host, port, target);
    }

    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("target must be HOST:PORT: {target}"))?;
    if host.contains(':') {
        return Err(anyhow!("IPv6 targets must use brackets: {target}"));
    }
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid port in target: {target}"))?;
    validate_host_port(host, port, target)
}

fn validate_host_port<'a>(host: &'a str, port: u16, target: &str) -> Result<(&'a str, u16)> {
    if host.is_empty() {
        return Err(anyhow!("target hostname must not be empty: {target}"));
    }
    if port == 0 {
        return Err(anyhow!("target port must be within 1..=65535: {target}"));
    }
    Ok((host, port))
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[test]
    fn splits_hostname_and_ipv6_targets() {
        assert_eq!(
            split_host_port("example.test:443").unwrap(),
            ("example.test", 443)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:5353").unwrap(),
            ("2001:db8::1", 5353)
        );
    }

    #[test]
    fn rejects_ambiguous_or_zero_port_targets() {
        assert!(split_host_port("2001:db8::1:443").is_err());
        assert!(split_host_port("example.test:0").is_err());
        assert!(split_host_port("example.test").is_err());
        assert!(validate_socket_target("127.0.0.1:0").is_err());
        assert!(validate_socket_target("[::1]:0").is_err());
        assert!(validate_socket_target("127.0.0.1:443").is_ok());
    }

    #[tokio::test]
    async fn validates_literals_and_rejects_malformed_host_port_forms() {
        let resolver = DnsResolver::new(&[]).unwrap();
        assert_eq!(
            resolver
                .resolve_socket_addrs("127.0.0.1:443")
                .await
                .unwrap(),
            vec!["127.0.0.1:443".parse().unwrap()]
        );
        assert!(resolver.resolve_socket_addrs("127.0.0.1:0").await.is_err());
        assert!(split_host_port("[::1").is_err());
        assert!(split_host_port("[::1]443").is_err());
        assert!(split_host_port("[]:443").is_err());
        assert!(split_host_port("[::1]:bad").is_err());
        assert!(split_host_port("host:").is_err());
        assert!(split_host_port(":443").is_err());
        assert!(validate_host_port("host", 0, "host:0").is_err());
    }

    #[test]
    fn deduplicates_without_reordering() {
        let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let second: SocketAddr = "192.0.2.2:443".parse().unwrap();
        assert_eq!(
            deduplicate_socket_addrs([first, second, first]),
            vec![first, second]
        );
    }

    #[tokio::test]
    async fn custom_server_returns_a_and_aaaa_addresses() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = DnsServer::from_socket_addr(socket.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut request = [0u8; 2048];
            loop {
                let (length, peer) = socket.recv_from(&mut request).await.unwrap();
                let response = dns_response(&request[..length]);
                socket.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::new(&[server]).unwrap();
        let addresses = resolver
            .resolve_socket_addrs("service.test:443")
            .await
            .unwrap();
        task.abort();

        assert!(addresses.contains(&"192.0.2.10:443".parse().unwrap()));
        assert!(addresses.contains(&"[2001:db8::10]:443".parse().unwrap()));
    }

    #[tokio::test]
    async fn falls_back_to_system_resolver_after_custom_failure() {
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = DnsServer::from_socket_addr(closed.local_addr().unwrap());
        drop(closed);
        let resolver = DnsResolver::new(&[server]).unwrap();
        let addresses = resolver.resolve_socket_addrs("localhost:80").await.unwrap();
        assert!(!addresses.is_empty());
    }

    fn dns_response(query: &[u8]) -> Vec<u8> {
        let question_end = question_end(query);
        let qtype = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
        let mut response = Vec::with_capacity(question_end + 32);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..question_end]);
        response.extend_from_slice(&0xc00cu16.to_be_bytes());
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&30u32.to_be_bytes());
        match qtype {
            1 => {
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&[192, 0, 2, 10]);
            }
            28 => {
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(
                    &"2001:db8::10"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
            }
            _ => {
                response.truncate(question_end);
                response[6..8].copy_from_slice(&0u16.to_be_bytes());
            }
        }
        response
    }

    fn question_end(query: &[u8]) -> usize {
        let mut cursor = 12;
        loop {
            let length = query[cursor] as usize;
            cursor += 1;
            if length == 0 {
                return cursor + 4;
            }
            cursor += length;
        }
    }

    #[test]
    fn validates_hostname_targets_and_port_boundaries() {
        assert!(validate_socket_target("example.test:443").is_ok());
        assert!(validate_socket_target("example.test:65535").is_ok());
        assert!(validate_socket_target("[2001:db8::1]:443").is_ok());
        assert!(validate_socket_target("example.test:65536").is_err());
        assert!(validate_socket_target("example.test:bad").is_err());
        assert!(validate_socket_target("example.test").is_err());
        assert!(split_host_port("example.test:65535").is_ok());
        assert!(split_host_port("example.test:65536").is_err());
    }

    #[test]
    fn deduplicates_empty_input_to_empty_output() {
        assert!(deduplicate_socket_addrs([]).is_empty());
    }

    #[tokio::test]
    async fn resolve_rejects_targets_without_valid_host_port() {
        let resolver = DnsResolver::new(&[]).unwrap();
        assert_eq!(
            resolver.resolve_socket_addrs("[::1]:443").await.unwrap(),
            vec!["[::1]:443".parse().unwrap()]
        );
        assert!(resolver.resolve_socket_addrs("example.test").await.is_err());
        assert!(
            resolver
                .resolve_socket_addrs("example.test:bad")
                .await
                .is_err()
        );
        assert!(resolver.resolve_socket_addrs("[::1]:0").await.is_err());
    }

    #[tokio::test]
    async fn system_resolver_failure_is_reported_with_context() {
        // A label longer than 63 bytes is not a valid DNS name, so even
        // fake-IP style intercepting resolvers must reject it.
        let host = format!("{}.invalid:80", "a".repeat(100));
        let resolver = DnsResolver::new(&[]).unwrap();
        let error = resolver.resolve_socket_addrs(&host).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("system resolver"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn later_custom_server_is_used_after_earlier_failure() {
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = DnsServer::from_socket_addr(closed.local_addr().unwrap());
        drop(closed);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alive = DnsServer::from_socket_addr(socket.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut request = [0u8; 2048];
            loop {
                let (length, peer) = socket.recv_from(&mut request).await.unwrap();
                let response = dns_response(&request[..length]);
                socket.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::new(&[dead, alive]).unwrap();
        let addresses = resolver
            .resolve_socket_addrs("service.test:443")
            .await
            .unwrap();
        task.abort();

        assert!(addresses.contains(&"192.0.2.10:443".parse().unwrap()));
    }

    #[tokio::test]
    async fn custom_server_with_empty_answers_falls_back_to_system() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = DnsServer::from_socket_addr(socket.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut request = [0u8; 2048];
            loop {
                let (length, peer) = socket.recv_from(&mut request).await.unwrap();
                let question_end = question_end(&request[..length]);
                let mut response = Vec::with_capacity(question_end);
                response.extend_from_slice(&request[..2]);
                response.extend_from_slice(&0x8180u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&request[12..question_end]);
                socket.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver = DnsResolver::new(&[server]).unwrap();
        let addresses = resolver.resolve_socket_addrs("localhost:80").await.unwrap();
        assert!(!addresses.is_empty());
        task.abort();
    }
}
