use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use std::net::SocketAddr;

/// A literal IP address of an upstream DNS server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct DnsServer(SocketAddr);

impl DnsServer {
    pub(crate) fn from_socket_addr(address: SocketAddr) -> Self {
        Self(address)
    }

    pub fn socket_addr(&self) -> SocketAddr {
        self.0
    }

    pub fn ip(&self) -> std::net::IpAddr {
        self.0.ip()
    }

    pub fn port(&self) -> u16 {
        self.0.port()
    }
}

impl<'de> Deserialize<'de> for DnsServer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let value = value.trim();
        if value.is_empty() {
            return Err(serde::de::Error::custom("DNS server must not be empty"));
        }
        let address = if let Ok(address) = value.parse::<SocketAddr>() {
            address
        } else if let Ok(ip) = value.parse::<std::net::IpAddr>() {
            SocketAddr::new(ip, 53)
        } else if let Some(ip) = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            && let Ok(ip) = ip.parse::<std::net::IpAddr>()
        {
            SocketAddr::new(ip, 53)
        } else {
            return Err(serde::de::Error::custom(
                "DNS server must be an IP address with an optional port",
            ));
        };
        if address.port() == 0 {
            return Err(serde::de::Error::custom(
                "DNS server port must be within 1..=65535",
            ));
        }
        Ok(Self(address))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FakeIpConfig {
    pub listen: SocketAddr,
    pub upstream_dns: Vec<DnsServer>,
    #[serde(default)]
    pub disable_ipv6: bool,
    #[serde(default = "default_fake_ipv4_pool")]
    pub ipv4_pool: IpNet,
    #[serde(default = "default_fake_ipv6_pool")]
    pub ipv6_pool: IpNet,
    #[serde(default = "default_fake_min_ttl")]
    pub min_cache_ttl_secs: u32,
    #[serde(default = "default_fake_max_ttl")]
    pub max_cache_ttl_secs: u32,
    #[serde(default = "default_fake_max_entries")]
    pub max_entries: usize,
}

fn default_fake_ipv4_pool() -> IpNet {
    "198.18.0.0/15".parse().expect("valid built-in FakeIP pool")
}

fn default_fake_ipv6_pool() -> IpNet {
    "fd74:696e:6563:7400::/64"
        .parse()
        .expect("valid built-in FakeIP pool")
}

fn default_fake_min_ttl() -> u32 {
    60
}

fn default_fake_max_ttl() -> u32 {
    86_400
}

fn default_fake_max_entries() -> usize {
    131_072
}
