//! Parsing and classification for carrier endpoint URLs.

use super::ConfigError;

/// The carrier is selected exclusively by an endpoint URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierProtocol {
    Quic,
    QuicFull,
    QuicFakeTcp,
    QuicFullFakeTcp,
}

impl CarrierProtocol {
    pub fn is_bare_udp(self) -> bool {
        matches!(self, Self::Quic | Self::QuicFakeTcp)
    }

    pub fn is_fake_tcp(self) -> bool {
        matches!(self, Self::QuicFakeTcp | Self::QuicFullFakeTcp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierEndpoint {
    pub protocol: CarrierProtocol,
    pub address: String,
}

impl CarrierEndpoint {
    pub fn parse(value: &str, field: &str) -> Result<Self, ConfigError> {
        let (protocol, address) = [
            ("quicfull://", CarrierProtocol::QuicFull),
            ("quic://", CarrierProtocol::Quic),
            ("quicfull-faketcp://", CarrierProtocol::QuicFullFakeTcp),
            ("quic-faketcp://", CarrierProtocol::QuicFakeTcp),
        ]
        .iter()
        .find_map(|(scheme, protocol)| value.strip_prefix(scheme).map(|address| (*protocol, address)))
        .ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{field} must use quicfull://, quic://, quicfull-faketcp:// or quic-faketcp://, got {value}"
            ))
        })?;
        if address.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "{field} has an empty address"
            )));
        }
        Ok(Self {
            protocol,
            address: address.into(),
        })
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::{CarrierEndpoint, CarrierProtocol};

    #[test]
    fn parses_all_supported_schemes_and_rejects_empty_addresses() {
        for (value, protocol) in [
            ("quic://127.0.0.1:1", CarrierProtocol::Quic),
            ("quicfull://127.0.0.1:1", CarrierProtocol::QuicFull),
            ("quic-faketcp://127.0.0.1:1", CarrierProtocol::QuicFakeTcp),
            (
                "quicfull-faketcp://127.0.0.1:1",
                CarrierProtocol::QuicFullFakeTcp,
            ),
        ] {
            let endpoint = CarrierEndpoint::parse(value, "listen").unwrap();
            assert_eq!(endpoint.protocol, protocol);
            assert!(!endpoint.address.is_empty());
        }
        assert!(CarrierEndpoint::parse("quic://", "listen").is_err());
    }
}
