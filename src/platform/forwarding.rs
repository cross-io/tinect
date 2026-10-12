//! Host forwarding preflight checks.

use super::PlatformError;
use std::process::Command;

fn read_sysctl(key: &'static str) -> Result<String, PlatformError> {
    let output = Command::new("sysctl")
        .args(["-n", key])
        .output()
        .map_err(|error| PlatformError::Command(error.to_string()))?;
    parse_sysctl_output(key, output.status.success(), &output.stdout)
}

fn parse_sysctl_output(
    key: &str,
    status_success: bool,
    stdout: &[u8],
) -> Result<String, PlatformError> {
    if !status_success {
        return Err(PlatformError::Command(format!("sysctl -n {key}")));
    }
    Ok(String::from_utf8_lossy(stdout).trim().to_owned())
}

/// Verifies forwarding is enabled without changing a host-wide sysctl.
///
/// Tinect owns only the firewall resources it installs. Requiring the
/// administrator to configure forwarding persistently avoids racing or
/// disabling another router when this daemon exits.
pub(super) fn require_ip_forwarding(keys: &[&'static str]) -> Result<(), PlatformError> {
    for key in keys {
        validate_ip_forwarding(key, &read_sysctl(key)?)?;
    }
    Ok(())
}

pub(super) fn validate_ip_forwarding(key: &str, value: &str) -> Result<(), PlatformError> {
    if value == "1" {
        Ok(())
    } else {
        Err(PlatformError::Command(format!(
            "Internet exit requires {key}=1; configure it persistently in your system sysctl configuration"
        )))
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_validation_accepts_only_exactly_enabled_value() {
        assert!(validate_ip_forwarding("net.ipv4.ip_forward", "1").is_ok());
        for value in ["0", "", "01", " 1", "1\n"] {
            let error = validate_ip_forwarding("net.ipv4.ip_forward", value).unwrap_err();
            assert!(error.to_string().contains("net.ipv4.ip_forward=1"));
        }
    }

    #[test]
    fn empty_forwarding_requirement_does_not_read_sysctl() {
        assert!(require_ip_forwarding(&[]).is_ok());
    }

    #[test]
    fn parse_sysctl_output_handles_status_and_whitespace() {
        assert_eq!(
            parse_sysctl_output("net.ipv4.ip_forward", true, b" 1\n").unwrap(),
            "1"
        );
        let error = parse_sysctl_output("tinect.no.such.key", false, &[]).unwrap_err();
        assert!(error.to_string().contains("sysctl -n tinect.no.such.key"));
    }
}
