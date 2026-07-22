//! Pure string helpers shared by the `ops read-json-field` /
//! `ops extract-managed-dns-expected-ip` commands and the live-lab test
//! binaries.
//!
//! Kept in an UN-GATED module (independent of the `vm-lab` feature) on purpose:
//! the always-built `live_*` evidence binaries (e.g. `live_linux_managed_dns_test`,
//! which its e2e wrapper runs via a plain `cargo run --bin`, no features) can call
//! this ONE canonical implementation in-process, instead of shelling out to
//! `cargo run -p rustynet-cli -- ops ...` (which rebuilt and clobbered the
//! orchestrator binary mid-run) or carrying a copy-pasted duplicate. The
//! `vm-lab`-gated `ops_live_lab_orchestrator` re-exports these, so the
//! ops-command dispatch keeps its existing `ops_live_lab_orchestrator::` paths.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadJsonFieldConfig {
    pub payload: String,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractManagedDnsExpectedIpConfig {
    pub fqdn: String,
    pub inspect_output: String,
}

/// Read a single top-level field out of a JSON object payload, rendering scalars
/// as bare strings (`true`/`false`, the number, the string) and a missing or
/// null field as the empty string. Non-scalar values are re-serialized.
pub fn execute_ops_read_json_field(config: ReadJsonFieldConfig) -> Result<String, String> {
    let payload = serde_json::from_str::<Value>(config.payload.as_str())
        .map_err(|err| format!("parse --payload JSON failed: {err}"))?;
    let object = payload
        .as_object()
        .ok_or_else(|| "--payload must be a JSON object".to_owned())?;
    let value = object.get(config.field.as_str());
    match value {
        None => Ok(String::new()),
        Some(Value::Null) => Ok(String::new()),
        Some(Value::Bool(flag)) => {
            if *flag {
                Ok("true".to_owned())
            } else {
                Ok("false".to_owned())
            }
        }
        Some(Value::String(text)) => Ok(text.clone()),
        Some(Value::Number(number)) => Ok(number.to_string()),
        Some(other) => {
            serde_json::to_string(other).map_err(|err| format!("serialize field failed: {err}"))
        }
    }
}

/// Extract the `expected_ip` for `fqdn` out of a `rustynet dns inspect` line.
/// Supports both the legacy flat form (`... fqdn=<x> ... expected_ip=<ip> ...`)
/// and the record-indexed form (`record.<n>.fqdn=<x> record.<n>.expected_ip=<ip>`).
/// Returns the empty string when the fqdn is not present.
pub fn execute_ops_extract_managed_dns_expected_ip(
    config: ExtractManagedDnsExpectedIpConfig,
) -> Result<String, String> {
    let fqdn = config.fqdn.trim().to_owned();
    if fqdn.is_empty() {
        return Err("--fqdn must be non-empty".to_owned());
    }
    let fqdn_token = format!("fqdn={fqdn}");
    for line in config.inspect_output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.contains(&fqdn_token.as_str()) {
            for token in &tokens {
                if let Some(value) = token.strip_prefix("expected_ip=") {
                    return Ok(value.to_owned());
                }
            }
        }

        for (index, token) in tokens.iter().enumerate() {
            let Some(record_token) = token.strip_prefix("record.") else {
                continue;
            };
            let Some((record_index, token_fqdn)) = record_token.split_once(".fqdn=") else {
                continue;
            };
            if token_fqdn != fqdn {
                continue;
            }

            let expected_ip_prefix = format!("record.{record_index}.expected_ip=");
            for candidate in &tokens {
                if let Some(value) = candidate.strip_prefix(expected_ip_prefix.as_str()) {
                    return Ok(value.to_owned());
                }
            }

            for candidate in tokens.iter().skip(index + 1) {
                if let Some(value) = candidate.strip_prefix("expected_ip=") {
                    return Ok(value.to_owned());
                }
            }
        }
    }
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_managed_dns_expected_ip_supports_legacy_tokens() {
        let output = "dns inspect: state=valid fqdn=exit.rustynet expected_ip=100.64.0.1";
        let expected =
            execute_ops_extract_managed_dns_expected_ip(ExtractManagedDnsExpectedIpConfig {
                fqdn: "exit.rustynet".to_owned(),
                inspect_output: output.to_owned(),
            })
            .expect("extract expected ip");
        assert_eq!(expected, "100.64.0.1");
    }

    #[test]
    fn extract_managed_dns_expected_ip_supports_record_indexed_tokens() {
        let output = "dns inspect: state=valid record_count=2 \
record.0.fqdn=client.rustynet record.0.expected_ip=100.68.223.117 \
record.1.fqdn=exit.rustynet record.1.expected_ip=100.109.33.213";
        let expected =
            execute_ops_extract_managed_dns_expected_ip(ExtractManagedDnsExpectedIpConfig {
                fqdn: "exit.rustynet".to_owned(),
                inspect_output: output.to_owned(),
            })
            .expect("extract expected ip");
        assert_eq!(expected, "100.109.33.213");
    }

    #[test]
    fn extract_managed_dns_expected_ip_returns_empty_when_fqdn_absent() {
        let out = execute_ops_extract_managed_dns_expected_ip(ExtractManagedDnsExpectedIpConfig {
            fqdn: "missing.rustynet".to_owned(),
            inspect_output: "dns inspect: state=valid fqdn=exit.rustynet expected_ip=100.64.0.1"
                .to_owned(),
        })
        .expect("no match yields empty, not an error");
        assert_eq!(out, "");
    }

    #[test]
    fn extract_managed_dns_expected_ip_rejects_empty_fqdn() {
        let err = execute_ops_extract_managed_dns_expected_ip(ExtractManagedDnsExpectedIpConfig {
            fqdn: "   ".to_owned(),
            inspect_output: "whatever".to_owned(),
        })
        .expect_err("a blank fqdn must fail closed");
        assert!(err.contains("--fqdn must be non-empty"), "{err}");
    }

    #[test]
    fn read_json_field_renders_each_scalar_kind_and_empty_for_missing() {
        let payload = r#"{"ip":"100.64.0.1","count":3,"ok":true,"off":false,"nothing":null}"#;
        let field = |name: &str| {
            execute_ops_read_json_field(ReadJsonFieldConfig {
                payload: payload.to_owned(),
                field: name.to_owned(),
            })
            .expect("read field")
        };
        assert_eq!(field("ip"), "100.64.0.1");
        assert_eq!(field("count"), "3");
        assert_eq!(field("ok"), "true");
        assert_eq!(field("off"), "false");
        assert_eq!(field("nothing"), "");
        assert_eq!(field("absent"), "");
    }

    #[test]
    fn read_json_field_rejects_a_non_object_payload() {
        let err = execute_ops_read_json_field(ReadJsonFieldConfig {
            payload: "[1,2,3]".to_owned(),
            field: "x".to_owned(),
        })
        .expect_err("an array payload must fail closed");
        assert!(err.contains("must be a JSON object"), "{err}");
    }
}
