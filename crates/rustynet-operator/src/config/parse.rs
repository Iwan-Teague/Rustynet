use crate::config::keys::is_allowed_config_key;
use std::collections::BTreeMap;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedConfig {
    pub values: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

pub fn normalize_config_value(value: &str) -> String {
    if value == "''" {
        return String::new();
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
        return value[1..value.len() - 1].to_owned();
    }
    value.to_owned()
}

pub fn parse_wizard_env(text: &str) -> ParsedConfig {
    let mut parsed = ParsedConfig::default();

    for line in text.lines() {
        let lead_trimmed = line.trim_start();
        if lead_trimmed.is_empty() || lead_trimmed.starts_with('#') {
            continue;
        }

        let Some(eq) = line.find('=') else {
            parsed
                .warnings
                .push("Ignoring malformed config line.".to_owned());
            continue;
        };
        let key = &line[..eq];
        let raw_value = &line[eq + 1..];

        let key_shaped = !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !key_shaped {
            parsed
                .warnings
                .push("Ignoring malformed config line.".to_owned());
            continue;
        }

        if !is_allowed_config_key(key) {
            parsed
                .warnings
                .push(format!("Ignoring unknown config key '{key}'."));
            continue;
        }

        parsed
            .values
            .insert(key.to_owned(), normalize_config_value(raw_value));
    }

    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_one_quote_layer() {
        assert_eq!(normalize_config_value("''"), "");
        assert_eq!(normalize_config_value("'abc'"), "abc");
        assert_eq!(normalize_config_value("plain"), "plain");
        assert_eq!(normalize_config_value("'a'b'"), "a'b");
    }

    #[test]
    fn parses_allowlisted_keys_only() {
        let text = "\
# comment line
   # indented comment

NODE_ROLE=admin
WG_LISTEN_PORT='51820'
UNKNOWN_KEY=whatever
not a config line
lowercase=skip
";
        let parsed = parse_wizard_env(text);
        assert_eq!(
            parsed.values.get("NODE_ROLE").map(String::as_str),
            Some("admin")
        );
        assert_eq!(
            parsed.values.get("WG_LISTEN_PORT").map(String::as_str),
            Some("51820")
        );
        assert!(!parsed.values.contains_key("UNKNOWN_KEY"));
        assert!(!parsed.values.contains_key("lowercase"));
        assert!(
            parsed
                .warnings
                .iter()
                .any(|msg| msg.contains("unknown config key 'UNKNOWN_KEY'"))
        );
        assert_eq!(
            parsed
                .warnings
                .iter()
                .filter(|msg| msg.contains("malformed"))
                .count(),
            2
        );
    }
}
