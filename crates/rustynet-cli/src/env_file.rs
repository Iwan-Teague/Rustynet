pub(crate) fn format_env_assignment(key: &str, value: &str) -> Result<String, String> {
    validate_env_key(key)?;
    let quoted = quote_env_value(value)?;
    Ok(format!("{key}={quoted}"))
}

pub(crate) fn parse_env_value(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains('\0') {
        return Err("env-file values must not contain NUL bytes".to_string());
    }
    if trimmed.starts_with('"') {
        return parse_double_quoted_env_value(trimmed);
    }
    if trimmed.starts_with('\'') {
        return parse_single_quoted_env_value(trimmed);
    }
    Ok(trimmed.to_string())
}

fn validate_env_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(format!("invalid env-file key: {key}"));
    }
    Ok(())
}

fn quote_env_value(value: &str) -> Result<String, String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err("env-file values must not contain NUL or newline characters".to_string());
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '$' => quoted.push_str("\\$"),
            '`' => quoted.push_str("\\`"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn parse_double_quoted_env_value(raw: &str) -> Result<String, String> {
    if !raw.ends_with('"') || raw.len() < 2 {
        return Err(format!("unterminated double-quoted env-file value: {raw}"));
    }
    let mut decoded = String::with_capacity(raw.len().saturating_sub(2));
    let mut chars = raw[1..raw.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let escaped = chars
                .next()
                .ok_or_else(|| format!("trailing escape in env-file value: {raw}"))?;
            decoded.push(escaped);
            continue;
        }
        decoded.push(ch);
    }
    Ok(decoded)
}

fn parse_single_quoted_env_value(raw: &str) -> Result<String, String> {
    if !raw.ends_with('\'') || raw.len() < 2 {
        return Err(format!("unterminated single-quoted env-file value: {raw}"));
    }
    Ok(raw[1..raw.len() - 1].to_string())
}

#[cfg(test)]
mod tests {
    use super::{format_env_assignment, parse_env_value};

    #[test]
    fn format_env_assignment_quotes_shell_metacharacters() {
        let rendered = format_env_assignment(
            "RUSTYNET_ASSIGNMENT_NODES",
            "exit-49|192.168.18.49:51820|abc;client-50|192.168.18.50:51820|def",
        )
        .expect("render env assignment");
        assert_eq!(
            rendered,
            "RUSTYNET_ASSIGNMENT_NODES=\"exit-49|192.168.18.49:51820|abc;client-50|192.168.18.50:51820|def\""
        );
    }

    #[test]
    fn format_env_assignment_escapes_shell_expansion_bytes() {
        let rendered = format_env_assignment(
            "RUSTYNET_TEST_VALUE",
            "path=$HOME \"quoted\" `command` \\\\",
        )
        .expect("render env assignment");
        assert_eq!(
            rendered,
            "RUSTYNET_TEST_VALUE=\"path=\\$HOME \\\"quoted\\\" \\`command\\` \\\\\\\\\""
        );
    }

    #[test]
    fn format_env_assignment_rejects_newlines() {
        assert!(format_env_assignment("RUSTYNET_TEST_VALUE", "bad\nvalue").is_err());
    }

    #[test]
    fn parse_env_value_decodes_double_quoted_values() {
        assert_eq!(
            parse_env_value("\"path=\\$HOME \\\"quoted\\\" \\`command\\` \\\\\\\\\"")
                .expect("parse quoted value"),
            "path=$HOME \"quoted\" `command` \\\\"
        );
    }

    #[test]
    fn parse_env_value_decodes_single_quoted_values() {
        assert_eq!(
            parse_env_value("'client-50|exit-49'").expect("parse single-quoted value"),
            "client-50|exit-49"
        );
    }
}
