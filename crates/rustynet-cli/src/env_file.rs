pub(crate) fn format_env_assignment(key: &str, value: &str) -> Result<String, String> {
    validate_env_key(key)?;
    let quoted = quote_env_value(value)?;
    Ok(format!("{key}={quoted}"))
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

#[cfg(test)]
mod tests {
    use super::format_env_assignment;

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
}
