const MAX_PUBLIC_ERROR_BYTES: usize = 512;

pub fn public_error_message(message: &str) -> String {
    let first_line = message.lines().next().unwrap_or("operation failed").trim();
    let redacted = redact_credentials(first_line);
    truncate(&redacted, MAX_PUBLIC_ERROR_BYTES)
}

fn redact_credentials(message: &str) -> String {
    let mut redacted = message.to_string();
    for scheme in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "sqlite://",
        "http://",
        "https://",
    ] {
        redacted = redact_scheme_credentials(&redacted, scheme);
    }
    redacted
}

fn redact_scheme_credentials(message: &str, scheme: &str) -> String {
    let mut output = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(start) = rest.find(scheme) {
        let (before, after_scheme_start) = rest.split_at(start);
        output.push_str(before);
        output.push_str(scheme);
        let after_scheme = &after_scheme_start[scheme.len()..];
        let authority_end = after_scheme
            .find(['/', '?', '#', ' ', '\t', '\n', '\r'])
            .unwrap_or(after_scheme.len());
        let (authority, after_authority) = after_scheme.split_at(authority_end);
        if let Some(at) = authority.rfind('@') {
            output.push_str("<redacted>@");
            output.push_str(&authority[at + 1..]);
        } else {
            output.push_str(authority);
        }
        rest = after_authority;
    }
    output.push_str(rest);
    output
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_url_credentials() {
        let message =
            public_error_message("failed: postgres://user:secret@db.local:5432/app\ncontext");
        assert_eq!(message, "failed: postgres://<redacted>@db.local:5432/app");
    }
}
