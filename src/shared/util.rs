/// Normalize a slice of tag strings: trim, lowercase, drop empties.
pub fn normalize_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect()
}

/// Ensure an IP address string has a CIDR mask suffix.
pub fn ensure_cidr(addr: &str, default_mask: &str) -> String {
    if addr.contains('/') {
        addr.to_string()
    } else {
        format!("{}{}", addr, default_mask)
    }
}

/// Truncate a key string to 20 characters with `...` suffix.
pub fn short_key(key: &str) -> String {
    if key.len() <= 20 {
        key.to_string()
    } else {
        format!("{}...", &key[..20])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_tags_trims_and_lowercases() {
        let tags = vec![" Foo ".to_string(), "".to_string(), "BAR".to_string()];
        assert_eq!(normalize_tags(&tags), vec!["foo", "bar"]);
    }

    #[test]
    fn ensure_cidr_appends_mask_when_missing() {
        assert_eq!(ensure_cidr("10.0.0.1", "/32"), "10.0.0.1/32");
        assert_eq!(ensure_cidr("10.0.0.1/24", "/32"), "10.0.0.1/24");
    }

    #[test]
    fn short_key_truncates_long_keys() {
        assert_eq!(short_key("short"), "short");
        assert_eq!(short_key("abcdefghijklmnopqrstuvwxyz"), "abcdefghijklmnopqrst...");
    }
}
