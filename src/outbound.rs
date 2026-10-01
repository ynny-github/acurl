use crate::config::Config;
use crate::Denied;
use regex::Regex;
use reqwest::Url;

pub fn is_read_only(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

pub fn check_method(cfg: &Config, method: &str, url: &Url) -> Result<(), Denied> {
    if is_read_only(method) {
        return Ok(());
    }
    let host = url.host_str().unwrap_or("");
    let allowed = cfg.allow_write.iter().any(|a| {
        a.host.eq_ignore_ascii_case(host) && a.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    });
    if allowed {
        Ok(())
    } else {
        Err(Denied::new(
            format!("{method} to {host} is not allowed"),
            format!("[[allow_write]] host = \"{host}\" methods = [\"{method}\"]"),
        ))
    }
}

/// 303 See Other turns any method into GET; other redirects keep it.
pub fn redirect_method(status: u16, method: &str) -> String {
    if status == 303 { "GET".into() } else { method.into() }
}

/// Writes must not be redirected to another host (the allow_write grant is per host).
pub fn check_redirect(method: &str, from: &Url, to: &Url) -> Result<(), Denied> {
    if is_read_only(method) || from.host_str() == to.host_str() {
        Ok(())
    } else {
        Err(Denied::new(
            format!("{method} redirected from {} to {}", from.host_str().unwrap_or(""), to.host_str().unwrap_or("")),
            "request the final URL directly".into(),
        ))
    }
}

const PATTERNS: &[(&str, &str)] = &[
    ("AWS access key", r"AKIA[0-9A-Z]{16}"),
    ("GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})"),
    ("API key (sk-)", r"\bsk-[A-Za-z0-9_-]{20,}"),
    ("Slack token", r"\bxox[bp]-[A-Za-z0-9-]{10,}"),
    ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
];

// Catches careless leaks of well-known token formats. Keeping secrets out of the sandbox
// (nono credential proxy) is the real defense; re-encoded secrets get through this scan.
pub fn check_secrets(parts: &[&str]) -> Result<(), Denied> {
    for part in parts {
        for (name, re) in PATTERNS {
            if Regex::new(re).unwrap().is_match(part) {
                return Err(Denied::new(
                    format!("request contains what looks like a {name}"),
                    "remove the secret from the request".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
        match (b[i], hex) {
            (b'%', Some(v)) => { out.push(v); i += 3; }
            (b'+', _) => { out.push(b' '); i += 1; }
            (c, _) => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// URL (raw + percent-decoded), header lines and body, as strings to scan.
pub fn request_parts(url: &Url, headers: &[(String, String)], body: &[u8]) -> Vec<String> {
    let mut parts = vec![url.as_str().to_string(), percent_decode(url.as_str())];
    parts.extend(headers.iter().map(|(k, v)| format!("{k}: {v}")));
    parts.push(String::from_utf8_lossy(body).into_owned());
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AllowWrite;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn methods() {
        let mut cfg = Config::default();
        assert!(check_method(&cfg, "GET", &url("https://a.com/")).is_ok());
        assert!(check_method(&cfg, "HEAD", &url("https://a.com/")).is_ok());
        let d = check_method(&cfg, "POST", &url("https://a.com/")).unwrap_err();
        assert!(d.hint.contains("host = \"a.com\""));
        cfg.allow_write.push(AllowWrite { host: "a.com".into(), methods: vec!["post".into()] });
        assert!(check_method(&cfg, "POST", &url("https://A.com/x")).is_ok());
        assert!(check_method(&cfg, "DELETE", &url("https://a.com/")).is_err());
        assert!(check_method(&cfg, "POST", &url("https://b.com/")).is_err());
    }

    #[test]
    fn see_other_switches_to_get_before_the_redirect_check() {
        assert_eq!(redirect_method(303, "POST"), "GET");
        assert_eq!(redirect_method(307, "POST"), "POST");
        assert_eq!(redirect_method(302, "GET"), "GET");
    }

    #[test]
    fn redirects() {
        let (a, a2, b) = (url("https://a.com/1"), url("https://a.com/2"), url("https://b.com/"));
        assert!(check_redirect("GET", &a, &b).is_ok());
        assert!(check_redirect("POST", &a, &a2).is_ok());
        assert!(check_redirect("POST", &a, &b).is_err());
    }

    #[test]
    fn detects_token_patterns() {
        assert!(check_secrets(&["AKIAABCDEFGHIJKLMNOP"]).is_err());
        assert!(check_secrets(&["token ghp_0123456789abcdefghijklmnopqrstuvwxyz"]).is_err());
        assert!(check_secrets(&["-----BEGIN OPENSSH PRIVATE KEY-----"]).is_err());
        assert!(check_secrets(&["Authorization: Bearer xoxb-1234567890-abc"]).is_err());
        assert!(check_secrets(&["hello world", "ask-me", "sk-short"]).is_ok());
    }

    #[test]
    fn decoded_url_parts_are_scanned() {
        let u = url(&format!("https://a.com/x?t=gh%70_{}", "a".repeat(36)));
        // raw URL alone would not match: proves decoding matters
        assert!(check_secrets(&[u.as_str()]).is_ok());
        let parts = request_parts(&u, &[], b"");
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        assert!(check_secrets(&refs).is_err());
    }
}
