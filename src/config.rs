use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const CONFIG_NAME: &str = ".acurl.toml";
pub const TRUSTED_PATH: &str = "/etc/acurl/trusted";

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AllowWrite {
    pub host: String,
    pub methods: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    pub command: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub allow_write: Vec<AllowWrite>,
    pub allow_binary: Vec<String>,
    #[serde(rename = "filter")]
    pub filters: Vec<Filter>,
    pub max_response_bytes: u64,
    pub max_output_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            allow_write: vec![],
            allow_binary: vec![],
            filters: vec![Filter {
                matches: [
                    "text/html", "application/xhtml+xml", "application/pdf",
                    "application/vnd.openxmlformats-officedocument.*", "application/msword",
                    "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
                    "application/vnd.ms-outlook", "application/epub+zip", "image/*",
                    "text/csv", "application/zip",
                ]
                .map(String::from)
                .to_vec(),
                command: ["markitdown", "-m", "{mime}"].map(String::from).to_vec(),
            }],
            max_response_bytes: 10_000_000,
            max_output_bytes: 200_000,
        }
    }
}

/// `*` matches any run of characters. Used for env var names and MIME patterns.
pub fn glob_match(pat: &str, s: &str) -> bool {
    match pat.split_once('*') {
        None => pat == s,
        Some((head, rest)) => {
            s.starts_with(head)
                && (0..=s.len() - head.len())
                    .filter(|&i| s.is_char_boundary(head.len() + i))
                    .any(|i| glob_match(rest, &s[head.len() + i..]))
        }
    }
}

pub fn find_config(start: &Path) -> Option<PathBuf> {
    start.ancestors().map(|d| d.join(CONFIG_NAME)).find(|p| p.is_file())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Root-owned and not writable by group/other.
pub fn is_secure(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

fn secure_path(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| is_secure(m.uid(), m.mode()))
}

/// Hashes from the trusted file, or empty if it (or its directory) could be tampered with.
pub fn trusted_hashes(path: &Path) -> HashSet<String> {
    let dir_ok = path.parent().is_some_and(secure_path);
    if !dir_ok || !secure_path(path) {
        return HashSet::new();
    }
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Why `p` would not count as secure, if it would not.
fn insecure_reason(p: &Path) -> Option<String> {
    let m = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(_) => return Some(format!("{}: missing", p.display())),
    };
    if m.uid() != 0 {
        Some(format!("{}: not owned by root", p.display()))
    } else if m.mode() & 0o022 != 0 {
        Some(format!("{}: writable by group/other (mode {:o})", p.display(), m.mode() & 0o777))
    } else {
        None
    }
}

/// `acurl doctor`: one (ok, message) per check of the setup acurl would use from `cwd`.
pub fn doctor(cwd: &Path, trusted_path: &Path) -> Vec<(bool, String)> {
    let mut out = vec![];
    let mut cfg = Config::default();
    match find_config(cwd) {
        None => out.push((true, format!("no {CONFIG_NAME} (strict defaults)"))),
        Some(path) => match std::fs::read(&path) {
            Err(e) => out.push((false, format!("{}: {e}", path.display()))),
            Ok(bytes) => {
                out.push((true, format!("config: {}", path.display())));
                let parsed = std::str::from_utf8(&bytes).map_err(|e| e.to_string()).and_then(parse);
                out.push(match &parsed {
                    Ok(_) => (true, "config parses".into()),
                    Err(e) => (false, format!("config does not parse: {e}")),
                });
                for p in [trusted_path.parent().unwrap_or(Path::new("/")), trusted_path] {
                    out.push(match insecure_reason(p) {
                        None => (true, format!("{}: owned by root, not group/other-writable", p.display())),
                        Some(why) => (false, why),
                    });
                }
                let hash = sha256_hex(&bytes);
                let trusted = trusted_hashes(trusted_path).contains(&hash);
                out.push(if trusted {
                    (true, format!("config trusted (sha256 {hash})"))
                } else {
                    (false, format!("config not trusted: sha256 {hash} is not in {} (run `sudo acurl trust`)", trusted_path.display()))
                });
                if let (true, Ok(c)) = (trusted, parsed) {
                    cfg = c;
                }
            }
        },
    }
    for f in &cfg.filters {
        let Some(cmd) = f.command.first() else {
            out.push((false, "filter with an empty command".into()));
            continue;
        };
        out.push(match crate::inbound::resolve_command(cmd) {
            Some(p) => (true, format!("filter {cmd}: {}", p.display())),
            None => (false, format!("filter {cmd}: not found (install it or use an absolute path in [[filter]])")),
        });
    }
    out
}

pub fn parse(text: &str) -> Result<Config, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}

/// Ok(config) or Err(message) for a trusted but unparsable config. Warnings go to stderr.
pub fn load(cwd: &Path) -> Result<Config, String> {
    let Some(path) = find_config(cwd) else { return Ok(Config::default()) };
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !trusted_hashes(Path::new(TRUSTED_PATH)).contains(&sha256_hex(&bytes)) {
        eprintln!(
            "acurl: warning: {} is not trusted (run `sudo acurl trust`); using strict defaults",
            path.display()
        );
        return Ok(Config::default());
    }
    let text = String::from_utf8(bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// `sudo acurl trust`: show the config, confirm, append its hash to TRUSTED_PATH.
pub fn trust(cwd: &Path) -> Result<(), String> {
    let path = find_config(cwd).ok_or(format!("no {CONFIG_NAME} found"))?;
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let text = String::from_utf8(bytes.clone()).map_err(|e| e.to_string())?;
    parse(&text)?;
    println!("--- {} ---\n{text}\n---", path.display());
    print!("Trust this config? [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).map_err(|e| e.to_string())?;
    if answer.trim() != "y" {
        return Err("aborted".into());
    }
    let trusted = Path::new(TRUSTED_PATH);
    let dir = trusted.parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(trusted)
        .map_err(|e| format!("{TRUSTED_PATH}: {e} (run with sudo)"))?;
    writeln!(f, "{}", sha256_hex(&bytes)).map_err(|e| e.to_string())?;
    if !secure_path(trusted) || !secure_path(dir) {
        return Err(format!("{TRUSTED_PATH} must be owned by root (run with sudo)"));
    }
    println!("trusted {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob() {
        assert!(glob_match("*_TOKEN", "GH_TOKEN"));
        assert!(glob_match("AWS_*", "AWS_SECRET_ACCESS_KEY"));
        assert!(glob_match("image/*", "image/png"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("*_TOKEN", "TOKEN"));
        assert!(!glob_match("text/html", "text/htmlx"));
    }

    #[test]
    fn secure_mode() {
        assert!(is_secure(0, 0o100644));
        assert!(!is_secure(1000, 0o100644));
        assert!(!is_secure(0, 0o100664));
        assert!(!is_secure(0, 0o100646));
    }

    #[test]
    fn parses_full_config() {
        let c = parse(
            r#"
            allow_binary = ["image/png"]
            max_output_bytes = 10
            [[allow_write]]
            host = "api.example.com"
            methods = ["POST"]
            [[filter]]
            match = ["*"]
            command = ["cat"]
            "#,
        )
        .unwrap();
        assert_eq!(c.allow_binary, vec!["image/png"]);
        assert_eq!(c.max_output_bytes, 10);
        assert_eq!(c.max_response_bytes, 10_000_000);
        assert_eq!(c.allow_write[0].host, "api.example.com");
        assert_eq!(c.filters, vec![Filter { matches: vec!["*".into()], command: vec!["cat".into()] }]);
    }

    #[test]
    fn empty_config_is_default_and_unknown_keys_fail() {
        assert_eq!(parse("").unwrap(), Config::default());
        assert!(parse("allow_everything = true").is_err());
    }

    #[test]
    fn untrusted_without_secure_file() {
        assert!(trusted_hashes(Path::new("/nonexistent/trusted")).is_empty());
    }

    fn tempdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("acurl-unit-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn fails(report: &[(bool, String)], needle: &str) -> bool {
        report.iter().any(|(ok, m)| !ok && m.contains(needle))
    }

    #[test]
    fn doctor_without_config() {
        let r = doctor(&tempdir("doc-none"), Path::new("/nonexistent/trusted"));
        assert_eq!(r[0], (true, "no .acurl.toml (strict defaults)".to_string()));
        assert!(r.iter().any(|(_, m)| m.starts_with("filter markitdown")), "{r:?}");
    }

    #[test]
    fn doctor_reports_parse_errors_and_untrusted_config() {
        let d = tempdir("doc-bad");
        std::fs::write(d.join(CONFIG_NAME), "allow_everything = true\n").unwrap();
        let r = doctor(&d, Path::new("/nonexistent/trusted"));
        assert!(fails(&r, "does not parse"), "{r:?}");
        assert!(fails(&r, "/nonexistent/trusted: missing"), "{r:?}");
        assert!(fails(&r, "not trusted"), "{r:?}");
    }

    #[test]
    fn doctor_rejects_a_trusted_file_not_owned_by_root() {
        let d = tempdir("doc-owner");
        std::fs::write(d.join(CONFIG_NAME), "").unwrap();
        let trusted = d.join("trusted");
        std::fs::write(&trusted, sha256_hex(b"")).unwrap();
        let r = doctor(&d, &trusted);
        assert!(fails(&r, "not owned by root"), "{r:?}");
        assert!(fails(&r, "not trusted"), "{r:?}");
    }

    #[test]
    fn hash_is_hex_sha256() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
