use crate::config::{glob_match, Config, Filter};
use crate::Denied;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

#[derive(Debug, PartialEq)]
pub enum Kind {
    Text(String),
    Executable(String),
    Archive(String),
    Binary(String),
}

const EXEC_MIMES: &[&str] = &[
    "application/x-executable", "application/x-elf", "application/x-mach-binary",
    "application/vnd.microsoft.portable-executable", "application/x-msdownload",
    "application/x-msdos-program", "application/x-sh", "application/x-shellscript",
];

const ARCHIVE_MIMES: &[&str] = &[
    "application/zip", "application/x-tar", "application/gzip", "application/x-gzip",
    "application/x-bzip2", "application/x-7z-compressed", "application/vnd.rar",
    "application/x-rar-compressed", "application/x-xz", "application/zstd",
    "application/x-compress", "application/x-lzip", "application/x-rpm",
    "application/vnd.debian.binary-package", "application/x-unix-archive",
    "application/vnd.ms-cab-compressed", "application/x-iso9660-image",
];

/// Content-Type essence ("text/html; charset=x" -> "text/html"), lowercased.
pub fn essence(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

pub fn charset(ct: &str) -> Option<String> {
    ct.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k.trim().eq_ignore_ascii_case("charset")).then(|| v.trim().trim_matches('"').to_string())
    })
}

fn is_text_mime(m: &str) -> bool {
    m.starts_with("text/")
        || ["json", "xml", "javascript", "ecmascript", "yaml", "toml"].iter().any(|t| m.contains(t))
}

fn looks_like_html(body: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&body[..body.len().min(512)])
        .trim_start_matches('\u{feff}')
        .trim_start()
        .to_ascii_lowercase();
    head.starts_with("<!doctype html") || head.starts_with("<html")
}

/// Decide what the body really is: magic bytes win over Content-Type.
pub fn classify(content_type: &str, body: &[u8]) -> Kind {
    let ct = essence(content_type);
    if body.is_empty() {
        return Kind::Text("text/plain".into());
    }
    if body.starts_with(b"#!") || EXEC_MIMES.contains(&ct.as_str()) {
        return Kind::Executable(ct);
    }
    let texty = !body.contains(&0);
    // infer's App matchers also cover PEM/DER/wasm/class; only EXEC_MIMES are executables,
    // and text such as PEM or PGP armor falls through to the text checks below.
    let detected = infer::get(body).filter(|t| {
        !(t.matcher_type() == infer::MatcherType::App && texty && !EXEC_MIMES.contains(&t.mime_type()))
    });
    if let Some(t) = detected {
        let mime = t.mime_type().to_string();
        return if EXEC_MIMES.contains(&t.mime_type()) {
            Kind::Executable(mime)
        } else if ARCHIVE_MIMES.contains(&t.mime_type()) {
            Kind::Archive(mime)
        } else if t.matcher_type() == infer::MatcherType::Text {
            Kind::Text(if is_text_mime(&ct) { ct } else { mime })
        } else {
            Kind::Binary(mime)
        };
    }
    if ARCHIVE_MIMES.contains(&ct.as_str()) {
        return Kind::Archive(ct);
    }
    if (ct.is_empty() || ct == "application/octet-stream") && texty {
        let mime = if looks_like_html(body) { "text/html" } else { "text/plain" };
        return Kind::Text(mime.into());
    }
    if is_text_mime(&ct) && texty {
        return Kind::Text(ct);
    }
    Kind::Binary(if ct.is_empty() { "application/octet-stream".into() } else { ct })
}

/// Read at most `max` bytes; more than that is a denial, not a silent cut.
/// The outer error is I/O (network), the inner one is policy.
pub fn read_limited(r: impl Read, max: u64) -> std::io::Result<Result<Vec<u8>, Denied>> {
    let mut buf = vec![];
    r.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Ok(Err(Denied::new(
            format!("response is larger than {max} bytes"),
            "max_response_bytes".into(),
        )));
    }
    Ok(Ok(buf))
}

/// Decode text by the Content-Type charset, else a <meta> charset if the body is not
/// UTF-8, else UTF-8 (lossy). A BOM wins over all of these (encoding_rs sniffs it).
pub fn decode(content_type: &str, body: &[u8]) -> String {
    let enc = charset(content_type)
        .and_then(|c| encoding_rs::Encoding::for_label(c.as_bytes()))
        .or_else(|| std::str::from_utf8(body).is_err().then(|| meta_charset(body)).flatten())
        .unwrap_or(encoding_rs::UTF_8);
    enc.decode(body).0.into_owned()
}

/// `charset=` from a <meta> tag in the first 1 KiB (HTML's own prescan window).
fn meta_charset(body: &[u8]) -> Option<&'static encoding_rs::Encoding> {
    let head = String::from_utf8_lossy(&body[..body.len().min(1024)]).to_ascii_lowercase();
    let rest = head[head.find("charset=")? + 8..].trim_start_matches(['"', '\'']);
    let label: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).collect();
    encoding_rs::Encoding::for_label(label.as_bytes())
}

/// Drop elements a browser would not show (and the agent should not read).
/// None if the HTML could not be rewritten: callers must not fall back to the raw page.
pub fn strip_html(html: &str) -> Option<String> {
    use lol_html::{doc_comments, element, rewrite_str, RewriteStrSettings};
    let settings = RewriteStrSettings::new()
        .with_strict(false) // strict mode bails out on parsing ambiguities, e.g. <style> inside <select>
        .append_element_content_handler(element!(
            // meta charset/http-equiv: the text is already decoded to UTF-8, so a stale
            // declaration would make the converter decode it a second time.
            r#"script, style, noscript, template, [hidden], [aria-hidden="true"], meta[charset], meta[http-equiv]"#,
            |el| {
                el.remove();
                Ok(())
            }
        ))
        .append_element_content_handler(element!("[style]", |el| {
            let s = el.get_attribute("style").unwrap_or_default().to_ascii_lowercase().replace(' ', "");
            if s.contains("display:none") || s.contains("visibility:hidden") {
                el.remove();
            }
            Ok(())
        }))
        .append_document_content_handler(doc_comments!(|c| {
            c.remove();
            Ok(())
        }));
    rewrite_str(html, settings).ok()
}

/// Where a filter command resolves the way `Command::new` will: absolute/relative paths as
/// given, bare names through PATH. Must be an executable regular file.
pub fn resolve_command(cmd: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let exec = |p: &std::path::Path| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
    if cmd.contains('/') {
        let p = std::path::PathBuf::from(cmd);
        return exec(&p).then_some(p);
    }
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(cmd)).find(|p| exec(p))
}

pub fn filters_for<'a>(cfg: &'a Config, mime: &str) -> Vec<&'a Filter> {
    cfg.filters.iter().filter(|f| f.matches.iter().any(|p| glob_match(p, mime))).collect()
}

pub enum FilterError {
    NotFound(String),
    Failed(Denied),
}

/// Pipe `input` through each filter's command; `{mime}` is replaced in arguments.
pub fn run_filters(filters: &[&Filter], mime: &str, input: Vec<u8>) -> Result<Vec<u8>, FilterError> {
    let mut data = input;
    for f in filters {
        let args: Vec<String> = f.command.iter().map(|a| a.replace("{mime}", mime)).collect();
        // Inherits the environment: Python tools live in uv/pipx/mise/pyenv paths. An agent
        // that rewrites PATH can swap a filter, so security filters belong as absolute paths.
        let mut child = match Command::new(&args[0])
            .args(&args[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(FilterError::NotFound(args[0].clone()))
            }
            Err(e) => return Err(FilterError::Failed(Denied::new(format!("filter {}: {e}", args[0]), String::new()))),
        };
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || stdin.write_all(&data));
        let out = child.wait_with_output().map_err(|e| FilterError::Failed(Denied::new(e.to_string(), String::new())))?;
        let _ = writer.join();
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(FilterError::Failed(Denied::new(
                format!("filter {} rejected the response: {}", args[0], err.lines().next().unwrap_or("")),
                "[[filter]]".into(),
            )));
        }
        data = out.stdout;
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf() -> Vec<u8> {
        let mut b = b"\x7fELF\x02\x01\x01".to_vec();
        b.resize(64, 0); // infer needs > 52 bytes
        b
    }

    #[test]
    fn classifies() {
        assert_eq!(classify("text/plain", &elf()), Kind::Executable("application/x-executable".into()));
        assert_eq!(classify("text/plain", b"#!/bin/sh\nrm -rf /"), Kind::Executable("text/plain".into()));
        assert_eq!(classify("application/x-sh", b"echo hi"), Kind::Executable("application/x-sh".into()));
        assert!(matches!(classify("", b"PK\x03\x04\x14\x00\x00\x00"), Kind::Archive(_)));
        assert!(matches!(classify("", b"\x1f\x8b\x08\x00\x00\x00"), Kind::Archive(_)));
        assert_eq!(classify("text/html; charset=utf-8", b"<p>hi</p>"), Kind::Text("text/html".into()));
        assert_eq!(classify("", b"<!DOCTYPE html><p>"), Kind::Text("text/html".into()));
        assert_eq!(classify("application/json", b"{}"), Kind::Text("application/json".into()));
        assert_eq!(classify("", b""), Kind::Text("text/plain".into()));
        assert_eq!(classify("", b"%PDF-1.7\n"), Kind::Binary("application/pdf".into()));
        assert_eq!(classify("image/png", b"\x89PNG\r\n\x1a\n"), Kind::Binary("image/png".into()));
        assert_eq!(classify("application/octet-stream", b"a\x00b"), Kind::Binary("application/octet-stream".into()));
    }

    #[test]
    fn sniffs_html_behind_generic_content_type() {
        assert_eq!(classify("application/octet-stream", b"<!DOCTYPE html><p>x</p>"), Kind::Text("text/html".into()));
        assert_eq!(classify("", "\u{feff}<html><p>x</p>".as_bytes()), Kind::Text("text/html".into()));
    }

    #[test]
    fn empty_body_is_text_whatever_the_content_type() {
        assert_eq!(classify("application/pdf", b""), Kind::Text("text/plain".into()));
        assert_eq!(classify("application/zip", b""), Kind::Text("text/plain".into()));
    }

    #[test]
    fn only_real_executables_are_executable() {
        let pgp = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(classify("text/plain", pgp), Kind::Text("text/plain".into()));
        assert_eq!(classify("", b"\0asm\x01\0\0\0"), Kind::Binary("application/wasm".into()));
    }

    #[test]
    fn docx_is_not_an_archive() {
        // minimal zip whose first entry is word/document.xml, which infer reads as docx
        let mut z = b"PK\x03\x04".to_vec();
        z.resize(30, 0); // local file header; the entry name starts at offset 30
        z.extend_from_slice(b"word/document.xml");
        assert!(matches!(classify("", &z), Kind::Binary(m) if m.contains("wordprocessingml")));
    }

    #[test]
    fn limits_size() {
        assert_eq!(read_limited(&b"abc"[..], 3).unwrap().unwrap(), b"abc");
        assert!(read_limited(&b"abcd"[..], 3).unwrap().is_err());
    }

    #[test]
    fn read_error_is_not_a_denial() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("connection reset"))
            }
        }
        assert!(read_limited(Broken, 3).is_err());
    }

    #[test]
    fn decodes_charset() {
        assert_eq!(decode("text/html; charset=Shift_JIS", b"\x93\xfa\x96\x7b"), "日本");
        assert_eq!(decode("text/plain", "日本".as_bytes()), "日本");
    }

    #[test]
    fn decodes_meta_charset_when_header_has_none() {
        let page = b"<html><head><meta charset=\"Shift_JIS\"></head><p>\x93\xfa\x96\x7b</p>";
        assert!(decode("text/html", page).contains("日本"));
    }

    #[test]
    fn strips_hidden_html() {
        let html = r#"<p>a</p><script>x</script><p hidden>b</p><div style="display: none">c</div><span aria-hidden="true">d</span><!-- e --><p>f</p>"#;
        assert_eq!(strip_html(html).unwrap(), "<p>a</p><p>f</p>");
    }

    #[test]
    fn drops_charset_declarations_after_decoding() {
        let html = r#"<meta charset="Shift_JIS"><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"><p>a</p>"#;
        assert_eq!(strip_html(html).unwrap(), "<p>a</p>");
    }

    #[test]
    fn ambiguous_html_is_not_blanked() {
        assert!(strip_html("<select><style>x</style></select><p>a</p>").unwrap().contains("<p>a</p>"));
    }

    #[test]
    fn runs_filter_chain() {
        let up = Filter { matches: vec!["*".into()], command: vec!["tr".into(), "a-z".into(), "A-Z".into()] };
        let rev = Filter { matches: vec!["*".into()], command: vec!["rev".into()] };
        assert_eq!(run_filters(&[&up, &rev], "text/plain", b"abc\n".to_vec()).ok().unwrap(), b"CBA\n");
        let fail = Filter { matches: vec!["*".into()], command: vec!["false".into()] };
        assert!(matches!(run_filters(&[&fail], "x", vec![]), Err(FilterError::Failed(_))));
        let missing = Filter { matches: vec!["*".into()], command: vec!["no-such-cmd-acurl".into()] };
        assert!(matches!(run_filters(&[&missing], "x", vec![]), Err(FilterError::NotFound(_))));
        let echo = Filter { matches: vec!["*".into()], command: vec!["echo".into(), "{mime}".into()] };
        assert_eq!(run_filters(&[&echo], "image/png", vec![]).ok().unwrap(), b"image/png\n");
    }

    #[test]
    fn resolves_commands_like_the_filter_runner() {
        assert!(resolve_command("sh").is_some());
        assert_eq!(resolve_command("/bin/sh"), Some(std::path::PathBuf::from("/bin/sh")));
        assert_eq!(resolve_command("no-such-acurl-cmd"), None);
        assert_eq!(resolve_command("/etc/passwd"), None); // not executable
    }

    #[test]
    fn filters_inherit_the_environment() {
        // uv/pipx/mise/pyenv installs need the user's PATH (and shims need HOME etc.)
        let sh = Filter { matches: vec!["*".into()], command: ["sh", "-c", "echo $PATH"].map(String::from).to_vec() };
        let want = format!("{}\n", std::env::var("PATH").unwrap());
        assert_eq!(run_filters(&[&sh], "x", vec![]).ok().unwrap(), want.as_bytes());
    }

    #[test]
    fn selects_filters_by_mime() {
        let cfg = Config::default();
        assert_eq!(filters_for(&cfg, "text/html").len(), 1);
        assert_eq!(filters_for(&cfg, "image/png").len(), 1);
        assert_eq!(filters_for(&cfg, "application/vnd.openxmlformats-officedocument.wordprocessingml.document").len(), 1);
        assert!(filters_for(&cfg, "audio/mpeg").is_empty());
        assert!(filters_for(&cfg, "application/json").is_empty());
    }
}
