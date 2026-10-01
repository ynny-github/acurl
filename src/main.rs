mod config;
mod inbound;
mod outbound;
mod output;

use clap::Parser;
use config::Config;
use inbound::{FilterError, Kind};
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, LOCATION};
use reqwest::redirect::Policy;
use reqwest::{Method, StatusCode, Url};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// A policy denial: what was refused and which setting would allow it.
#[derive(Debug)]
pub struct Denied {
    pub reason: String,
    pub hint: String,
}

impl Denied {
    pub fn new(reason: String, hint: String) -> Self {
        Denied { reason, hint }
    }
}

enum Error {
    Denied(Denied),
    Other(String),
}

impl From<Denied> for Error {
    fn from(d: Denied) -> Self {
        Error::Denied(d)
    }
}

impl<E: std::fmt::Display> From<E> for Error where E: std::error::Error {
    fn from(e: E) -> Self {
        Error::Other(e.to_string())
    }
}

/// HTTP client for AI agents: a curl subset with content-based policy.
/// Subcommands: `acurl prompt` (text for the agent's system prompt), `sudo acurl trust`.
#[derive(Parser)]
#[command(name = "acurl", version)]
struct Args {
    /// HTTP method
    #[arg(short = 'X')]
    request: Option<String>,
    /// Header "Name: value" (repeatable)
    #[arg(short = 'H')]
    header: Vec<String>,
    /// Request body, or @file
    #[arg(short = 'd')]
    data: Option<String>,
    /// Save to file instead of stdout
    #[arg(short = 'o')]
    output: Option<PathBuf>,
    /// Include status line and headers in the output
    #[arg(short = 'i')]
    include: bool,
    /// Follow redirects (max 10)
    #[arg(short = 'L')]
    location: bool,
    url: String,
}

enum Out {
    Raw(Vec<u8>),
    Text(String),
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    match argv.get(1).map(String::as_str) {
        Some("prompt") => {
            print!("{}", output::PROMPT);
            return 0;
        }
        Some("trust") => {
            return match config::trust(&cwd) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("acurl: {e}");
                    1
                }
            }
        }
        _ => {}
    }
    let args = match Args::try_parse_from(&argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { 64 } else { 0 };
        }
    };
    let cfg = match config::load(&cwd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("acurl: {e}");
            return 1;
        }
    };
    match fetch(&args, &cfg) {
        Ok(code) => code,
        Err(Error::Denied(d)) => {
            eprintln!("acurl: denied: {} ({})", d.reason, d.hint);
            2
        }
        Err(Error::Other(e)) => {
            eprintln!("acurl: {e}");
            1
        }
    }
}

fn fetch(args: &Args, cfg: &Config) -> Result<i32, Error> {
    let mut url = Url::parse(&args.url)?;
    let mut body = match &args.data {
        None => vec![],
        Some(d) => match d.strip_prefix('@') {
            Some(path) => std::fs::read(path)?,
            None => d.clone().into_bytes(),
        },
    };
    let default_method = if args.data.is_some() { "POST" } else { "GET" };
    let mut method = args.request.as_deref().unwrap_or(default_method).to_ascii_uppercase();
    let headers = args
        .header
        .iter()
        .map(|h| {
            h.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .ok_or(Error::Other(format!("bad header (want \"Name: value\"): {h}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let client = Client::builder().redirect(Policy::none()).timeout(Duration::from_secs(30)).build()?;

    let mut hops = 0;
    let resp = loop {
        outbound::check_method(cfg, &method, &url)?;
        let parts = outbound::request_parts(&url, &headers, &body);
        outbound::check_secrets(&parts.iter().map(String::as_str).collect::<Vec<_>>())?;
        let mut req = client.request(Method::from_bytes(method.as_bytes())?, url.clone());
        for (k, v) in &headers {
            req = req.header(k, v);
        }
        if !body.is_empty() {
            req = req.body(body.clone());
        }
        let resp = req.send()?;
        let next = resp.headers().get(LOCATION).and_then(|l| l.to_str().ok()).and_then(|l| url.join(l).ok());
        match next {
            Some(next) if args.location && resp.status().is_redirection() => {
                hops += 1;
                if hops > 10 {
                    return Err(Error::Other("too many redirects".into()));
                }
                outbound::check_redirect(&method, &url, &next)?;
                if resp.status() == StatusCode::SEE_OTHER {
                    method = "GET".into();
                    body.clear();
                }
                url = next;
            }
            _ => break resp,
        }
    };

    let status = resp.status();
    let ct = resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let mut head = format!("{:?} {status}\n", resp.version());
    for (k, v) in resp.headers() {
        head += &format!("{k}: {}\n", String::from_utf8_lossy(v.as_bytes()));
    }
    let raw = inbound::read_limited(resp, cfg.max_response_bytes)?;
    let code = if status.is_client_error() || status.is_server_error() {
        eprintln!("acurl: HTTP {status}");
        1
    } else {
        0
    };
    match render(cfg, &ct, raw)? {
        Out::Raw(bytes) => match &args.output {
            Some(p) => std::fs::write(p, bytes)?,
            None => std::io::stdout().write_all(&bytes)?,
        },
        Out::Text(text) => {
            let text = if args.include { format!("{head}\n{text}") } else { text };
            match &args.output {
                Some(p) => std::fs::write(p, output::strip_invisible(&text))?,
                None => print!("{}", output::finish(&text, url.as_str(), cfg.max_output_bytes)),
            }
        }
    }
    Ok(code)
}

/// Turn a response body into what the agent may see, or deny it.
fn render(cfg: &Config, ct: &str, raw: Vec<u8>) -> Result<Out, Error> {
    match inbound::classify(ct, &raw) {
        Kind::Executable(m) => {
            Err(Denied::new(format!("executable content ({m})"), "executables are always denied".into()).into())
        }
        Kind::Binary(m) if cfg.allow_binary.contains(&m) => Ok(Out::Raw(raw)),
        Kind::Text(m) => {
            let mut text = inbound::decode(ct, &raw);
            if m == "text/html" || m == "application/xhtml+xml" {
                text = inbound::strip_html(&text);
            }
            let filters = inbound::filters_for(cfg, &m);
            if filters.is_empty() {
                return Ok(Out::Text(text));
            }
            match inbound::run_filters(&filters, &m, text.clone().into_bytes()) {
                Ok(o) => Ok(Out::Text(String::from_utf8_lossy(&o).into_owned())),
                Err(FilterError::NotFound(cmd)) => {
                    eprintln!("acurl: warning: {cmd} not found; returning unconverted text");
                    Ok(Out::Text(text))
                }
                Err(FilterError::Failed(d)) => Err(d.into()),
            }
        }
        Kind::Archive(m) | Kind::Binary(m) => {
            let filters = inbound::filters_for(cfg, &m);
            if filters.is_empty() {
                return Err(Denied::new(
                    format!("binary content ({m})"),
                    format!("allow_binary = [\"{m}\"] or a [[filter]] matching {m}; archives only via [[filter]]"),
                )
                .into());
            }
            match inbound::run_filters(&filters, &m, raw) {
                Ok(o) => Ok(Out::Text(String::from_utf8_lossy(&o).into_owned())),
                Err(FilterError::NotFound(cmd)) => Err(Denied::new(
                    format!("{m} needs converter `{cmd}`, which is not installed"),
                    format!("install {cmd} or change [[filter]]"),
                )
                .into()),
                Err(FilterError::Failed(d)) => Err(d.into()),
            }
        }
    }
}
