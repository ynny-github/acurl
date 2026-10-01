mod config;
mod inbound;
mod outbound;
mod output;

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

fn main() {
    if std::env::args().nth(1).as_deref() == Some("prompt") {
        print!("{}", output::PROMPT);
    }
}
