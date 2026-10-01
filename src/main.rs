mod output;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("prompt") {
        print!("{}", output::PROMPT);
    }
}
