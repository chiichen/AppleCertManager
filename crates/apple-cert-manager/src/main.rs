mod cli;

fn main() {
    if let Err(err) = cli::run() {
        eprintln!("apple-cert-manager: {err}");
        std::process::exit(1);
    }
}
