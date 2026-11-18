//! Story 12.16 feasibility spike: live transfer of TCP passthrough
//! connections and UDP sessions between two processes.
//!
//! `spike harness [--key value]...` runs backends and clients, starts
//! generation 0 of the proxy and checks the outcome. `spike proxy` is one
//! generation; the harness and each generation start it themselves.
//! `run-all.sh` names the scenarios; the method and the results are in
//! `docs/stories/story-12.16-live-transfer.md`, "Spike outcome".

mod chan;
mod harness;
mod proxy;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("proxy") => proxy::main(&args[2..]),
        Some("harness") => harness::main(&args[2..]),
        _ => {
            eprintln!("usage: spike (harness|proxy) [--key value]...");
            std::process::exit(2);
        }
    }
}
