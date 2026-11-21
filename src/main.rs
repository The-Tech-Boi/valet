//! valet: use credentials from a vault without revealing them. One binary: an MCP server on stdio (a
//! thin shim), the background agent that holds the unlocked vault, and a small CLI (`cli::USAGE`).

mod agent;
mod audit;
mod broker;
mod browser;
mod check;
mod cli;
mod cred;
mod crypto;
mod http;
mod install;
mod ipc;
mod mcp;
mod otp;
mod rdp;
mod redact;
mod run;
mod sql;
mod ssh;
mod sspi;
mod ui;
mod vault;
mod winrm;

/// NUL-terminated UTF-16, for Windows APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn main() {
    std::process::exit(cli::main(std::env::args().skip(1).collect()));
}
