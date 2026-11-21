//! valet: use credentials from a vault without revealing them.
//!
//! One binary, several roles:
//!   valet                 MCP server on stdio (a thin shim; the agent does the work)
//!   valet agent           background process: holds the unlocked vault, asks approval, signs in
//!   valet install         copy valet to %LOCALAPPDATA%\Programs\valet, add it to PATH, then setup
//!   valet uninstall       undo install (the login in %LOCALAPPDATA%\valet stays)
//!   valet setup           connect to the vault: URL and personal API key (a window)
//!   valet unlock | lock   unlock (asks the master password) or lock the agent
//!   valet status          locked/unlocked, item count
//!   valet stop            stop the background agent
//!   valet run [-e NAME=valet://ITEM/FIELD] [--env-file F] -- COMMAND...
//!   valet rdp ITEM [HOST] Remote Desktop, signed in
//!   valet check [ITEM...] try every item's sign-in
//!   valet browser         start Edge/Chrome with the CDP port browser_login uses

mod agent;
mod audit;
mod broker;
mod browser;
mod cred;
mod crypto;
mod http;
mod install;
mod ipc;
mod mcp;
mod rdp;
mod run;
mod sql;
mod ssh;
mod sspi;
mod ui;
mod vault;
mod winrm;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(agent::cli(args));
}
