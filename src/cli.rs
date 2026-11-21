//! The command line: every role and command of the one binary.

use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::agent::{cdp, home};
use crate::cred::fail;
use crate::ui::Ui;
use crate::vault::Vault;
use crate::{agent, browser, install, ipc, mcp, run};

const USAGE: &str = "usage:
  valet                 MCP server on stdio
  valet install         copy valet to %LOCALAPPDATA%\\Programs\\valet, add it to PATH, then setup
  valet uninstall       undo install (your login in %LOCALAPPDATA%\\valet stays)
  valet setup           connect to the vault: URL and personal API key (a window)
  valet unlock | lock   unlock (asks the master password) or lock the agent
  valet status          locked/unlocked, item count
  valet stop            stop the background agent
  valet run [-e NAME=valet://ITEM/FIELD] [--env-file F] -- COMMAND...
  valet rdp ITEM [HOST] Remote Desktop, signed in
  valet check [ITEM...] try every item's sign-in
  valet browser         start Edge/Chrome with the CDP port browser_login uses";

/// Exit code.
pub fn main(args: Vec<String>) -> i32 {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [] => {
            let call = |tool: &str, args: Value| {
                ipc::send(&json!({"op": "call", "tool": tool, "args": args}), true)
                    .unwrap_or_else(|e| json!({"error": format!("valet agent: {e:#}")}))
            };
            mcp::serve(std::io::stdin().lock(), std::io::stdout().lock(), call).map_or(1, |_| 0)
        }
        ["agent"] => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => return fail_with(e),
            };
            let result = rt.block_on(agent::run());
            rt.shutdown_background(); // an approval window still open must not hold up the exit
            match result {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("valet agent: {e:#}");
                    1
                }
            }
        }
        ["install"] => {
            let _ = ipc::send(&json!({"op": "stop"}), false); // the agent may run the exe being replaced
            let exe = match install::install() {
                Ok(exe) => exe,
                Err(e) => return fail_with(format!("{e:#}")),
            };
            println!("Installed {}; open a new terminal to use `valet` there.", exe.display());
            println!("MCP clients: register a stdio server with the command {}", exe.display());
            if matches!(Vault::load(&home()), Ok(Some(_))) { 0 } else { connect() }
        }
        ["uninstall"] => {
            let _ = ipc::send(&json!({"op": "stop"}), false);
            match install::uninstall() {
                Ok(()) => {
                    println!("Removed {} and its PATH entry. Your login stays in {}.", install::dir().display(), home().display());
                    0
                }
                Err(e) => fail_with(format!("{e:#}")),
            }
        }
        ["setup"] => connect(),
        ["browser"] => browser::start(&cdp(), &home()).map_or_else(fail_with, |_| 0),
        ["run", ..] => run::main(&args[1..]),
        ["rdp", item] | ["rdp", item, _] => {
            let host = a.get(2);
            print_call(json!({"op": "call", "tool": "rdp_open", "args": {"credential": item, "host": host}}))
        }
        ["check", items @ ..] => {
            let names = if items.is_empty() { Value::Null } else { json!(items) };
            let r = match ipc::send(&json!({"op": "call", "tool": "check_credentials", "args": {"credentials": names}}), true) {
                Ok(r) => r,
                Err(e) => return fail_with(e),
            };
            for x in r["results"].as_array().into_iter().flatten() {
                let s = |k: &str| x[k].as_str().unwrap_or("").to_string();
                println!("{:8} {}  {}  {}", s("result"), s("credential"), s("uri"), s("detail"));
            }
            println!("{}", if r["summary"].is_null() { &r["error"] } else { &r["summary"] });
            i32::from(r.get("error").is_some())
        }
        [op @ ("unlock" | "lock" | "status" | "stop")] => match ipc::send(&json!({"op": op}), *op == "unlock") {
            Ok(r) if r.get("error").is_some() => fail_with(r["error"].as_str().unwrap_or("")),
            Ok(r) => {
                let items = r.get("items").map(|n| format!(", {n} items")).unwrap_or_default();
                println!("{}{items}", r["status"].as_str().unwrap_or(""));
                0
            }
            Err(_) if *op != "unlock" => {
                println!("{}", if *op == "status" { "not running" } else { "not running (locked)" });
                0
            }
            Err(e) => fail_with(e),
        },
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}

/// `valet setup`: the setup window, then the unlock window from a fresh agent.
fn connect() -> i32 {
    let vault = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt.block_on(setup(Arc::new(Ui::start()), &home())),
        Err(e) => return fail_with(e),
    };
    let Some(vault) = vault else { return fail_with("setup cancelled") };
    println!("Signed in as {}.", vault.email());
    let _ = ipc::send(&json!({"op": "stop"}), false); // a running agent still has the old login
    print_call(json!({"op": "unlock"}))
}

/// Setup window until a sign-in works; None if the user cancels. Also run by an agent started
/// before setup ever ran.
pub async fn setup(ui: Arc<Ui>, home: &Path) -> Option<Vault> {
    let mut server = Vault::load(home).ok().flatten().map(|v| v.server().to_string()).unwrap_or_default();
    let (mut client_id, mut error) = (String::new(), None::<String>);
    loop {
        let (ui, s, c) = (ui.clone(), server.clone(), client_id.clone());
        let key = tokio::task::spawn_blocking(move || ui.api_key(&s, &c, error.as_deref())).await.ok()??;
        match Vault::sign_in(home, &key.server, &key.client_id, key.client_secret).await {
            Ok(vault) => return Some(vault),
            Err(e) => (server, client_id, error) = (key.server, key.client_id, Some(fail(e).to_string())),
        }
    }
}

fn fail_with(e: impl std::fmt::Display) -> i32 {
    eprintln!("valet: {e}");
    1
}

fn print_call(req: Value) -> i32 {
    match ipc::send(&req, true) {
        Ok(r) => {
            println!("{r}");
            i32::from(r.get("error").is_some())
        }
        Err(e) => fail_with(e),
    }
}
