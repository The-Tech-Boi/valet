//! CLI dispatch and the background agent process (owner: core).
//! The agent serves `ipc` requests, holds the `vault`, the `Broker` and the `ui` handle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::broker::{Approver, Broker, Source};
use crate::cred::{fail, Error, Result};
use crate::ui::Ui;
use crate::vault::Vault;
use crate::{browser, install, ipc, mcp, run};

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

/// VALET_DIR, else %LOCALAPPDATA%\valet.
pub fn home() -> PathBuf {
    std::env::var_os("VALET_DIR").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_else(|| ".".into())).join("valet")
    })
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.into())
}

fn cdp() -> String {
    env("VALET_CDP", "http://127.0.0.1:9333")
}

pub fn cli(args: Vec<String>) -> i32 {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [] => {
            let call = |tool: &str, args: Value| {
                ipc::send(&json!({"op": "call", "tool": tool, "args": args}), true)
                    .unwrap_or_else(|e| json!({"error": format!("valet agent: {e:#}")}))
            };
            mcp::serve(std::io::stdin().lock(), std::io::stdout().lock(), call).map_or(1, |_| 0)
        }
        ["agent"] => match tokio::runtime::Runtime::new().map_err(anyhow::Error::from).and_then(|rt| rt.block_on(agent())) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("valet agent: {e:#}");
                1
            }
        },
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

/// Setup window until a sign-in works; None if the user cancels.
async fn setup(ui: Arc<Ui>, home: &Path) -> Option<Vault> {
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

struct Agent {
    /// None if `valet login` never ran.
    vault: Option<Arc<Mutex<Vault>>>,
    broker: Option<Broker>,
    ui: Arc<Ui>,
    collection: String,
}

async fn agent() -> anyhow::Result<()> {
    let mut server = ipc::listen(true)?; // fails if another agent already serves the pipe
    let home = home();
    let ui = Arc::new(Ui::start());
    let vault = match Vault::load(&home)? {
        Some(v) => Some(v),
        None => setup(ui.clone(), &home).await, // the request that started us waits on the pipe
    };
    let vault = vault.map(|v| Arc::new(Mutex::new(v)));
    let collection = env("VALET_COLLECTION", "Agent");
    let approver: Approver = {
        let ui = ui.clone();
        Arc::new(move |a: &crate::broker::Approval| ui.approve(a))
    };
    let broker = vault.as_ref().map(|v| Broker::new(Source::Vault(v.clone(), collection.clone()), approver, home, cdp()));
    let agent = Arc::new(Agent { vault, broker, ui, collection });
    loop {
        server.connect().await?;
        let client = std::mem::replace(&mut server, ipc::listen(false)?);
        let agent = agent.clone();
        tokio::spawn(async move {
            let stop = agent.serve(client).await;
            if stop {
                std::process::exit(0);
            }
        });
    }
}

impl Agent {
    /// One request, one answer. True if the agent should exit afterwards.
    async fn serve(&self, pipe: NamedPipeServer) -> bool {
        let caller = ipc::caller(&pipe);
        let (r, mut w) = tokio::io::split(pipe);
        let mut line = String::new();
        if tokio::io::BufReader::new(r).read_line(&mut line).await.is_err() {
            return false;
        }
        let req: Value = serde_json::from_str(&line).unwrap_or_default();
        let (resp, stop) = match (req["op"].as_str().unwrap_or(""), &self.vault, &self.broker) {
            ("stop", _, _) => (json!({"status": "stopped"}), true),
            // exit, so the next request starts an agent that sees the login
            (_, None, _) | (_, _, None) => (json!({"error": "valet is not connected to a vault; run `valet setup`"}), true),
            (op, Some(vault), Some(broker)) => {
                let resp = self.handle(op, &req, vault, broker, &caller).await;
                (resp.unwrap_or_else(|e| json!({"error": e.to_string()})), false)
            }
        };
        let text = Zeroizing::new(format!("{resp}\n")); // a resolve answer carries secrets
        let _ = w.write_all(text.as_bytes()).await;
        let _ = w.flush().await;
        stop
    }

    async fn handle(&self, op: &str, req: &Value, vault: &Mutex<Vault>, broker: &Broker, caller: &str) -> Result<Value> {
        match op {
            "status" => {
                let v = vault.lock().await;
                if !v.is_unlocked() {
                    return Ok(json!({"status": "locked"}));
                }
                Ok(json!({"status": "unlocked", "items": v.creds(&self.collection)?.len()}))
            }
            "lock" => {
                vault.lock().await.lock();
                Ok(json!({"status": "locked"}))
            }
            "unlock" => self.unlock(vault).await.map(|_| json!({"status": "unlocked"})),
            "call" => {
                self.unlock(vault).await?;
                let tool = req["tool"].as_str().unwrap_or("");
                Ok(broker.call(tool, req["args"].clone(), caller).await)
            }
            "resolve" => {
                let refs: BTreeMap<String, String> = serde_json::from_value(req["refs"].clone()).map_err(fail)?;
                self.unlock(vault).await?;
                let (values, secrets) = broker.resolve(refs, req["what"].as_str().unwrap_or(""), caller).await?;
                let values: BTreeMap<&str, &str> = values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                Ok(json!({"values": values, "secrets": secrets}))
            }
            _ => Err(Error::Refused(format!("unknown op {op:?}"))),
        }
    }

    /// Ask the master password (up to 3 tries) if the vault is locked.
    async fn unlock(&self, vault: &Mutex<Vault>) -> Result<()> {
        let mut v = vault.lock().await; // held while asking: concurrent callers wait for this unlock
        let mut error: Option<String> = None;
        for _ in 0..3 {
            if v.is_unlocked() {
                return Ok(());
            }
            let (ui, email, shown) = (self.ui.clone(), v.email().to_string(), error.clone());
            let password = tokio::task::spawn_blocking(move || ui.master_password(&email, shown.as_deref()))
                .await
                .map_err(fail)?
                .ok_or_else(|| Error::Denied("unlock cancelled".into()))?;
            if let Err(e) = v.unlock(&password).await {
                error = Some(fail(e).to_string());
            }
        }
        if v.is_unlocked() {
            return Ok(());
        }
        Err(Error::Failed(format!("vault not unlocked: {}", error.unwrap_or_default())))
    }
}
