//! The background agent process: serves `ipc` requests and holds the `vault`, the `Broker` and the
//! `ui` handle.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::{Mutex, Notify};
use zeroize::Zeroizing;

use crate::broker::{Approval, Approver, Broker, Source};
use crate::cred::{fail, Error, Result};
use crate::ui::Ui;
use crate::vault::Vault;
use crate::{cli, ipc};

/// VALET_DIR, else %LOCALAPPDATA%\valet.
pub fn home() -> PathBuf {
    std::env::var_os("VALET_DIR").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_else(|| ".".into())).join("valet")
    })
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.into())
}

/// The DevTools endpoint of the browser browser_login uses.
pub fn cdp() -> String {
    env("VALET_CDP", "http://127.0.0.1:9333")
}

struct Agent {
    /// None if setup never ran.
    connected: Option<(Arc<Mutex<Vault>>, Broker)>,
    ui: Arc<Ui>,
    collection: String,
}

/// Serve the pipe until a request says stop.
pub async fn run() -> anyhow::Result<()> {
    let mut server = ipc::listen(true)?; // fails if another agent already serves the pipe
    let home = home();
    let ui = Arc::new(Ui::start());
    let vault = match Vault::load(&home)? {
        Some(v) => Some(v),
        None => cli::setup(ui.clone(), &home).await, // the request that started us waits on the pipe
    };
    let collection = env("VALET_COLLECTION", "Agent");
    let approver: Approver = {
        let ui = ui.clone();
        Arc::new(move |a: &Approval| ui.approve(a))
    };
    let connected = vault.map(|v| {
        let v = Arc::new(Mutex::new(v));
        let broker = Broker::new(Source::Vault(v.clone(), collection.clone()), approver, home, cdp());
        (v, broker)
    });
    let agent = Arc::new(Agent { connected, ui, collection });
    let stop = Arc::new(Notify::new());
    loop {
        tokio::select! {
            r = server.connect() => r?,
            _ = stop.notified() => return Ok(()),
        }
        let client = std::mem::replace(&mut server, ipc::listen(false)?);
        let (agent, stop) = (agent.clone(), stop.clone());
        tokio::spawn(async move {
            if agent.serve(client).await {
                stop.notify_one();
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
        let (resp, stop) = match (req["op"].as_str().unwrap_or(""), &self.connected) {
            ("stop", _) => (json!({"status": "stopped"}), true),
            // stop, so the next request starts an agent that sees the login
            (_, None) => (json!({"error": "valet is not connected to a vault; run `valet setup`"}), true),
            (op, Some((vault, broker))) => {
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
                let resolved = broker.resolve(refs, req["what"].as_str().unwrap_or(""), caller).await?;
                serde_json::to_value(&resolved).map_err(fail)
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
