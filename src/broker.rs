//! The policy core. Every tool call goes through `Broker::call`: find the credential (only items in
//! the agent's collection exist), check the target is allowed, ask approval per the item's policy,
//! run the driver, audit, and redact every secret of that credential from the result.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{Local, NaiveDate};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::audit;
use crate::cred::{Cred, Endpoint, Error, Policy, Result, Tool};
use crate::otp::totp_now;
use crate::redact::{scrub, secrets, Redactor};
use crate::run::Resolved;
use crate::vault::Vault;
use crate::{browser, http, rdp, sql, ssh, winrm};

/// What the approval window shows. `detail` is the command, query or "GET /path".
#[derive(Debug, Clone)]
pub struct Approval {
    pub credential: String,
    pub username: String,
    pub tool: String,
    pub target: String,
    pub detail: String,
    /// Process that called valet, e.g. "code.exe (pid 1234)". Taken from the pipe client, not trusted input.
    pub caller: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Today,
    Once,
    Deny,
}

/// Blocking approval prompt (the agent passes `ui.approve`); the broker runs it on a blocking thread.
pub type Approver = Arc<dyn Fn(&Approval) -> Answer + Send + Sync>;

/// Optional argument; missing and null are None.
pub(crate) fn opt<T: DeserializeOwned>(args: &Value, name: &str) -> Result<Option<T>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|e| Error::Refused(format!("argument {name}: {e}"))),
    }
}

fn req<T: DeserializeOwned>(args: &Value, name: &str) -> Result<T> {
    opt(args, name)?.ok_or_else(|| Error::Refused(format!("missing argument {name}")))
}

fn secs(t: f64) -> Duration {
    Duration::from_secs_f64(t.clamp(0.0, 86_400.0))
}

/// host and path of a URL (no query: it may carry a key), for audit and approval.
fn host_path(url: &str) -> (String, String) {
    Url::parse(url).map(|u| (u.host_str().unwrap_or("").to_string(), u.path().to_string())).unwrap_or_default()
}

/// Where a single-credential call goes: a URL for the web tools, one of the item's endpoints otherwise.
enum Target {
    Url(String),
    Server(Endpoint),
}

impl Target {
    fn of(tool: Tool, c: &Cred, args: &Value) -> Result<Target> {
        Ok(match tool {
            Tool::HttpRequest => Target::Url(req(args, "url")?),
            Tool::BrowserLogin => Target::Url(opt(args, "url")?.or_else(|| c.uris.first().cloned()).unwrap_or_default()),
            _ => Target::Server(c.endpoint(tool.schemes(), opt::<String>(args, "host")?.as_deref())?),
        })
    }

    /// The audit log's method and target.
    fn audit(&self, tool: Tool, args: &Value) -> (String, String) {
        match self {
            Target::Url(url) => {
                let method = if tool == Tool::BrowserLogin { "LOGIN" } else { args["method"].as_str().unwrap_or("") };
                let (host, path) = host_path(url);
                (method.to_uppercase(), host + &path)
            }
            Target::Server(ep) => (tool.schemes()[0].to_uppercase(), ep.to_string()),
        }
    }
}

/// Where the credentials come from: the agent's vault, or a fixed list (tests).
pub enum Source {
    Vault(Arc<tokio::sync::Mutex<Vault>>, String),
    #[cfg(test)]
    Fixed(Vec<Cred>),
}

/// The day the user answered "today" for one (credential, tool). Locked while asking, so a
/// concurrent call for the same key waits for that answer instead of opening a second window.
type Today = Arc<tokio::sync::Mutex<Option<NaiveDate>>>;

pub struct Broker {
    source: Source,
    approver: Approver,
    pub(crate) home: PathBuf,
    cdp: String,
    /// (credential id, tool) -> its "today" answer.
    approved: Mutex<HashMap<(String, Tool), Today>>,
}

impl Broker {
    pub fn new(source: Source, approver: Approver, home: PathBuf, cdp: String) -> Broker {
        Broker { source, approver, home, cdp, approved: Mutex::default() }
    }

    pub(crate) async fn creds(&self, sync: bool) -> Result<Vec<Cred>> {
        match &self.source {
            #[cfg(test)]
            Source::Fixed(c) => Ok(c.clone()),
            Source::Vault(v, collection) => {
                // The vault stays locked during the sync: fetching refreshes its token, which needs the
                // vault's API key; a cache miss is rare and the request times out after 30 s.
                let mut v = v.lock().await;
                if sync {
                    v.sync().await?;
                }
                Ok(v.creds(collection)?)
            }
        }
    }

    /// By name or id; on a miss, sync once (maybe added since) and retry.
    async fn find(&self, r: &str) -> Result<Cred> {
        for sync in [false, true] {
            let mut found: Vec<Cred> = self.creds(sync).await?.into_iter().filter(|c| c.id == r || c.name == r).collect();
            if found.len() > 1 {
                return Err(Error::Refused(format!("{} credentials are named {r:?}; pass the id instead", found.len())));
            }
            if let Some(c) = found.pop() {
                return Ok(c);
            }
        }
        Err(Error::Refused(format!("no credential {r:?} in the broker collection; call list_credentials")))
    }

    pub(crate) async fn ask(&self, a: Approval) -> Answer {
        let f = self.approver.clone();
        tokio::task::spawn_blocking(move || f(&a)).await.unwrap_or(Answer::Deny)
    }

    async fn approve(&self, cred: &Cred, tool: Tool, target: &str, detail: &str, caller: &str) -> Result<()> {
        let policy = cred.approval(tool)?;
        if policy == Policy::Never {
            return Ok(());
        }
        let ask = || {
            self.ask(Approval {
                credential: cred.name.clone(),
                username: cred.username.clone(),
                tool: tool.name().into(),
                target: target.into(),
                detail: detail.into(),
                caller: caller.into(),
            })
        };
        let denied = || Error::Denied(format!("the user denied {} with credential {:?} on {target}", tool.name(), cred.name));
        if policy == Policy::Always {
            return if ask().await == Answer::Deny { Err(denied()) } else { Ok(()) };
        }
        let slot = self.approved.lock().unwrap().entry((cred.id.clone(), tool)).or_default().clone();
        let mut day = slot.lock().await;
        let today = Local::now().date_naive();
        if *day == Some(today) {
            return Ok(());
        }
        match ask().await {
            Answer::Deny => Err(denied()),
            Answer::Today => {
                *day = Some(today);
                Ok(())
            }
            Answer::Once => Ok(()),
        }
    }

    /// Run one MCP tool call and return the JSON result (or {"error": ...}), already redacted and audited.
    pub async fn call(&self, tool: &str, args: Value, caller: &str) -> Value {
        let out = match tool {
            "list_credentials" => self.list().await,
            "check_credentials" => self.check(&args, caller).await,
            _ => match Tool::parse(tool).filter(|t| *t != Tool::Run) {
                Some(t) => return self.with_cred(t, &args, caller).await,
                None => Err(Error::Refused(format!("unknown tool {tool:?}"))),
            },
        };
        out.unwrap_or_else(|e| json!({"error": e.to_string()}))
    }

    /// The single-credential tools: find, run, audit, redact.
    async fn with_cred(&self, tool: Tool, args: &Value, caller: &str) -> Value {
        let mut entry = audit::Entry {
            tool: tool.name().into(),
            credential: args["credential"].as_str().unwrap_or("").into(),
            ..Default::default()
        };
        let mut redact = Redactor::default();
        let out = async {
            let c = self.find(&req::<String>(args, "credential")?).await?;
            (entry.credential, redact) = (c.name.clone(), Redactor::for_cred(&c));
            let target = Target::of(tool, &c, args)?;
            let (method, shown) = target.audit(tool, args);
            (entry.method, entry.target) = (Some(method), Some(shown));
            self.op(tool, &c, args, target, caller).await
        }
        .await;
        entry.result = match &out {
            Ok(v) => v.get("status").cloned().unwrap_or_default(),
            Err(e) => e.kind().into(),
        };
        audit::write(&self.home, entry, &redact);
        scrub(out.unwrap_or_else(|e| json!({"error": e.to_string()})), &redact)
    }

    /// Check `target` against the item, ask approval, run the driver.
    async fn op(&self, tool: Tool, c: &Cred, args: &Value, target: Target, caller: &str) -> Result<Value> {
        match target {
            Target::Url(url) if tool == Tool::HttpRequest => {
                c.check_url(&url)?;
                c.http_auth()?;
                let (host, path) = host_path(&url);
                let request = http::Request {
                    method: req::<String>(args, "method")?.to_uppercase(),
                    headers: opt(args, "headers")?.unwrap_or_default(),
                    body: opt(args, "body")?,
                    json: opt(args, "json")?,
                    timeout: secs(opt(args, "timeout")?.unwrap_or(30.0)),
                    url,
                };
                self.approve(c, tool, &host, &format!("{} {path}", request.method), caller).await?;
                http::request(c, request).await
            }
            Target::Url(url) => {
                c.browser_auth()?;
                c.check_url(&url)?;
                let explicit = opt::<String>(args, "url")?.is_some();
                let (host, path) = host_path(&url);
                self.approve(c, tool, &host, &format!("sign in at {path}"), caller).await?;
                browser::login(c, &url, explicit, &self.cdp).await
            }
            Target::Server(ep) => {
                let detail: String = match tool {
                    Tool::SshExec | Tool::WinExec => req(args, "command")?,
                    Tool::SqlQuery => req(args, "query")?,
                    _ => String::new(),
                };
                let timeout = secs(opt(args, "timeout")?.unwrap_or(60.0));
                let (database, max_rows) = (opt::<String>(args, "database")?, opt(args, "max_rows")?.unwrap_or(200));
                self.approve(c, tool, &ep.to_string(), &detail, caller).await?;
                match tool {
                    Tool::SshExec => ssh::exec(c, &ep, Some(&detail), timeout).await,
                    Tool::WinExec => winrm::exec(c, &ep, &detail, timeout).await,
                    Tool::SqlQuery => sql::query(c, &ep, &detail, database.as_deref(), max_rows, timeout).await,
                    _ => rdp::open(c, &ep),
                }
            }
        }
    }

    async fn list(&self) -> Result<Value> {
        let out: Vec<Value> = self
            .creds(false)
            .await?
            .iter()
            .map(|c| {
                let hosts = c.hosts();
                let approval = |t: Tool| c.approval(t).map_or_else(|e| e.to_string(), |p| p.name().to_string());
                let mut tools = Map::new();
                for (t, usable) in [(Tool::HttpRequest, c.http_auth().is_ok()), (Tool::BrowserLogin, c.browser_auth().is_ok())] {
                    if usable && !hosts.is_empty() {
                        tools.insert(t.name().into(), json!({"auth": c.auth(t), "approval": approval(t)}));
                    }
                }
                let endpoints = c.endpoints();
                for t in Tool::ALL {
                    let targets: Vec<String> =
                        endpoints.iter().filter(|e| t.schemes().contains(&e.scheme.as_str())).map(Endpoint::to_string).collect();
                    if !targets.is_empty() {
                        tools.insert(t.name().into(), json!({"approval": approval(t), "targets": targets}));
                    }
                }
                json!({"name": c.name, "id": c.id, "hosts": hosts, "tools": tools, "totp": !c.totp.is_empty()})
            })
            .collect();
        Ok(json!({"credentials": out}))
    }

    /// For `valet run`: resolve NAME -> valet://item/field, one approval per item, with every secret
    /// of those items to redact from the command's output.
    pub async fn resolve(&self, refs: BTreeMap<String, String>, what: &str, caller: &str) -> Result<Resolved> {
        let mut creds: Vec<(String, Cred)> = Vec::new(); // (reference used, item)
        let out = async {
            let mut resolved = Resolved::default();
            for (env, r) in &refs {
                let (item, field) = r
                    .strip_prefix("valet://")
                    .and_then(|rest| rest.rsplit_once('/'))
                    .filter(|(i, f)| !i.is_empty() && !f.is_empty())
                    .ok_or_else(|| Error::Refused(format!("{env}: expected valet://<item>/<field>, got {r:?}")))?;
                if !creds.iter().any(|(i, _)| i == item) {
                    creds.push((item.to_string(), self.find(item).await?));
                    self.approve(&creds[creds.len() - 1].1, Tool::Run, "this computer", what, caller).await?;
                }
                let c = &creds.iter().find(|(i, _)| i == item).expect("pushed above").1;
                let f = field.to_lowercase();
                let value = match f.as_str() {
                    "password" => c.password.clone(),
                    "username" => Zeroizing::new(c.username.clone()),
                    "uri" => Zeroizing::new(c.uris.first().cloned().unwrap_or_default()),
                    "totp" => totp_now(&c.totp).unwrap_or_default(),
                    _ => c.fields.get(&f).cloned().ok_or_else(|| {
                        Error::Refused(format!("{env}: item {:?} has no field {field:?}", c.name))
                    })?,
                };
                let mut s = secrets(c);
                if f != "username" && f != "uri" {
                    s.push(value.clone());
                }
                resolved.secrets.push((c.name.clone(), s));
                resolved.values.insert(env.clone(), value);
            }
            Ok(resolved)
        }
        .await;
        let names: Vec<&str> = creds.iter().map(|(_, c)| c.name.as_str()).collect();
        let entry = audit::Entry {
            tool: Tool::Run.name().into(),
            credential: if names.is_empty() { "-".into() } else { names.join(", ") },
            target: Some(what.chars().take(200).collect()),
            result: out.as_ref().map_or_else(Error::kind, |_| "ok").into(),
            ..Default::default()
        };
        let named: Vec<_> = creds.iter().map(|(_, c)| (c.name.clone(), secrets(c))).collect();
        audit::write(&self.home, entry, &Redactor::new(&named));
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cred::tests::{PASSWORD, SEED, TOKEN};
    use base64::Engine;

    /// Records every approval asked and answers with `answer`.
    pub fn approver(answer: Answer) -> (Approver, Arc<Mutex<Vec<Approval>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        (Arc::new(move |a: &Approval| {
            seen.lock().unwrap().push(a.clone());
            answer
        }), calls)
    }

    pub fn broker(creds: Vec<Cred>, answer: Answer, home: &std::path::Path) -> (Broker, Arc<Mutex<Vec<Approval>>>) {
        let (a, calls) = approver(answer);
        (Broker::new(Source::Fixed(creds), a, home.to_path_buf(), "http://127.0.0.1:1".into()), calls)
    }

    pub fn temp_home(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("valet-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    pub fn assert_clean(text: &str) {
        let b64 = base64::engine::general_purpose::STANDARD.encode(format!("svc-user:{PASSWORD}"));
        for s in [TOKEN, PASSWORD, "P%40ss-test-456", SEED, &b64] {
            assert!(!text.contains(s), "secret leaked: {text}");
        }
    }

    pub fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    pub fn items() -> Vec<Cred> {
        vec![
            Cred::test("api-bearer", &["https://api.test"], TOKEN, &[]),
            Cred::test("api-daily", &["https://api.test"], TOKEN, &[("broker_approval", "daily")]),
            Cred::test("api-always", &["https://api.test"], TOKEN, &[("broker_approval", "always")]),
            Cred::test("web-plain", &["https://web.test/login"], PASSWORD, &[("broker_auth", "form")]),
            Cred::test("api-basic", &["https://api.test"], PASSWORD, &[("broker_auth", "basic")]),
            Cred::test("remote", &["https://api.example.com", "https://*.example.org/x"], TOKEN, &[]),
            Cred::test("box", &["ssh://127.0.0.1:2222"], PASSWORD, &[]),
            Cred::test("winbox", &["winrm://10.0.0.7", "winrms://10.0.0.8", "rdp://10.0.0.7"], PASSWORD, &[]),
            Cred::test("db", &["mssql://10.0.0.9:1444"], PASSWORD, &[("broker_approval", "never")]),
            Cred { totp: Zeroizing::new(SEED.into()), ..Cred::test("web", &["https://web.test/login"], PASSWORD, &[]) },
        ]
    }

    #[test]
    fn list_credentials_shape_and_endpoint_scoping() {
        let home = temp_home("list");
        let mut c = items();
        c.push(Cred::test("odd-auth", &["https://api.test"], TOKEN, &[("broker_auth", "digest")]));
        let (b, _) = broker(c, Answer::Once, &home);
        let out = rt().block_on(b.call("list_credentials", json!({}), "t"));
        assert_clean(&out.to_string());
        let names: HashMap<&str, &Value> =
            out["credentials"].as_array().unwrap().iter().map(|c| (c["name"].as_str().unwrap(), c)).collect();
        let tools = |n: &str| names[n]["tools"].as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(tools("api-bearer"), ["browser_login", "http_request"]);
        assert_eq!(tools("web-plain"), ["browser_login"]);
        assert_eq!(tools("api-basic"), ["http_request"]);
        assert!(tools("odd-auth").is_empty(), "neither web tool can use broker_auth=digest");
        assert_eq!(names["api-bearer"]["tools"]["http_request"], json!({"auth": "bearer", "approval": "never"}));
        assert_eq!(names["web"]["tools"]["browser_login"]["approval"], "daily");
        assert_eq!(names["web"]["totp"], true);
        assert_eq!(names["api-bearer"]["totp"], false);
        assert_eq!(names["remote"]["hosts"], json!(["api.example.com", "*.example.org"]));
        assert_eq!(tools("box"), ["ssh_exec"]);
        assert_eq!(names["box"]["hosts"], json!([]));
        assert_eq!(names["winbox"]["tools"]["win_exec"]["targets"], json!(["winrm://10.0.0.7:5985", "winrms://10.0.0.8:5986"]));
        assert_eq!(names["winbox"]["tools"]["rdp_open"], json!({"approval": "never", "targets": ["rdp://10.0.0.7:3389"]}));
        assert_eq!(names["db"]["tools"]["sql_query"]["targets"], json!(["mssql://10.0.0.9:1444"]));
    }

    #[test]
    fn refusals_happen_before_approval_and_are_audited() {
        let home = temp_home("refuse");
        let (b, calls) = broker(items(), Answer::Once, &home);
        let rt = rt();
        let call = |tool: &str, args: Value| rt.block_on(b.call(tool, args, "t"))["error"].as_str().unwrap_or("").to_string();
        // an ssh:// URI does not make its host a web host, and creds only go to their protocol's endpoints
        assert!(call("http_request", json!({"credential": "winbox", "method": "GET", "url": "https://10.0.0.7/"})).contains("not allowed"));
        assert!(call("ssh_exec", json!({"credential": "winbox", "command": "id"})).contains("no ssh:// URI"));
        assert!(call("win_exec", json!({"credential": "winbox", "command": "x", "host": "10.0.0.9"}))
            .contains("no winrm/winrms:// URI for host \"10.0.0.9\""));
        for url in ["http://api.test/x", "https://evil.example.net/", "https://api.test.evil.net/"] {
            let e = call("http_request", json!({"credential": "api-bearer", "method": "GET", "url": url}));
            assert!(e.contains("not allowed"), "{e}");
        }
        assert!(call("http_request", json!({"credential": "web-plain", "method": "GET", "url": "https://web.test/"})).contains("cannot use"));
        assert!(call("browser_login", json!({"credential": "api-basic"})).contains("only form or ntlm"));
        assert!(call("browser_login", json!({"credential": "web", "url": "https://example.com/login"})).contains("not allowed"));
        assert!(call("http_request", json!({"credential": "nope", "method": "GET", "url": "https://api.test/"})).contains("no credential"));
        assert!(call("ssh_exec", json!({"credential": "box"})).contains("missing argument command"));
        assert!(calls.lock().unwrap().is_empty());
        let audit = std::fs::read_to_string(home.join("audit.jsonl")).unwrap();
        assert_clean(&audit);
        let lines: Vec<Value> = audit.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 11);
        assert!(lines.iter().all(|l| l["result"] == "refused" && l["ts"].is_string() && l["tool"].is_string()));
        assert_eq!(lines[0]["target"], "10.0.0.7/");
        assert_eq!(lines[0]["method"], "GET");
        assert_eq!(lines[2]["credential"], "winbox");
        assert_eq!((lines[8]["method"].as_str(), lines[8]["target"].as_str()), (Some("LOGIN"), Some("example.com/login")));
    }

    #[test]
    fn approval_policies_deny_and_daily_memory() {
        let home = temp_home("approve");
        let rt = rt();
        let c = items();
        let cred = |n: &str| c.iter().find(|c| c.name == n).unwrap();
        let approve = |b: &Broker, n: &str| rt.block_on(b.approve(cred(n), Tool::HttpRequest, "h", "", ""));
        let (b, calls) = broker(c.clone(), Answer::Deny, &home);
        let e = rt.block_on(b.approve(cred("api-daily"), Tool::HttpRequest, "api.test", "GET /", "code.exe")).unwrap_err();
        assert!(matches!(e, Error::Denied(_)) && e.to_string().contains("denied"));
        assert_eq!(calls.lock().unwrap()[0].caller, "code.exe");
        assert_eq!(calls.lock().unwrap()[0].detail, "GET /");

        let (b, calls) = broker(c.clone(), Answer::Once, &home);
        for _ in 0..2 {
            approve(&b, "api-daily").unwrap();
        }
        assert_eq!(calls.lock().unwrap().len(), 2);

        let (b, calls) = broker(c.clone(), Answer::Today, &home);
        for _ in 0..3 {
            approve(&b, "api-daily").unwrap();
        }
        assert_eq!(calls.lock().unwrap().len(), 1);
        for _ in 0..2 {
            approve(&b, "api-always").unwrap();
        }
        assert_eq!(calls.lock().unwrap().len(), 3);
        approve(&b, "api-bearer").unwrap(); // policy never
        assert_eq!(calls.lock().unwrap().len(), 3);
        // a new day asks again
        let yesterday = Local::now().date_naive().pred_opt().unwrap();
        b.approved.lock().unwrap().values().for_each(|d| *d.try_lock().unwrap() = Some(yesterday));
        approve(&b, "api-daily").unwrap();
        assert_eq!(calls.lock().unwrap().len(), 4);
        let bad = Cred::test("x", &[], "", &[("broker_approval", "sometimes")]);
        assert!(matches!(rt.block_on(b.approve(&bad, Tool::Run, "", "", "")), Err(Error::Refused(_))));
    }

    #[test]
    fn daily_asks_once_for_concurrent_calls() {
        let home = temp_home("concurrent");
        let (b, calls) = broker(items(), Answer::Today, &home);
        let c = &items()[1]; // api-daily
        let (x, y) = rt().block_on(async {
            tokio::join!(b.approve(c, Tool::HttpRequest, "h", "", ""), b.approve(c, Tool::HttpRequest, "h", "", ""))
        });
        assert!(x.is_ok() && y.is_ok());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn denied_remote_call_is_audited_and_redacted() {
        let home = temp_home("deny");
        let (b, calls) = broker(items(), Answer::Deny, &home);
        let out = rt().block_on(b.call("win_exec", json!({"credential": "winbox", "command": "hostname", "host": "10.0.0.8"}), "t"));
        assert!(out["error"].as_str().unwrap().contains("denied"));
        let a = calls.lock().unwrap()[0].clone();
        assert_eq!((a.tool.as_str(), a.target.as_str(), a.detail.as_str()), ("win_exec", "winrms://10.0.0.8:5986", "hostname"));
        let line: Value = serde_json::from_str(std::fs::read_to_string(home.join("audit.jsonl")).unwrap().trim()).unwrap();
        assert_eq!((line["result"].as_str(), line["target"].as_str(), line["method"].as_str()), (Some("denied"), Some("winrms://10.0.0.8:5986"), Some("WINRM")));
    }

    #[test]
    fn resolve_fields_approval_and_audit() {
        let home = temp_home("resolve");
        let mut c = items();
        c[8].fields.insert("api key".into(), Zeroizing::new("k-123".into()));
        let (b, calls) = broker(c, Answer::Once, &home);
        let rt = rt();
        let refs: BTreeMap<String, String> = [
            ("P", "valet://db/password"),
            ("U", "valet://db/username"),
            ("K", "valet://db/api key"),
            ("W", "valet://web/password"),
            ("T", "valet://web/totp"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let r = rt.block_on(b.resolve(refs, "deploy.cmd", "pwsh.exe")).unwrap();
        assert_eq!(r.values["P"].as_str(), PASSWORD);
        assert_eq!(r.values["U"].as_str(), "svc-user");
        assert_eq!(r.values["K"].as_str(), "k-123");
        assert_eq!(r.values["T"].len(), 6);
        let redact = Redactor::new(&r.secrets);
        assert_eq!(redact.apply(&format!("{PASSWORD} svc-user k-123")), "[REDACTED:db] svc-user [REDACTED:db]");
        // db is broker_approval=never; web (daily) asks once for the whole run
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(calls.lock().unwrap()[0].detail, "deploy.cmd");
        for bad in ["valet://nope/password", "valet://db/nofield", "valet://db", "plain"] {
            let refs = BTreeMap::from([("X".to_string(), bad.to_string())]);
            assert!(matches!(rt.block_on(b.resolve(refs, "x", "")), Err(Error::Refused(_))), "{bad}");
        }
        let audit = std::fs::read_to_string(home.join("audit.jsonl")).unwrap();
        assert_clean(&audit);
        let first: Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
        assert_eq!((first["tool"].as_str(), first["result"].as_str(), first["credential"].as_str()), (Some("run"), Some("ok"), Some("db, web")));
    }
}
