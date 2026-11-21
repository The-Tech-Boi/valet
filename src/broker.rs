//! The policy core (owner: core). Spec: valet/broker.py `Broker`, `scrub`, `redactor`, `not_allowed`.
//!
//! Every tool call goes through `Broker::call`: find the credential (only items in the agent's
//! collection exist), check the target is allowed, ask approval per the item's policy, run the
//! operation module, audit, and redact every secret of that credential from the result.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::{Local, NaiveDate};
use futures_util::future::join_all;
use hmac::{Hmac, KeyInit, Mac};
use regex::{Regex, RegexBuilder};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::cred::{default_port, fail, lookup, Cred, Endpoint, Error, Result, AUTH, SCHEME_TOOLS};
use crate::vault::Vault;
use crate::{audit, browser, http, rdp, sql, ssh, winrm};

const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1", "[::1]"];
/// browser_login auth kinds; ntlm = the browser answers a Windows sign-in challenge.
const BROWSER_AUTH: &[&str] = &["form", "ntlm"];
/// Ports check_credentials probes on a scheme-less URI (a bare host).
const PROBES: &[(&str, u16)] = &[("ssh", 22), ("winrm", 5985), ("mssql", 1433), ("rdp", 3389)];

/// What the approval window shows. `detail` is the command, query or "GET /path".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Approval {
    pub credential: String,
    pub username: String,
    pub tool: String,
    pub target: String,
    pub detail: String,
    /// Process that called valet, e.g. "code.exe (pid 1234)". Taken from the pipe client, not trusted input.
    pub caller: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Answer {
    Today,
    Once,
    Deny,
}

/// Blocking approval prompt (the agent passes `ui.approve`); the broker runs it on a blocking thread.
pub type Approver = Arc<dyn Fn(&Approval) -> Answer + Send + Sync>;

/// `[REDACTED:<name>]` for every secret, longest first. Case-insensitive.
pub struct Redactor {
    re: Option<Regex>,
    tags: HashMap<String, String>,
}

impl Redactor {
    pub fn new(named: &[(String, Vec<String>)]) -> Self {
        let mut pairs: Vec<(&str, &str)> = named
            .iter()
            .flat_map(|(n, s)| s.iter().filter(|s| !s.is_empty()).map(move |s| (s.as_str(), n.as_str())))
            .collect();
        pairs.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        let mut tags = HashMap::new();
        for (s, n) in &pairs {
            tags.entry(s.to_lowercase()).or_insert_with(|| format!("[REDACTED:{n}]"));
        }
        let re = (!pairs.is_empty()).then(|| {
            let alts: Vec<String> = pairs.iter().map(|(s, _)| regex::escape(s)).collect();
            RegexBuilder::new(&alts.join("|"))
                .case_insensitive(true)
                .size_limit(1 << 28)
                .build()
                .expect("escaped literals always compile")
        });
        Redactor { re, tags }
    }

    pub fn apply(&self, text: &str) -> String {
        match &self.re {
            None => text.to_string(),
            Some(re) => re
                .replace_all(text, |m: &regex::Captures| {
                    self.tags.get(&m[0].to_lowercase()).cloned().unwrap_or_else(|| "[REDACTED]".into())
                })
                .into_owned(),
        }
    }

    fn for_cred(cred: &Cred) -> Self {
        Redactor::new(&[(cred.name.clone(), secrets(cred))])
    }
}

/// Every string inside `v` (keys too) through the redactor.
fn scrub(v: Value, r: &Redactor) -> Value {
    match v {
        Value::String(s) => Value::String(r.apply(&s)),
        Value::Array(a) => Value::Array(a.into_iter().map(|v| scrub(v, r)).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (r.apply(&k), scrub(v, r))).collect()),
        v => v,
    }
}

/// Every string a caller may see for this credential's secrets: password, TOTP seed and current
/// codes, base64(user:pass), and their URL/JSON-escaped forms.
pub fn secrets(cred: &Cred) -> Vec<String> {
    let mut s = vec![cred.password.to_string(), cred.totp.to_string()];
    if !cred.password.is_empty() {
        let pair = Zeroizing::new(format!("{}:{}", cred.username, cred.password.as_str()));
        s.push(base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()));
    }
    if let Some(otp) = Otp::parse(&cred.totp) {
        s.push(otp.secret.to_string());
        s.extend([-30, 0, 30].map(|d| otp.at(unix_now() + d).to_string()));
    }
    let escaped: Vec<String> =
        s.iter().flat_map(|v| [quote(v, false), quote(v, true), json_escaped(v, false), json_escaped(v, true)]).collect();
    s.extend(escaped);
    s.retain(|v| !v.is_empty());
    s.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    s.dedup();
    s
}

/// Python's `quote(v, safe="")` (or `quote_plus` when `plus`).
fn quote(v: &str, plus: bool) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => (b as char).to_string(),
            b' ' if plus => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The inside of a JSON string literal; `ascii` escapes non-ASCII as \uXXXX like Python's json.dumps.
fn json_escaped(v: &str, ascii: bool) -> String {
    let quoted = serde_json::to_string(v).unwrap_or_default();
    let inner = &quoted[1..quoted.len() - 1];
    if !ascii {
        return inner.to_string();
    }
    inner
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                c.encode_utf16(&mut [0; 2]).iter().map(|u| format!("\\u{u:04x}")).collect()
            }
        })
        .collect()
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Why `url` may not receive `cred`, or None.
pub fn not_allowed(cred: &Cred, url: &str) -> Option<String> {
    if url.is_empty() {
        return Some("no URL given and the item has no login URI".into());
    }
    let u = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => return Some(format!("not a valid URL ({e}); use https://host/path")),
    };
    let host = u.host_str().unwrap_or("").to_lowercase();
    let http_ok = LOCAL_HOSTS.contains(&host.as_str()) || cred.flag("broker_allow_http");
    if u.scheme() != "https" && !(u.scheme() == "http" && http_ok) {
        return Some(format!(
            "{} scheme not allowed; use https (http only for localhost, or items with broker_allow_http=yes)",
            u.scheme()
        ));
    }
    let hosts = cred.hosts();
    if !hosts.iter().any(|h| *h == host || (h.starts_with("*.") && host.ends_with(&h[1..]))) {
        let allowed = if hosts.is_empty() { "none".to_string() } else { hosts.join(", ") };
        return Some(format!("host {host:?} is not allowed for credential {:?} (allowed: {allowed})", cred.name));
    }
    None
}

/// Current TOTP code for the item, if it has a seed.
pub fn totp_now(cred: &Cred) -> Option<Zeroizing<String>> {
    Otp::parse(&cred.totp).map(|o| o.at(unix_now()))
}

/// RFC 6238 parameters from a base32 seed or an otpauth:// URI.
struct Otp {
    secret: Zeroizing<String>,
    key: Zeroizing<Vec<u8>>,
    digits: u32,
    period: u64,
    algorithm: String,
}

impl Otp {
    fn parse(seed: &str) -> Option<Otp> {
        let (mut secret, mut digits, mut period, mut algorithm) =
            (Zeroizing::new(seed.to_string()), 6, 30, "SHA1".to_string());
        if seed.starts_with("otpauth://") {
            secret = Zeroizing::new(String::new());
            for (k, v) in Url::parse(seed).ok()?.query_pairs() {
                match &*k {
                    "secret" => secret = Zeroizing::new(v.into_owned()),
                    "digits" => digits = v.parse().ok()?,
                    "period" => period = v.parse().ok()?,
                    "algorithm" => algorithm = v.to_uppercase(),
                    _ => {}
                }
            }
        }
        let secret = Zeroizing::new(secret.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase());
        let key = Zeroizing::new(base32(&secret)?);
        let valid = !key.is_empty()
            && (1..=10).contains(&digits)
            && period > 0
            && ["SHA1", "SHA256", "SHA512"].contains(&algorithm.as_str());
        valid.then_some(Otp { secret, key, digits, period, algorithm })
    }

    fn at(&self, t: i64) -> Zeroizing<String> {
        let counter = (t.max(0) as u64 / self.period).to_be_bytes();
        let h: Zeroizing<Vec<u8>> = Zeroizing::new(match self.algorithm.as_str() {
            "SHA256" => Hmac::<sha2::Sha256>::new_from_slice(&self.key).unwrap().chain_update(counter).finalize().into_bytes().to_vec(),
            "SHA512" => Hmac::<sha2::Sha512>::new_from_slice(&self.key).unwrap().chain_update(counter).finalize().into_bytes().to_vec(),
            _ => Hmac::<sha1::Sha1>::new_from_slice(&self.key).unwrap().chain_update(counter).finalize().into_bytes().to_vec(),
        });
        let o = (h[h.len() - 1] & 0xf) as usize;
        let n = u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff;
        Zeroizing::new(format!("{:0w$}", n as u64 % 10u64.pow(self.digits), w = self.digits as usize))
    }
}

/// RFC 4648 base32, uppercase, padding optional. None on any other character.
fn base32(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5 | v as u32) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Optional argument; missing and null are None.
fn opt<T: DeserializeOwned>(args: &Value, name: &str) -> Result<Option<T>> {
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

/// host+path of a URL (no query: it may carry a key), for audit and approval.
fn host_path(url: &str) -> (String, String) {
    Url::parse(url).map(|u| (u.host_str().unwrap_or("").to_string(), u.path().to_string())).unwrap_or_default()
}

/// The URL may receive the credential and http_request knows the item's auth kind.
fn http_ready(cred: &Cred, url: &str) -> Result<()> {
    if let Some(reason) = not_allowed(cred, url) {
        return Err(Error::Refused(reason));
    }
    let auth = cred.auth("http_request");
    if matches!(auth.as_str(), "bearer" | "basic" | "ntlm") || auth.starts_with("header:") || auth.starts_with("query:") {
        return Ok(());
    }
    Err(Error::Refused(format!("credential {:?} has broker_auth={auth:?}, which http_request cannot use", cred.name)))
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

async fn port_open(host: &str, port: u16) -> bool {
    let connect = tokio::net::TcpStream::connect((host, port));
    matches!(tokio::time::timeout(Duration::from_secs(2), connect).await, Ok(Ok(_)))
}

/// Sign in and return a short proof.
async fn probe(c: &Cred, ep: &Endpoint) -> Result<String> {
    let t = Duration::from_secs(15);
    match ep.scheme.as_str() {
        "ssh" => Ok(text(&ssh::exec(c, ep, None, t).await?["status"])),
        "winrm" | "winrms" => {
            let r = winrm::exec(c, ep, "$env:COMPUTERNAME", t).await?;
            if r["exit_code"].as_i64().unwrap_or(0) != 0 {
                return Err(fail(text(&r["stderr"]).chars().take(200).collect::<String>()));
            }
            Ok(format!("signed in to {}", text(&r["stdout"]).trim()))
        }
        "mssql" => {
            let r = sql::query(c, ep, "SELECT SUSER_SNAME()", None, 1, t).await?;
            Ok(format!("signed in as {}", text(&r["results"][0]["rows"][0][0])))
        }
        s => Err(Error::Refused(format!("{s} sign-in cannot be tested"))),
    }
}

/// Where the credentials come from: the agent's vault, or a fixed list (tests).
pub enum Source {
    Vault(Arc<tokio::sync::Mutex<Vault>>, String),
    #[cfg(test)]
    Fixed(Vec<Cred>),
}

pub struct Broker {
    source: Source,
    approver: Approver,
    home: PathBuf,
    cdp: String,
    /// (credential id, tool) -> day the user answered "today".
    approved: Mutex<HashMap<(String, String), NaiveDate>>,
}

impl Broker {
    pub fn new(source: Source, approver: Approver, home: PathBuf, cdp: String) -> Broker {
        Broker { source, approver, home, cdp, approved: Mutex::default() }
    }

    async fn creds(&self, sync: bool) -> Result<Vec<Cred>> {
        match &self.source {
            #[cfg(test)]
            Source::Fixed(c) => Ok(c.clone()),
            Source::Vault(v, collection) => {
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

    async fn ask(&self, a: Approval) -> Answer {
        let f = self.approver.clone();
        tokio::task::spawn_blocking(move || f(&a)).await.unwrap_or(Answer::Deny)
    }

    async fn approve(&self, cred: &Cred, tool: &str, target: &str, detail: &str, caller: &str) -> Result<()> {
        let policy = cred.approval(tool);
        if !["never", "daily", "always"].contains(&policy.as_str()) {
            return Err(Error::Refused(format!("credential {:?} has unknown broker_approval {policy:?}", cred.name)));
        }
        let (key, today) = ((cred.id.clone(), tool.to_string()), Local::now().date_naive());
        if policy == "never" || (policy == "daily" && self.approved.lock().unwrap().get(&key) == Some(&today)) {
            return Ok(());
        }
        let a = Approval {
            credential: cred.name.clone(),
            username: cred.username.clone(),
            tool: tool.into(),
            target: target.into(),
            detail: detail.into(),
            caller: caller.into(),
        };
        match self.ask(a).await {
            Answer::Deny => {
                Err(Error::Denied(format!("the user denied {tool} with credential {:?} on {target}", cred.name)))
            }
            Answer::Today if policy == "daily" => {
                self.approved.lock().unwrap().insert(key, today);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Run one MCP tool call and return the JSON result (or {"error": ...}), already redacted and audited.
    pub async fn call(&self, tool: &str, args: Value, caller: &str) -> Value {
        let out = match tool {
            "list_credentials" => self.list().await,
            "check_credentials" => self.check(&args, caller).await,
            "http_request" | "browser_login" | "ssh_exec" | "win_exec" | "sql_query" | "rdp_open" => {
                return self.with_cred(tool, &args, caller).await
            }
            _ => Err(Error::Refused(format!("unknown tool {tool:?}"))),
        };
        out.unwrap_or_else(|e| json!({"error": e.to_string()}))
    }

    /// The single-credential tools: find, run, audit, redact.
    async fn with_cred(&self, tool: &str, args: &Value, caller: &str) -> Value {
        let mut entry = Map::new();
        entry.insert("tool".into(), tool.into());
        entry.insert("credential".into(), args.get("credential").cloned().unwrap_or_default());
        let mut cred = None;
        let out = async {
            let c = cred.insert(self.find(&req::<String>(args, "credential")?).await?);
            entry.insert("credential".into(), c.name.clone().into());
            self.op(tool, c, args, caller, &mut entry).await
        }
        .await;
        let (value, result) = match out {
            Ok(v) => {
                let status = v.get("status").cloned().unwrap_or_default();
                (v, status)
            }
            Err(e) => {
                let kind = match e {
                    Error::Denied(_) => "denied",
                    Error::Refused(_) => "refused",
                    Error::Failed(_) => "error",
                };
                (json!({"error": e.to_string()}), kind.into())
            }
        };
        entry.insert("result".into(), result);
        let r = cred.as_ref().map(Redactor::for_cred).unwrap_or_else(|| Redactor::new(&[]));
        if let Value::Object(e) = scrub(Value::Object(entry), &r) {
            audit::write(&self.home, e);
        }
        scrub(value, &r)
    }

    async fn op(&self, tool: &str, c: &Cred, args: &Value, caller: &str, entry: &mut Map<String, Value>) -> Result<Value> {
        match tool {
            "http_request" => {
                let method = req::<String>(args, "method")?.to_uppercase();
                let url: String = req(args, "url")?;
                let (host, path) = host_path(&url);
                entry.insert("method".into(), method.clone().into());
                entry.insert("target".into(), format!("{host}{path}").into());
                http_ready(c, &url)?;
                let request = http::Request {
                    headers: opt(args, "headers")?.unwrap_or_default(),
                    body: opt(args, "body")?,
                    json: opt(args, "json")?,
                    timeout: secs(opt(args, "timeout")?.unwrap_or(30.0)),
                    method,
                    url,
                };
                self.approve(c, tool, &host, &format!("{} {path}", request.method), caller).await?;
                http::request(c, request).await
            }
            "browser_login" => {
                let explicit: Option<String> = opt(args, "url")?;
                let url = explicit.clone().or_else(|| c.uris.first().cloned()).unwrap_or_default();
                let (host, path) = host_path(&url);
                entry.insert("method".into(), "LOGIN".into());
                entry.insert("target".into(), format!("{host}{path}").into());
                let auth = c.auth(tool);
                if !BROWSER_AUTH.contains(&auth.as_str()) {
                    return Err(Error::Refused(format!(
                        "credential {:?} has broker_auth={auth:?}; only form or ntlm items can be used with browser_login",
                        c.name
                    )));
                }
                if let Some(reason) = not_allowed(c, &url) {
                    return Err(Error::Refused(reason));
                }
                self.approve(c, tool, &host, &format!("sign in at {path}"), caller).await?;
                browser::login(c, explicit.as_deref(), &self.cdp).await
            }
            "ssh_exec" | "win_exec" | "sql_query" | "rdp_open" => {
                let schemes: &[&str] = match tool {
                    "ssh_exec" => &["ssh"],
                    "win_exec" => &["winrm", "winrms"],
                    "sql_query" => &["mssql"],
                    _ => &["rdp"],
                };
                entry.insert("method".into(), schemes[0].to_uppercase().into());
                let ep = c.endpoint(schemes, opt::<String>(args, "host")?.as_deref())?;
                entry.insert("target".into(), ep.to_string().into());
                let detail: String = match tool {
                    "ssh_exec" | "win_exec" => req(args, "command")?,
                    "sql_query" => req(args, "query")?,
                    _ => String::new(),
                };
                let timeout = secs(opt(args, "timeout")?.unwrap_or(60.0));
                let (database, max_rows) = (opt::<String>(args, "database")?, opt(args, "max_rows")?.unwrap_or(200));
                self.approve(c, tool, &ep.to_string(), &detail, caller).await?;
                match tool {
                    "ssh_exec" => ssh::exec(c, &ep, Some(&detail), timeout).await,
                    "win_exec" => winrm::exec(c, &ep, &detail, timeout).await,
                    "sql_query" => sql::query(c, &ep, &detail, database.as_deref(), max_rows, timeout).await,
                    _ => rdp::open(c, &ep),
                }
            }
            _ => Err(Error::Refused(format!("unknown tool {tool:?}"))),
        }
    }

    async fn list(&self) -> Result<Value> {
        let out: Vec<Value> = self
            .creds(false)
            .await?
            .iter()
            .map(|c| {
                let hosts = c.hosts();
                let mut tools = Map::new();
                for (t, _) in AUTH.iter().filter(|_| !hosts.is_empty()) {
                    let auth = c.auth(t);
                    let usable = if *t == "browser_login" { BROWSER_AUTH.contains(&auth.as_str()) } else { auth != "form" };
                    if usable {
                        tools.insert(t.to_string(), json!({"auth": auth, "approval": c.approval(t)}));
                    }
                }
                for ep in c.endpoints() {
                    let t = lookup(SCHEME_TOOLS, &ep.scheme).unwrap_or("");
                    let entry = tools.entry(t).or_insert_with(|| json!({"approval": c.approval(t), "targets": []}));
                    if let Some(targets) = entry["targets"].as_array_mut() {
                        targets.push(ep.to_string().into());
                    }
                }
                json!({"name": c.name, "id": c.id, "hosts": hosts, "tools": tools, "totp": !c.totp.is_empty()})
            })
            .collect();
        Ok(json!({"credentials": out}))
    }

    /// Try each item's sign-in on each of its URIs (one approval for the whole batch).
    async fn check(&self, args: &Value, caller: &str) -> Result<Value> {
        let names: Vec<String> = opt(args, "credentials")?.unwrap_or_default();
        let creds: Vec<Cred> = self
            .creds(false)
            .await?
            .into_iter()
            .filter(|c| names.is_empty() || names.contains(&c.name) || names.contains(&c.id))
            .collect();
        if creds.is_empty() {
            return Ok(json!({"error": "no matching credentials in the broker collection"}));
        }
        let a = Approval {
            credential: format!("{} credentials", creds.len()),
            username: String::new(),
            tool: "check_credentials".into(),
            target: "the hosts listed on each item".into(),
            detail: creds.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", "),
            caller: caller.into(),
        };
        if self.ask(a).await == Answer::Deny {
            return Ok(json!({"error": "the user denied check_credentials"}));
        }
        let gate = &tokio::sync::Semaphore::new(8);
        let checks = creds.iter().flat_map(|c| c.uris.iter().map(move |u| (c, u))).map(|(c, u)| async move {
            let (result, detail) = {
                let _permit = gate.acquire().await;
                self.check_one(c, u).await.unwrap_or_else(|e| ("failed", e.to_string().chars().take(300).collect()))
            };
            let r = Redactor::for_cred(c);
            let mut e = Map::new();
            e.insert("tool".into(), "check_credentials".into());
            e.insert("credential".into(), c.name.clone().into());
            e.insert("target".into(), r.apply(u.split('?').next().unwrap_or("")).into());
            e.insert("result".into(), result.into());
            audit::write(&self.home, e);
            scrub(json!({"credential": c.name, "uri": u, "result": result, "detail": detail}), &r)
        });
        let mut results = join_all(checks).await;
        results.extend(creds.iter().filter(|c| c.uris.is_empty()).map(|c| {
            json!({"credential": c.name, "uri": "", "result": "skipped", "detail": "item has no URI"})
        }));
        let count = |k: &str| results.iter().filter(|r| r["result"] == k).count();
        let summary = json!({"ok": count("ok"), "failed": count("failed"), "skipped": count("skipped")});
        Ok(json!({"summary": summary, "results": results}))
    }

    async fn check_one(&self, c: &Cred, uri: &str) -> Result<(&'static str, String)> {
        if !uri.contains("://") {
            // A bare host, e.g. from an import: see which sign-in services answer.
            let host = Url::parse(&format!("http://{uri}"))
                .ok()
                .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_string()))
                .ok_or_else(|| Error::Refused(format!("{uri:?} is not a host")))?;
            let open = join_all(PROBES.iter().map(|(_, p)| port_open(&host, *p))).await;
            let found: Vec<(&str, u16)> = PROBES.iter().zip(open).filter(|(_, o)| *o).map(|(p, _)| *p).collect();
            if found.is_empty() {
                return Ok(("skipped", "no ssh, winrm, mssql or rdp port open; give the URI a scheme".into()));
            }
            let (mut parts, mut ok) = (Vec::new(), false);
            for (scheme, port) in found {
                if scheme == "rdp" {
                    parts.push("rdp port open (not testable)".to_string());
                    continue;
                }
                match probe(c, &Endpoint { scheme: scheme.into(), host: host.clone(), port }).await {
                    Ok(d) => {
                        ok = true;
                        parts.push(format!("{scheme} ok ({d})"));
                    }
                    Err(e) => parts.push(format!("{scheme} failed ({})", e.to_string().chars().take(120).collect::<String>())),
                }
            }
            let hint = if ok { format!("; set the URI to e.g. ssh://{host}") } else { String::new() };
            return Ok((if ok { "ok" } else { "failed" }, parts.join("; ") + &hint));
        }
        let u = Url::parse(uri).map_err(fail)?;
        match u.scheme() {
            "http" | "https" => {
                if c.auth("http_request") == "form" {
                    return Ok(("skipped", "web form login (check it with browser_login)".into()));
                }
                http_ready(c, uri)?;
                let request = http::Request {
                    method: "GET".into(),
                    url: uri.into(),
                    headers: BTreeMap::new(),
                    body: None,
                    json: None,
                    timeout: Duration::from_secs(15),
                };
                let code = http::request(c, request).await?["status"].as_u64().unwrap_or(0);
                Ok((if code == 401 || code == 403 { "failed" } else { "ok" }, format!("HTTP {code}")))
            }
            "rdp" => Ok(("skipped", "RDP sign-in cannot be tested without opening a session".into())),
            s if default_port(s).is_some() => Ok(("ok", probe(c, &c.endpoint(&[s], u.host_str())?).await?)),
            s => Ok(("skipped", format!("unknown scheme {s:?}"))),
        }
    }

    /// For `valet run`: resolve NAME -> valet://item/field after approval; also returns the secrets to redact.
    pub async fn resolve(
        &self,
        refs: BTreeMap<String, String>,
        what: &str,
        caller: &str,
    ) -> Result<(BTreeMap<String, Zeroizing<String>>, Vec<(String, Vec<String>)>)> {
        let mut creds: Vec<(String, Cred)> = Vec::new(); // (reference used, item), one approval each
        let out = async {
            let (mut values, mut named) = (BTreeMap::new(), Vec::new());
            for (env, r) in &refs {
                let (item, field) = r
                    .strip_prefix("valet://")
                    .and_then(|rest| rest.rsplit_once('/'))
                    .filter(|(i, f)| !i.is_empty() && !f.is_empty())
                    .ok_or_else(|| Error::Refused(format!("{env}: expected valet://<item>/<field>, got {r:?}")))?;
                if !creds.iter().any(|(i, _)| i == item) {
                    creds.push((item.to_string(), self.find(item).await?));
                    let c = &creds[creds.len() - 1].1;
                    self.approve(c, "run", "this computer", what, caller).await?;
                }
                let c = &creds.iter().find(|(i, _)| i == item).expect("pushed above").1;
                let f = field.to_lowercase();
                let value = match f.as_str() {
                    "password" => c.password.clone(),
                    "username" => Zeroizing::new(c.username.clone()),
                    "uri" => Zeroizing::new(c.uris.first().cloned().unwrap_or_default()),
                    "totp" => totp_now(c).unwrap_or_else(|| Zeroizing::new(String::new())),
                    _ => c.fields.get(&f).cloned().ok_or_else(|| {
                        Error::Refused(format!("{env}: item {:?} has no field {field:?}", c.name))
                    })?,
                };
                let mut s = secrets(c);
                if f != "username" && f != "uri" {
                    s.push(value.to_string());
                }
                named.push((c.name.clone(), s));
                values.insert(env.clone(), value);
            }
            Ok((values, named))
        }
        .await;
        let result = match &out {
            Ok(_) => "ok",
            Err(Error::Denied(_)) => "denied",
            Err(Error::Refused(_)) => "refused",
            Err(Error::Failed(_)) => "error",
        };
        let names: Vec<&str> = creds.iter().map(|(_, c)| c.name.as_str()).collect();
        let mut e = Map::new();
        e.insert("tool".into(), "run".into());
        e.insert("credential".into(), if names.is_empty() { "-".into() } else { names.join(", ").into() });
        e.insert("target".into(), what.chars().take(200).collect::<String>().into());
        e.insert("result".into(), result.into());
        audit::write(&self.home, e);
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const TOKEN: &str = "tok_test_123";
    pub const PASSWORD: &str = "P@ss-test-456";
    /// RFC 6238 test key "12345678901234567890".
    pub const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    pub fn cred(name: &str, uris: &[&str], password: &str, fields: &[(&str, &str)]) -> Cred {
        Cred {
            id: format!("id-{name}"),
            name: name.into(),
            username: "svc-user".into(),
            password: Zeroizing::new(password.into()),
            totp: Zeroizing::new(String::new()),
            uris: uris.iter().map(|u| u.to_string()).collect(),
            fields: fields.iter().map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string()))).collect(),
        }
    }

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

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    fn items() -> Vec<Cred> {
        vec![
            cred("api-bearer", &["https://api.test"], TOKEN, &[]),
            cred("api-daily", &["https://api.test"], TOKEN, &[("broker_approval", "daily")]),
            cred("api-always", &["https://api.test"], TOKEN, &[("broker_approval", "always")]),
            cred("web-plain", &["https://web.test/login"], PASSWORD, &[("broker_auth", "form")]),
            cred("api-basic", &["https://api.test"], PASSWORD, &[("broker_auth", "basic")]),
            cred("remote", &["https://api.example.com", "https://*.example.org/x"], TOKEN, &[]),
            cred("box", &["ssh://127.0.0.1:2222"], PASSWORD, &[]),
            cred(
                "winbox",
                &["winrm://10.0.0.7", "winrms://10.0.0.8", "rdp://10.0.0.7"],
                PASSWORD,
                &[],
            ),
            cred("db", &["mssql://10.0.0.9:1444"], PASSWORD, &[("broker_approval", "never")]),
            {
                let mut c = cred("web", &["https://web.test/login"], PASSWORD, &[]);
                c.totp = Zeroizing::new(SEED.into());
                c
            },
        ]
    }

    #[test]
    fn scheme_and_wildcard_rules() {
        let c = cred("remote", &["https://api.example.com", "*.example.org", "http://localhost:8080"], "", &[]);
        assert_eq!(not_allowed(&c, "https://api.example.com/v1"), None);
        assert!(not_allowed(&c, "http://api.example.com/v1").unwrap().contains("scheme"));
        assert!(not_allowed(&c, "ftp://api.example.com/").unwrap().contains("scheme"));
        assert_eq!(not_allowed(&c, "https://a.example.org/"), None);
        assert_eq!(not_allowed(&c, "https://a.b.example.org/"), None);
        assert!(not_allowed(&c, "https://example.org/").unwrap().contains("not allowed"));
        assert!(not_allowed(&c, "https://badexample.org/").unwrap().contains("not allowed"));
        assert!(not_allowed(&c, "https://api.example.com.evil.net/").unwrap().contains("not allowed"));
        assert_eq!(not_allowed(&c, "http://localhost:9999/x"), None);
        assert!(not_allowed(&c, "").is_some() && not_allowed(&c, "api.example.com").is_some());
        let lan = cred("n", &["http://10.0.0.5"], "", &[]);
        assert!(not_allowed(&lan, "http://10.0.0.5/").unwrap().contains("scheme"));
        let lan = cred("n", &["http://10.0.0.5"], "", &[("broker_allow_http", "yes")]);
        assert_eq!(not_allowed(&lan, "http://10.0.0.5/"), None);
        assert!(not_allowed(&lan, "ftp://10.0.0.5/").unwrap().contains("scheme"));
    }

    #[test]
    fn totp_matches_rfc6238() {
        let o = Otp::parse(SEED).unwrap();
        assert_eq!(*o.at(59), "287082");
        let o = Otp::parse(&format!("otpauth://totp/x?secret={}&digits=8", SEED.to_lowercase())).unwrap();
        assert_eq!(*o.at(59), "94287082");
        assert_eq!(*o.at(1111111109), "07081804");
        // SHA256 test key is the 32-byte "1234567890" * 3 + "12".
        let o = Otp::parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256").unwrap();
        assert_eq!(*o.at(59), "46119246");
        assert!(Otp::parse("not base32!").is_none() && Otp::parse("").is_none());
    }

    #[test]
    fn secrets_cover_escaped_forms_and_totp() {
        let mut c = cred("web", &[], "p ä\"/", &[]);
        c.totp = Zeroizing::new(SEED.into());
        let s = secrets(&c);
        let code = totp_now(&c).unwrap();
        for want in ["p ä\"/", "p%20%C3%A4%22%2F", "p+%C3%A4%22%2F", "p ä\\\"/", "p \\u00e4\\\"/", SEED, code.as_str()] {
            assert!(s.iter().any(|x| x == want), "missing {want:?}");
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode("svc-user:p ä\"/");
        assert!(s.contains(&b64));
        let r = Redactor::new(&[("web".into(), s)]);
        assert_eq!(r.apply(&format!("a P%20%c3%a4%22%2f b {} c", code.as_str())), "a [REDACTED:web] b [REDACTED:web] c");
    }

    #[test]
    fn redactor_longest_first_and_case_insensitive() {
        let r = Redactor::new(&[("a".into(), vec!["abc".into()]), ("b".into(), vec!["abcdef".into()])]);
        assert_eq!(r.apply("xABCDEFx abc"), "x[REDACTED:b]x [REDACTED:a]");
        assert_eq!(Redactor::new(&[]).apply("same"), "same");
    }

    #[test]
    fn list_credentials_shape_and_endpoint_scoping() {
        let home = temp_home("list");
        let (b, _) = broker(items(), Answer::Once, &home);
        let out = rt().block_on(b.call("list_credentials", json!({}), "t"));
        assert_clean(&out.to_string());
        let names: HashMap<&str, &Value> =
            out["credentials"].as_array().unwrap().iter().map(|c| (c["name"].as_str().unwrap(), c)).collect();
        let tools = |n: &str| names[n]["tools"].as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(tools("api-bearer"), ["browser_login", "http_request"]);
        assert_eq!(tools("web-plain"), ["browser_login"]);
        assert_eq!(tools("api-basic"), ["http_request"]);
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
        assert!(call("http_request", json!({"credential": "nope", "method": "GET", "url": "https://api.test/"})).contains("no credential"));
        assert!(call("ssh_exec", json!({"credential": "box"})).contains("missing argument command"));
        assert!(calls.lock().unwrap().is_empty());
        let audit = std::fs::read_to_string(home.join("audit.jsonl")).unwrap();
        assert_clean(&audit);
        let lines: Vec<Value> = audit.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 10);
        assert!(lines.iter().all(|l| l["result"] == "refused" && l["ts"].is_string() && l["tool"].is_string()));
        assert_eq!(lines[0]["target"], "10.0.0.7/");
        assert_eq!(lines[0]["method"], "GET");
        assert_eq!(lines[2]["credential"], "winbox");
    }

    #[test]
    fn approval_policies_deny_and_daily_memory() {
        let home = temp_home("approve");
        let rt = rt();
        let c = items();
        let cred = |n: &str| c.iter().find(|c| c.name == n).unwrap();
        let (b, calls) = broker(c.clone(), Answer::Deny, &home);
        let e = rt.block_on(b.approve(cred("api-daily"), "http_request", "api.test", "GET /", "code.exe")).unwrap_err();
        assert!(matches!(e, Error::Denied(_)) && e.to_string().contains("denied"));
        assert_eq!(calls.lock().unwrap()[0].caller, "code.exe");
        assert_eq!(calls.lock().unwrap()[0].detail, "GET /");

        let (b, calls) = broker(c.clone(), Answer::Once, &home);
        for _ in 0..2 {
            rt.block_on(b.approve(cred("api-daily"), "http_request", "h", "", "")).unwrap();
        }
        assert_eq!(calls.lock().unwrap().len(), 2);

        let (b, calls) = broker(c.clone(), Answer::Today, &home);
        for _ in 0..3 {
            rt.block_on(b.approve(cred("api-daily"), "http_request", "h", "", "")).unwrap();
        }
        assert_eq!(calls.lock().unwrap().len(), 1);
        for _ in 0..2 {
            rt.block_on(b.approve(cred("api-always"), "http_request", "h", "", "")).unwrap();
        }
        assert_eq!(calls.lock().unwrap().len(), 3);
        rt.block_on(b.approve(cred("api-bearer"), "http_request", "h", "", "")).unwrap(); // policy never
        assert_eq!(calls.lock().unwrap().len(), 3);
        // a new day asks again
        let yesterday = Local::now().date_naive().pred_opt().unwrap();
        b.approved.lock().unwrap().values_mut().for_each(|d| *d = yesterday);
        rt.block_on(b.approve(cred("api-daily"), "http_request", "h", "", "")).unwrap();
        assert_eq!(calls.lock().unwrap().len(), 4);
        let bad = super::tests::cred("x", &[], "", &[("broker_approval", "sometimes")]);
        assert!(matches!(rt.block_on(b.approve(&bad, "run", "", "", "")), Err(Error::Refused(_))));
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
    fn check_credentials_skips_and_asks_once() {
        let home = temp_home("check");
        let mut c = items();
        c.push(cred("no-uri", &[], PASSWORD, &[]));
        c.push(cred("odd", &["ftp://files.test"], PASSWORD, &[]));
        c.push(cred("desk", &["rdp://10.0.0.7"], PASSWORD, &[]));
        let (b, calls) = broker(c, Answer::Once, &home);
        let out = rt().block_on(b.call("check_credentials", json!({"credentials": ["web-plain", "desk", "no-uri", "odd"]}), "t"));
        let got: Vec<&str> = out["results"].as_array().unwrap().iter().map(|r| r["result"].as_str().unwrap()).collect();
        assert_eq!(got, ["skipped"; 4]);
        assert_eq!(out["summary"], json!({"ok": 0, "failed": 0, "skipped": 4}));
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(calls.lock().unwrap()[0].credential, "4 credentials");
        let (b, _) = broker(items(), Answer::Deny, &home);
        let out = rt().block_on(b.call("check_credentials", json!({"credentials": ["web-plain"]}), "t"));
        assert_eq!(out["error"], "the user denied check_credentials");
        assert_clean(&std::fs::read_to_string(home.join("audit.jsonl")).unwrap());
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
        let (values, named) = rt.block_on(b.resolve(refs, "deploy.cmd", "pwsh.exe")).unwrap();
        assert_eq!(values["P"].as_str(), PASSWORD);
        assert_eq!(values["U"].as_str(), "svc-user");
        assert_eq!(values["K"].as_str(), "k-123");
        assert_eq!(values["T"].len(), 6);
        let r = Redactor::new(&named);
        assert_eq!(r.apply(&format!("{PASSWORD} svc-user k-123")), "[REDACTED:db] svc-user [REDACTED:db]");
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
