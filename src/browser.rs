//! browser_login and `valet browser` (owner: browser). Spec: valet/broker.py `browser_login`,
//! `windows_login`, `fill_login`; valet/__main__.py `start_browser`. Speaks CDP directly over a
//! websocket (no Playwright).

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::broker::{not_allowed, totp_now};
use crate::cred::{fail, Cred, Error, Result};

const PASS_SEL: &str = "input[type=password]";
const USER_SEL: &str = "input[autocomplete=username], input[type=email], input[name*=user i], input[id*=user i], \
                        input[name*=login i], input[name*=email i], input[type=text]";
const SUBMIT_SEL: &str = "button[type=submit], input[type=submit]";
const OTP_SEL: &str = "input[autocomplete=one-time-code], input[name*=otp i], input[id*=otp i], input[name*=totp i], \
                       input[name*=code i], input[id*=code i], input[inputmode=numeric]";

/// Helpers every page script starts with. A field is (kind, selector): kind "first" is the first visible
/// match; "before" is the last visible text/email input before the first visible match (the username
/// in front of a password field).
const PRELUDE: &str = r#"
const vis = e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
const first = s => [...document.querySelectorAll(s)].find(vis);
const field = (k, s) => { const e = first(s); if (k !== 'before' || !e) return e;
  return [...document.querySelectorAll('input')].filter(i => vis(i) && [null, 'text', 'email'].includes(i.getAttribute('type'))
    && (i.compareDocumentPosition(e) & Node.DOCUMENT_POSITION_FOLLOWING)).pop(); };
"#;
const VISIBLE: &str = "return !!field(a[0], a[1]);";
/// Gone only once the new document has parsed, so a page in mid-navigation does not count as gone.
const GONE: &str = "return !field(a[0], a[1]) && document.readyState !== 'loading';";
/// Native value setter plus input/change events, so React-style forms see the value. Refuses (false)
/// if the page is no longer at the URL that was checked (a[3]).
const FILL: &str = r#"if (a[3] && location.href !== a[3]) return false;
const e = field(a[0], a[1]); if (!e) throw new Error('login field disappeared');
e.focus();
const proto = e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, a[2]);
for (const t of ['input', 'change']) e.dispatchEvent(new Event(t, { bubbles: true }));
return true;"#;
/// Click the submit button (a[2] overrides; else the field's form's first visible one); false = none, field focused.
const SUBMIT: &str = r#"const e = field(a[0], a[1]);
const b = a[2] ? first(a[2]) : [...(e?.closest('form')?.querySelectorAll(a[3]) ?? [])].find(vis);
if (b) { b.click(); return true; }
e?.focus(); return false;"#;

type Field<'a> = (&'static str, &'a str);

/// Sign in in the shared browser. `url` is the explicit URL or None for the item's first URI.
/// Returns {"status", "url", "title"}.
pub async fn login(cred: &Cred, url: Option<&str>, cdp: &str) -> Result<Value> {
    let target = url.map(str::to_string).or_else(|| cred.uris.first().cloned()).unwrap_or_default();
    if let Some(why) = not_allowed(cred, &target) {
        return Err(Error::Refused(why));
    }
    let run = async {
        let (mut page, frame, at) = open_tab(cred, cdp).await?;
        page.call("Page.bringToFront", json!({})).await?;
        if cred.auth("browser_login") == "ntlm" {
            return windows_login(&mut page, cred, &target, &frame).await;
        }
        if at.is_none() || url.is_some_and(|u| Some(u) != at.as_deref()) {
            page.goto(cred, &target, &frame, 0).await?;
        }
        fill_login(&mut page, cred).await
    };
    timeout(Duration::from_secs(120), run).await.map_err(|_| fail("browser_login timed out"))?
}

/// A page tab whose URL the credential may use, else a new one. Returns the connection, the target id
/// (= main frame id) and the reused tab's URL (None for a new tab).
async fn open_tab(cred: &Cred, cdp: &str) -> Result<(Page, String, Option<String>)> {
    let http = reqwest::Client::new();
    let tabs: Vec<Value> = http.get(format!("{cdp}/json/list")).send().await.map_err(fail)?.json().await.map_err(fail)?;
    let reuse = tabs.into_iter().find(|t| t["type"] == "page" && not_allowed(cred, t["url"].as_str().unwrap_or("")).is_none());
    let reused = reuse.is_some();
    let tab = match reuse {
        Some(t) => t,
        None => http.put(format!("{cdp}/json/new")).send().await.map_err(fail)?.json().await.map_err(fail)?,
    };
    let ws = tab["webSocketDebuggerUrl"].as_str().ok_or_else(|| fail("browser tab has no debugger URL"))?;
    let (ws, _) = connect_async(ws).await.map_err(fail)?;
    let id = tab["id"].as_str().unwrap_or("").to_string();
    Ok((Page { ws, next_id: 0 }, id, reused.then(|| tab["url"].as_str().unwrap_or("").to_string())))
}

async fn windows_login(page: &mut Page, cred: &Cred, url: &str, frame: &str) -> Result<Value> {
    page.call("Fetch.enable", json!({"handleAuthRequests": true})).await?;
    let code = page.goto(cred, url, frame, 3).await;
    page.call("Fetch.disable", json!({})).await?;
    let status = match code? {
        Some(c) if c < 400 => "signed in".to_string(),
        c => format!("sign-in failed (HTTP {})", c.map_or("None".to_string(), |c| c.to_string())),
    };
    page.result(&status).await
}

async fn fill_login(p: &mut Page, cred: &Cred) -> Result<Value> {
    let (pass_sel, user_sel) = (sel(cred, "pass_selector", PASS_SEL), sel(cred, "user_selector", USER_SEL));
    let pw: Field = ("first", pass_sel);
    if !p.wait(VISIBLE, ("first", &format!("{pass_sel}, {user_sel}")), 10).await {
        return p.result("no login form found on the page").await;
    }
    if !p.wait(VISIBLE, pw, 0).await {
        // username-first flow: submit the username, then wait for the password field
        let user = ("first", user_sel);
        p.fill(cred, user, &cred.username).await?;
        p.submit(cred, user).await?;
        if !p.wait(VISIBLE, pw, 10).await {
            return p.result("username submitted but no password field appeared").await;
        }
    } else {
        let user = if cred.field("user_selector").is_empty() { ("before", pass_sel) } else { ("first", user_sel) };
        if !cred.username.is_empty() && p.wait(VISIBLE, user, 0).await {
            p.fill(cred, user, &cred.username).await?;
        }
    }
    p.fill(cred, pw, &cred.password).await?;
    p.submit(cred, pw).await?;
    if !p.wait(GONE, pw, 15).await {
        if p.wait(VISIBLE, pw, 0).await {
            p.dom(FILL, &[json!(pw.0), json!(pw.1), json!(""), Value::Null]).await?; // don't leave the password in the shared browser
        }
        return p.result("password field still visible after submit (wrong credentials or blocked?)").await;
    }
    if !cred.totp.is_empty() {
        let code = ("first", OTP_SEL);
        if !p.wait(VISIBLE, code, 5).await {
            return p.result("submitted (no TOTP field appeared)").await;
        }
        p.fill(cred, code, &totp_now(cred).unwrap_or_default()).await?;
        p.submit(cred, code).await?;
        if !p.wait(GONE, code, 15).await {
            return p.result("TOTP field still visible after submit").await;
        }
    }
    p.result("submitted").await
}

fn sel<'a>(cred: &'a Cred, name: &str, default: &'a str) -> &'a str {
    Some(cred.field(name)).filter(|s| !s.is_empty()).unwrap_or(default)
}

/// One DevTools connection to a page target.
struct Page {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl Page {
    async fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        self.next_id += 1;
        let msg = json!({"id": self.next_id, "method": method, "params": params}).to_string();
        self.ws.send(Message::text(msg)).await.map_err(fail)?;
        Ok(self.next_id)
    }

    /// Next message from the browser (a reply or an event).
    async fn next(&mut self) -> Result<Value> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Text(t))) => return serde_json::from_str(&t).map_err(fail),
                Some(Ok(Message::Close(_))) | None => return Err(fail("the browser closed the DevTools connection")),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(fail(e)),
            }
        }
    }

    /// Send a command and wait for its reply; events meanwhile are dropped.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.send(method, params).await?;
        loop {
            let m = self.next().await?;
            if m["id"] == id {
                if let Some(e) = m["error"]["message"].as_str() {
                    return Err(fail(format!("{method}: {e}")));
                }
                return Ok(m["result"].clone());
            }
        }
    }

    /// Navigate and wait for load, answering auth challenges (only seen while Fetch is enabled) at most
    /// `answers` times for allowed URLs. Returns the main document's HTTP status.
    async fn goto(&mut self, cred: &Cred, url: &str, frame: &str, answers: u32) -> Result<Option<u64>> {
        self.call("Page.enable", json!({})).await?;
        self.call("Network.enable", json!({})).await?;
        let nav = self.send("Page.navigate", json!({"url": url})).await?;
        let (mut answered, mut code, mut responded, mut loaded) = (0, None, false, false);
        let wait = async {
            while !(responded && loaded) {
                let m = self.next().await?;
                let ev = &m["params"];
                if m["id"] == nav {
                    if let Some(e) = m["error"]["message"].as_str().or(m["result"]["errorText"].as_str()) {
                        return Err(fail(format!("navigation failed: {e}")));
                    }
                    responded = true;
                    loaded |= m["result"]["loaderId"].is_null(); // same-document navigation: no load event
                    continue;
                }
                match m["method"].as_str().unwrap_or("") {
                    "Fetch.authRequired" => {
                        let ok = answered < answers && not_allowed(cred, ev["request"]["url"].as_str().unwrap_or("")).is_none();
                        answered += ok as u32;
                        let resp = if ok {
                            json!({"response": "ProvideCredentials", "username": cred.username, "password": cred.password.as_str()})
                        } else {
                            json!({"response": "CancelAuth"})
                        };
                        self.send("Fetch.continueWithAuth", json!({"requestId": ev["requestId"], "authChallengeResponse": resp})).await?;
                    }
                    "Fetch.requestPaused" => {
                        self.send("Fetch.continueRequest", json!({"requestId": ev["requestId"]})).await?;
                    }
                    "Network.responseReceived" if ev["type"] == "Document" && ev["frameId"] == frame => {
                        code = ev["response"]["status"].as_u64();
                    }
                    "Page.loadEventFired" => loaded = true,
                    _ => {}
                }
            }
            Ok(())
        };
        timeout(Duration::from_secs(30), wait).await.map_err(|_| fail("navigation timed out"))??;
        Ok(code)
    }

    /// Run `PRELUDE + body` in the page with `args` as `a` (values never go into the script text).
    async fn dom(&mut self, body: &str, args: &[Value]) -> Result<Value> {
        let win = self.call("Runtime.evaluate", json!({"expression": "window"})).await?;
        let args: Vec<Value> = args.iter().map(|v| json!({"value": v})).collect();
        let r = self
            .call(
                "Runtime.callFunctionOn",
                json!({"objectId": win["result"]["objectId"], "functionDeclaration": format!("function(...a) {{{PRELUDE}{body}}}"),
                       "arguments": args, "returnByValue": true}),
            )
            .await?;
        if let Some(e) = r.get("exceptionDetails") {
            let text = e["exception"]["description"].as_str().or(e["text"].as_str()).unwrap_or("error");
            return Err(fail(format!("page script failed: {text}")));
        }
        Ok(r["result"]["value"].clone())
    }

    /// Poll `check` (VISIBLE or GONE) on `f` for up to `secs` seconds; errors (mid-navigation) count as no.
    async fn wait(&mut self, check: &str, f: Field<'_>, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        loop {
            if self.dom(check, &[json!(f.0), json!(f.1)]).await.ok() == Some(Value::Bool(true)) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Type `value` into `f`, but only while the page is on a host this credential may use.
    async fn fill(&mut self, cred: &Cred, f: Field<'_>, value: &str) -> Result<()> {
        let href = self.dom("return location.href;", &[]).await?;
        if let Some(why) = not_allowed(cred, href.as_str().unwrap_or("")) {
            return Err(Error::Refused(format!("login page is on a host this credential may not use: {why}")));
        }
        if self.dom(FILL, &[json!(f.0), json!(f.1), json!(value), href]).await? != Value::Bool(true) {
            return Err(Error::Refused("login page moved while filling in the form".into()));
        }
        Ok(())
    }

    async fn submit(&mut self, cred: &Cred, f: Field<'_>) -> Result<()> {
        let clicked = self.dom(SUBMIT, &[json!(f.0), json!(f.1), json!(cred.field("submit_selector")), json!(SUBMIT_SEL)]).await?;
        if clicked != Value::Bool(true) {
            for kind in ["keyDown", "keyUp"] {
                let key = json!({"type": kind, "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "text": "\r"});
                self.call("Input.dispatchKeyEvent", key).await?;
            }
        }
        Ok(())
    }

    async fn result(&mut self, status: &str) -> Result<Value> {
        let v = self.dom("return [location.href, document.title];", &[]).await?;
        Ok(json!({"status": status, "url": v[0], "title": v[1]}))
    }
}

/// msedge or chrome: PATH, then Program Files, then LocalAppData.
fn browser_exe() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let on_path = std::env::split_paths(&path).flat_map(|d| [d.join("msedge.exe"), d.join("chrome.exe")]);
    let installed = ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"].into_iter().flat_map(|base| {
        let base = PathBuf::from(std::env::var_os(base).unwrap_or_default());
        [base.join(r"Microsoft\Edge\Application\msedge.exe"), base.join(r"Google\Chrome\Application\chrome.exe")]
    });
    on_path.chain(installed).find(|p| p.is_file())
}

/// Start Edge (or Chrome) with --remote-debugging-port and valet's own profile.
pub fn start(cdp: &str, home: &Path) -> anyhow::Result<()> {
    let port = url::Url::parse(cdp)?.port().unwrap_or(9333);
    let exe = browser_exe().ok_or_else(|| anyhow::anyhow!("Neither Microsoft Edge nor Google Chrome was found."))?;
    let profile = home.join("browser-profile");
    std::process::Command::new(&exe)
        .arg(format!("--remote-debugging-port={port}"))
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg("--no-first-run")
        .spawn()?;
    println!("Started {}\nCDP endpoint: http://127.0.0.1:{port}\nProfile: {}", exe.display(), profile.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    use super::*;

    const PASSWORD: &str = "P@ss-test-456";
    const SEED: &str = "JBSWY3DPEHPK3PXP";
    const LOGIN: &str = r#"<title>Sign in</title><input type=text name=q placeholder=search>
<form method=post action=/login><input type=text name=user><input type=password name=pass>
<button type=button>show</button><button type=submit>Sign in</button></form>"#;
    const OTP_PAGE: &str = r#"<title>Code</title><form method=post action=/otp>
<input name=code autocomplete=one-time-code><button type=submit>Verify</button></form>"#;
    const FIRST: &str = "<title>First</title><form method=post action=/first><input type=text name=email></form>";
    const SECOND: &str = r#"<title>Password</title><form method=post action=/login>
<input type=hidden name=user value=plain-user><input type=password name=pass></form>"#;

    fn cred(name: &str, uri: &str, password: &str, username: &str, totp: &str, fields: &[(&str, &str)]) -> Cred {
        Cred {
            id: format!("id-{name}"),
            name: name.into(),
            username: username.into(),
            password: Zeroizing::new(password.into()),
            totp: Zeroizing::new(totp.into()),
            uris: vec![uri.into()],
            fields: fields.iter().map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string()))).collect(),
        }
    }

    /// The login site from conftest.py; records (method, path, body) of every request.
    struct Site {
        url: String,
        seen: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    async fn site() -> Site {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let web = cred("web", &url, PASSWORD, "web-user", SEED, &[]);
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(handle(s, port, log.clone(), web.clone()));
            }
        });
        Site { url, seen }
    }

    async fn handle(mut s: TcpStream, port: u16, seen: Arc<Mutex<Vec<(String, String, String)>>>, web: Cred) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let header = |name: &str| {
            head.lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
                .unwrap_or_default()
        };
        let len: usize = header("content-length").parse().unwrap_or(0);
        while buf.len() < head_end + len {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
        let mut words = head.split_whitespace();
        let (method, path) = (words.next().unwrap_or("").to_string(), words.next().unwrap_or("").to_string());
        seen.lock().unwrap().push((method.clone(), path.clone(), body.clone()));
        let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
        let cookie = header("cookie");
        let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
        let page = |html: &str| (200, String::new(), html.to_string());
        let redirect = |to: &str, c: &str| {
            let set = if c.is_empty() { String::new() } else { format!("Set-Cookie: session={c}; Path=/\r\n") };
            (302, format!("Location: {to}\r\n{set}"), String::new())
        };
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("ntlm-user:{PASSWORD}")));
        let (code, extra, html) = match (method.as_str(), path.as_str()) {
            ("GET", "/login") => page(LOGIN),
            ("POST", "/login") if get("pass") != PASSWORD || !["web-user", "plain-user"].contains(&get("user")) => page(LOGIN),
            ("POST", "/login") if get("user") == "web-user" => redirect("/otp", "half"),
            ("POST", "/login") => redirect("/welcome", "ok"),
            ("GET", "/otp") => page(OTP_PAGE),
            ("POST", "/otp") if cookie.contains("session=half") && totp_now(&web).as_deref().map(String::as_str) == Some(get("code")) => {
                redirect("/welcome", "ok")
            }
            ("POST", "/otp") => page(OTP_PAGE),
            (_, "/welcome") if !cookie.contains("session=ok") => redirect("/login", ""),
            (_, "/welcome") => page("<title>Welcome</title><h1>Welcome</h1>"),
            (_, "/elsewhere") => redirect(&format!("http://localhost:{port}/login"), ""),
            ("GET", "/first") => page(FIRST),
            ("POST", "/first") if get("email") == "plain-user" => page(SECOND),
            ("POST", "/first") => page(FIRST),
            (_, "/intranet") if header("authorization") == basic => page("<title>Intranet</title>"),
            (_, "/intranet") => (401, "WWW-Authenticate: Basic realm=\"intranet\"\r\n".into(), "<title>401</title>".into()),
            _ => (404, String::new(), String::new()),
        };
        let resp = format!(
            "HTTP/1.1 {code} X\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{html}",
            html.len()
        );
        let _ = s.write_all(resp.as_bytes()).await;
    }

    /// A headless Edge with its own temporary profile, killed on drop.
    struct Edge {
        child: std::process::Child,
        dir: PathBuf,
        cdp: String,
    }

    impl Drop for Edge {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn edge() -> Edge {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("valet-test-profile-{port}"));
        let child = std::process::Command::new(browser_exe().expect("Edge or Chrome installed"))
            .args(["--headless=new", "--no-first-run", "--disable-background-networking", "about:blank"])
            .arg(format!("--remote-debugging-port={port}"))
            .arg(format!("--user-data-dir={}", dir.display()))
            .spawn()
            .unwrap();
        let edge = Edge { child, dir, cdp: format!("http://127.0.0.1:{port}") };
        for _ in 0..100 {
            if reqwest::get(format!("{}/json/version", edge.cdp)).await.is_ok() {
                return edge;
            }
            sleep(Duration::from_millis(100)).await;
        }
        panic!("browser did not start");
    }

    fn assert_clean(out: &Value, c: &Cred) {
        let text = out.to_string();
        assert!(!text.contains(PASSWORD) && !text.contains("P%40ss"), "{text}");
        if let Some(code) = totp_now(c) {
            assert!(!text.contains(code.as_str()), "{text}");
        }
    }

    async fn page_tabs(cdp: &str) -> usize {
        let tabs: Vec<Value> = reqwest::get(format!("{cdp}/json/list")).await.unwrap().json().await.unwrap();
        tabs.iter().filter(|t| t["type"] == "page").count()
    }

    #[tokio::test]
    async fn login_with_totp() {
        let (s, e) = (site().await, edge().await);
        let web = cred("web", &format!("{}/login", s.url), PASSWORD, "web-user", SEED, &[]);
        let out = login(&web, None, &e.cdp).await.unwrap(); // opens the item's first URI in a new tab
        assert_eq!(out["status"], "submitted", "{out}");
        assert_eq!(out["url"], format!("{}/welcome", s.url));
        assert_eq!(out["title"], "Welcome");
        assert_clean(&out, &web);
    }

    #[tokio::test]
    async fn login_without_totp_reuses_tab() {
        let (s, e) = (site().await, edge().await);
        let plain = cred("web-plain", &format!("{}/login", s.url), PASSWORD, "plain-user", "", &[("broker_auth", "form")]);
        let url = format!("{}/login", s.url);
        login(&plain, Some(&url), &e.cdp).await.unwrap();
        let tabs = page_tabs(&e.cdp).await;
        let out = login(&plain, Some(&url), &e.cdp).await.unwrap();
        assert_eq!(out["status"], "submitted", "{out}");
        assert_eq!(out["title"], "Welcome");
        assert_eq!(page_tabs(&e.cdp).await, tabs);
        assert_clean(&out, &plain);
    }

    #[tokio::test]
    async fn username_first_flow_submits_with_enter() {
        let (s, e) = (site().await, edge().await);
        let plain = cred("web-plain", &format!("{}/login", s.url), PASSWORD, "plain-user", "", &[]);
        let out = login(&plain, Some(&format!("{}/first", s.url)), &e.cdp).await.unwrap();
        assert_eq!(out["status"], "submitted", "{out}");
        assert_eq!(out["title"], "Welcome");
    }

    #[tokio::test]
    async fn wrong_password_reported_without_leak() {
        let (s, e) = (site().await, edge().await);
        let web = cred("web", &format!("{}/login", s.url), "Wr0ng-test-pass", "web-user", SEED, &[]);
        let out = login(&web, None, &e.cdp).await.unwrap();
        assert!(out["status"].as_str().unwrap().contains("still visible"), "{out}");
        assert_eq!(out["title"], "Sign in");
        assert!(!out.to_string().contains("Wr0ng"));
    }

    #[tokio::test]
    async fn refuses_to_type_on_foreign_host() {
        let (s, e) = (site().await, edge().await);
        let web = cred("web", &format!("{}/login", s.url), PASSWORD, "web-user", SEED, &[]);
        let err = login(&web, Some(&format!("{}/elsewhere", s.url)), &e.cdp).await.unwrap_err(); // redirects to localhost
        assert!(matches!(&err, Error::Refused(m) if m.contains("may not use")), "{err}");
        assert!(!s.seen.lock().unwrap().iter().any(|(m, p, b)| m == "POST" && p == "/login" && !b.is_empty()));
    }

    #[tokio::test]
    async fn refuses_url_the_item_may_not_use() {
        let web = cred("web", "http://127.0.0.1:1/login", PASSWORD, "web-user", "", &[]);
        let err = login(&web, Some("https://example.com/login"), "http://127.0.0.1:1").await.unwrap_err();
        assert!(matches!(err, Error::Refused(_)), "{err}");
    }

    #[tokio::test]
    async fn no_browser_does_not_leak() {
        let web = cred("web", "http://127.0.0.1:1/login", PASSWORD, "web-user", SEED, &[]);
        let err = login(&web, None, "http://127.0.0.1:1").await.unwrap_err(); // nothing listens there
        assert!(matches!(err, Error::Failed(_)), "{err}");
        assert!(!err.to_string().contains(PASSWORD));
    }

    #[tokio::test]
    async fn windows_sign_in_answers_challenge() {
        let (s, e) = (site().await, edge().await);
        let url = format!("{}/intranet", s.url);
        let ok = cred("intranet", &url, PASSWORD, "ntlm-user", "", &[("broker_auth", "ntlm")]);
        let out = login(&ok, None, &e.cdp).await.unwrap();
        assert_eq!(out["status"], "signed in", "{out}");
        assert_eq!(out["title"], "Intranet");
        assert_clean(&out, &ok);
    }

    #[tokio::test]
    async fn windows_sign_in_wrong_password_gives_up() {
        let (s, e) = (site().await, edge().await);
        let url = format!("{}/intranet", s.url);
        let bad = cred("intranet", &url, "Wr0ng-test-pass", "ntlm-user", "", &[("broker_auth", "ntlm")]);
        let out = login(&bad, None, &e.cdp).await.unwrap();
        assert_eq!(out["status"], "sign-in failed (HTTP 401)", "{out}");
        let challenges = s.seen.lock().unwrap().iter().filter(|(_, p, _)| p == "/intranet").count();
        assert!(challenges <= 4, "{challenges} requests"); // at most 3 answers, then cancel
    }
}
