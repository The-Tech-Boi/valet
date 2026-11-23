//! Approval, unlock and setup windows. Design: mocks/approval-dialog.html variant A,
//! mocks/setup-window.html. One UI thread for the agent's lifetime; windows (WebView2) exist only
//! while shown, so the idle agent carries no browser engine.
//!
//! Page protocol (window.ipc.postMessage): "size:<css px height>" when loaded or resized, then one
//! answer: "today" | "once" | "deny" from the approval page, "ok:<password>" | "cancel" from the
//! unlock page, "ok:<server>\n<client_id>\n<client_secret>" | "cancel" from the setup page.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use serde_json::{json, Value};
use tao::dpi::{LogicalSize, PhysicalPosition};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::windows::{EventLoopBuilderExtWindows, IconExtWindows};
use tao::window::{Icon, Window, WindowBuilder};
use wry::{WebContext, WebView, WebViewBuilder};
use zeroize::Zeroizing;

use crate::broker::{Answer, Approval};

const APPROVAL_HTML: &str = include_str!("ui/approval.html");
const UNLOCK_HTML: &str = include_str!("ui/unlock.html");
const SETUP_HTML: &str = include_str!("ui/setup.html");
/// The page denies at 60 s; this catches a page that never answers.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(65);
/// Typing a master password can take a while; a window that vanishes mid-typing is worse.
const UNLOCK_TIMEOUT: Duration = Duration::from_secs(300);
const WIDTH: f64 = 460.0;

enum Msg {
    Show { id: u64, html: &'static str, data: String, reply: Sender<Zeroizing<String>> },
    Ipc(u64, Zeroizing<String>),
    Close(u64),
}

pub struct Ui(EventLoopProxy<Msg>);

impl Ui {
    pub fn start() -> Ui {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || run(tx));
        Ui(rx.recv().expect("ui thread failed to start"))
    }

    /// Blocks until the user answers. Closing the window or 60 s without an answer = Deny.
    pub fn approve(&self, request: &Approval) -> Answer {
        self.approve_within(request, APPROVAL_TIMEOUT)
    }

    fn approve_within(&self, request: &Approval, timeout: Duration) -> Answer {
        parse_answer(self.ask(APPROVAL_HTML, approval_page(request), timeout).as_deref().map(String::as_str))
    }

    /// Blocks; None if cancelled. `error` is shown after a wrong password.
    pub fn master_password(&self, email: &str, error: Option<&str>) -> Option<Zeroizing<String>> {
        parse_password(self.ask(UNLOCK_HTML, json!({"email": email, "error": error}), UNLOCK_TIMEOUT)?)
    }

    /// Blocks; None if cancelled. `server` and `client_id` prefill the form, `error` is the last failure.
    pub fn api_key(&self, server: &str, client_id: &str, error: Option<&str>) -> Option<ApiKey> {
        let data = json!({"server": server, "client_id": client_id, "error": error});
        parse_api_key(self.ask(SETUP_HTML, data, UNLOCK_TIMEOUT)?)
    }

    /// Shows a page and returns its answer; None if the window was closed, failed, or timed out.
    fn ask(&self, html: &'static str, data: Value, timeout: Duration) -> Option<Zeroizing<String>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let (reply, rx) = mpsc::channel();
        // serde_json output is a valid JS expression with every special character escaped.
        let data = format!("window.valet = {data};");
        self.0.send_event(Msg::Show { id, html, data, reply }).ok()?;
        let answer = rx.recv_timeout(timeout).ok();
        if answer.is_none() {
            let _ = self.0.send_event(Msg::Close(id));
        }
        answer
    }
}

fn parse_answer(body: Option<&str>) -> Answer {
    match body {
        Some("today") => Answer::Today,
        Some("once") => Answer::Once,
        _ => Answer::Deny,
    }
}

fn parse_password(mut body: Zeroizing<String>) -> Option<Zeroizing<String>> {
    if !body.starts_with("ok:") {
        return None;
    }
    body.drain(..3);
    Some(body)
}

pub struct ApiKey {
    pub server: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
}

fn parse_api_key(body: Zeroizing<String>) -> Option<ApiKey> {
    let mut parts = body.strip_prefix("ok:")?.splitn(3, '\n');
    let (server, client_id, secret) = (parts.next()?, parts.next()?, parts.next()?);
    Some(ApiKey { server: server.into(), client_id: client_id.into(), client_secret: Zeroizing::new(secret.into()) })
}

/// What the approval page shows for a request.
fn approval_page(r: &Approval) -> Value {
    // (it wants to ..., target label, detail label, protocol)
    let (what, target, detail, proto) = match r.tool.as_str() {
        "ssh_exec" => ("run a command on a server with this login", "Server", "Command", "SSH"),
        "win_exec" => ("run a command on a server with this login", "Server", "Command", "WinRM"),
        "sql_query" => ("run a SQL query with this login", "Server", "Query", "SQL Server"),
        "browser_login" => ("sign in to a website with this login", "Website", "Page", ""),
        "http_request" => ("call an API with this login", "Server", "Request", ""),
        "rdp_open" => ("open Remote Desktop with this login", "Server", "Details", "Remote Desktop"),
        "run" => ("give this login to a script", "Script", "Details", ""),
        "check_credentials" => ("test signing in with these logins", "Targets", "Details", ""),
        _ => ("use this login", "Target", "Details", ""),
    };
    let target_text = if proto.is_empty() || r.target.contains("://") {
        r.target.clone()
    } else {
        format!("{} · {proto}", r.target)
    };
    let rows: Vec<Value> = [
        json!({"label": "Login", "text": r.credential, "note": r.username}),
        json!({"label": target, "text": target_text}),
        json!({"label": detail, "text": r.detail, "code": true}),
        json!({"label": "Asked by", "text": r.caller}),
    ]
    .into_iter()
    .filter(|row| row["text"] != "")
    .collect();
    let fine = if r.tool == "run" {
        "Only the script gets the password. The assistant never sees it."
    } else {
        "The password is used by valet only. The assistant never sees it."
    };
    json!({
        "question": format!("Allow the coding assistant to use {}?", r.credential),
        "sub": format!("It wants to {what}."),
        "rows": rows,
        "fine": fine,
    })
}

/// The UI thread: owns every window and webview; never returns.
fn run(started: Sender<EventLoopProxy<Msg>>) {
    let event_loop = EventLoopBuilder::<Msg>::with_user_event().with_any_thread(true).build();
    let proxy = event_loop.create_proxy();
    started.send(proxy.clone()).unwrap();
    // Without a data directory WebView2 writes "valet.exe.WebView2" next to the binary.
    let mut context = WebContext::new(Some(crate::agent::home().join("webview")));
    let mut open: HashMap<u64, (Window, WebView, Sender<Zeroizing<String>>)> = HashMap::new();

    event_loop.run(move |event, target, flow| {
        *flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(Msg::Show { id, html, data, reply }) => {
                let window = WindowBuilder::new()
                    .with_title("valet")
                    .with_window_icon(Icon::from_resource(1, None).ok()) // assets/valet.rc
                    .with_inner_size(LogicalSize::new(WIDTH, 400.0))
                    .with_visible(false)
                    .with_resizable(false)
                    .with_minimizable(false)
                    .with_maximizable(false)
                    .with_always_on_top(true)
                    .build(target);
                let Ok(window) = window else { return };
                let proxy = proxy.clone();
                let webview = WebViewBuilder::new_with_web_context(&mut context)
                    .with_html(html)
                    .with_initialization_script(data)
                    .with_ipc_handler(move |req| {
                        let _ = proxy.send_event(Msg::Ipc(id, Zeroizing::new(req.into_body())));
                    })
                    .build(&window);
                if let Ok(webview) = webview {
                    open.insert(id, (window, webview, reply));
                }
            }
            Event::UserEvent(Msg::Ipc(id, body)) => {
                if let Some(height) = body.strip_prefix("size:").and_then(|h| h.parse::<f64>().ok()) {
                    if let Some((window, webview, _)) = open.get(&id) {
                        window.set_inner_size(LogicalSize::new(WIDTH, height));
                        if window.is_visible() {
                            return; // a later resize: keep the window where the user sees it
                        }
                        if let Some(m) = window.current_monitor() {
                            let (screen, size) = (m.size(), window.outer_size());
                            let x = m.position().x + (screen.width as i32 - size.width as i32) / 2;
                            let y = m.position().y + (screen.height as i32 - size.height as i32) / 2;
                            window.set_outer_position(PhysicalPosition::new(x, y));
                        }
                        window.set_visible(true);
                        window.set_focus();
                        let _ = webview.focus();
                    }
                } else if let Some((_, _, reply)) = open.remove(&id) {
                    let _ = reply.send(body);
                }
            }
            Event::UserEvent(Msg::Close(id)) => {
                open.remove(&id);
            }
            Event::WindowEvent { window_id, event: WindowEvent::CloseRequested, .. } => {
                // Dropping the reply sender answers Deny / None.
                open.retain(|_, (w, _, _)| w.id() != window_id);
            }
            _ => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(tool: &str, target: &str, detail: &str) -> Approval {
        Approval {
            credential: "Example-CRM".into(),
            username: r"CORP\jdoe".into(),
            tool: tool.into(),
            target: target.into(),
            detail: detail.into(),
            caller: "code.exe (pid 1234)".into(),
        }
    }

    #[test]
    fn approval_page_rows() {
        let page = approval_page(&request("win_exec", "crm.example.local", "Get-Service MSCRM*"));
        assert_eq!(page["question"], "Allow the coding assistant to use Example-CRM?");
        assert_eq!(page["sub"], "It wants to run a command on a server with this login.");
        assert_eq!(
            page["rows"],
            json!([
                {"label": "Login", "text": "Example-CRM", "note": r"CORP\jdoe"},
                {"label": "Server", "text": "crm.example.local · WinRM"},
                {"label": "Command", "text": "Get-Service MSCRM*", "code": true},
                {"label": "Asked by", "text": "code.exe (pid 1234)"},
            ])
        );
    }

    #[test]
    fn approval_page_per_tool() {
        let page = approval_page(&request("rdp_open", "rdp://crm:3389", ""));
        assert_eq!(page["sub"], "It wants to open Remote Desktop with this login.");
        assert_eq!(page["rows"][1]["text"], "rdp://crm:3389");
        assert_eq!(page["rows"].as_array().unwrap().len(), 3, "empty detail row is dropped");
        let page = approval_page(&request("http_request", "api.example.com", "GET /v1/items"));
        assert_eq!(page["sub"], "It wants to call an API with this login.");
        assert_eq!(page["rows"][2]["label"], "Request");
        let page = approval_page(&request("run", "python job.py", ""));
        assert_eq!(page["sub"], "It wants to give this login to a script.");
        assert!(page["fine"].as_str().unwrap().contains("script"));
    }

    #[test]
    fn page_data_is_escaped() {
        let mut r = request("sql_query", "db", "SELECT '</script>' -- \"x\"\n\u{2028}");
        r.credential = "a\"b\\c".into();
        let page = approval_page(&r);
        let back: Value = serde_json::from_str(&page.to_string()).unwrap();
        assert_eq!(back["rows"][2]["text"], r.detail);
        assert_eq!(back["question"], "Allow the coding assistant to use a\"b\\c?");
    }

    #[test]
    fn answers() {
        assert_eq!(parse_answer(Some("today")), Answer::Today);
        assert_eq!(parse_answer(Some("once")), Answer::Once);
        for other in [Some("deny"), Some("Today"), Some(""), Some("size:300"), None] {
            assert_eq!(parse_answer(other), Answer::Deny);
        }
        let pw = |s: &str| parse_password(Zeroizing::new(s.to_string())).map(|p| p.to_string());
        assert_eq!(pw("ok:hunter2:x"), Some("hunter2:x".into()));
        assert_eq!(pw("ok:"), Some(String::new()));
        assert_eq!(pw("cancel"), None);
        assert_eq!(pw("deny"), None);
        let key = parse_api_key(Zeroizing::new("ok:https://v.example\nuser.1\ns3c:r\net".into())).unwrap();
        assert_eq!((key.server.as_str(), key.client_id.as_str()), ("https://v.example", "user.1"));
        assert_eq!(*key.client_secret, "s3c:r\net");
        for other in ["cancel", "ok:https://v.example\nuser.1", "size:300"] {
            assert!(parse_api_key(Zeroizing::new(other.into())).is_none(), "{other}");
        }
    }

    fn private_mb() -> String {
        let pid = std::process::id();
        // Own private bytes, plus the WebView2 processes started for us (child or not).
        let ps = format!(
            "$w = @(Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" | \
             Where-Object {{ $_.CommandLine -like '*valet*webview*' }}); \
             '{{0:N1}} MB private; WebView2: {{1}} processes, {{2:N1}} MB private' -f \
             ((Get-Process -Id {pid}).PrivateMemorySize64/1MB), $w.Count, \
             (($w | ForEach-Object {{ (Get-Process -Id $_.ProcessId).PrivateMemorySize64 }} | Measure-Object -Sum).Sum/1MB)"
        );
        let out = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &ps]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Shows a real window. `cargo test ui::tests::memory -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn memory() {
        let ui = Ui::start();
        std::thread::sleep(Duration::from_secs(1));
        println!("idle:   {}", private_mb());
        let answer = std::thread::scope(|s| {
            let shown = s.spawn(|| ui.approve_within(&request("ssh_exec", "crm", "uptime"), Duration::from_secs(6)));
            std::thread::sleep(Duration::from_secs(4));
            println!("shown:  {}", private_mb());
            shown.join().unwrap()
        });
        assert_eq!(answer, Answer::Deny);
        std::thread::sleep(Duration::from_secs(2));
        println!("closed: {}", private_mb());
        std::thread::sleep(Duration::from_secs(8));
        println!("later:  {}", private_mb());
    }
}
