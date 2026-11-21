//! A vault login as the broker sees it, the tools that use it, and the rules about where it may go.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use url::Url;
use zeroize::Zeroizing;

/// Why a call did not run. Messages never contain secrets.
#[derive(Debug)]
pub enum Error {
    /// Policy said no (host not allowed, bad field value, ...).
    Refused(String),
    /// The user said no in the approval window.
    Denied(String),
    /// Anything else: network, protocol, wrong password. First line only.
    Failed(String),
}

impl Error {
    /// The audit log's word for this error.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Refused(_) => "refused",
            Error::Denied(_) => "denied",
            Error::Failed(_) => "error",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Refused(m) | Error::Denied(m) | Error::Failed(m) => f.write_str(m),
        }
    }
}

/// Any other error as `Failed`, first line only, so `?` works on anyhow results.
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        fail(e)
    }
}

/// `Failed` from any error: first line, at most 500 characters (call chains and logs stay out).
pub fn fail(e: impl std::fmt::Display) -> Error {
    let text = e.to_string();
    Error::Failed(text.lines().next().unwrap_or("").chars().take(500).collect())
}

pub type Result<T> = std::result::Result<T, Error>;

/// `f`, or `Failed("<what> timed out ...")`.
pub async fn within<T>(timeout: Duration, what: &str, f: impl Future<Output = T>) -> Result<T> {
    tokio::time::timeout(timeout, f)
        .await
        .map_err(|_| Error::Failed(format!("{what} timed out after {} s", timeout.as_secs())))
}

/// The tools that use a credential: the MCP tools, and "run" for `valet run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    HttpRequest,
    BrowserLogin,
    SshExec,
    WinExec,
    SqlQuery,
    RdpOpen,
    Run,
}

impl Tool {
    pub const ALL: [Tool; 7] =
        [Tool::HttpRequest, Tool::BrowserLogin, Tool::SshExec, Tool::WinExec, Tool::SqlQuery, Tool::RdpOpen, Tool::Run];

    pub fn name(self) -> &'static str {
        match self {
            Tool::HttpRequest => "http_request",
            Tool::BrowserLogin => "browser_login",
            Tool::SshExec => "ssh_exec",
            Tool::WinExec => "win_exec",
            Tool::SqlQuery => "sql_query",
            Tool::RdpOpen => "rdp_open",
            Tool::Run => "run",
        }
    }

    pub fn parse(name: &str) -> Option<Tool> {
        Tool::ALL.into_iter().find(|t| t.name() == name)
    }

    /// The URI schemes a server tool connects to; empty for the others.
    pub fn schemes(self) -> &'static [&'static str] {
        match self {
            Tool::SshExec => &["ssh"],
            Tool::WinExec => &["winrm", "winrms"],
            Tool::SqlQuery => &["mssql"],
            Tool::RdpOpen => &["rdp"],
            _ => &[],
        }
    }

    /// Approval when the item has no `broker_approval`.
    fn default_policy(self) -> Policy {
        match self {
            Tool::HttpRequest | Tool::RdpOpen => Policy::Never,
            _ => Policy::Daily,
        }
    }
}

/// `broker_approval`: when the user is asked before a credential is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Never,
    /// Once a day per credential and tool, if the user answers "today".
    Daily,
    Always,
}

impl Policy {
    pub fn name(self) -> &'static str {
        match self {
            Policy::Never => "never",
            Policy::Daily => "daily",
            Policy::Always => "always",
        }
    }
}

/// How http_request puts the secret into a request (`broker_auth`, default bearer).
#[derive(Debug, PartialEq, Eq)]
pub enum HttpAuth {
    Bearer,
    Basic,
    /// Windows sign-in (Negotiate/NTLM) with the username and password.
    Ntlm,
    /// `header:<Name>`: the secret is the value of that header.
    Header(String),
    /// `query:<param>`: the secret is that query parameter.
    Query(String),
}

/// Default port of each server scheme; None for any other scheme.
pub fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "ssh" => Some(22),
        "rdp" => Some(3389),
        "winrm" => Some(5985),
        "winrms" => Some(5986),
        "mssql" => Some(1433),
        _ => None,
    }
}

const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1", "[::1]"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

#[derive(Clone)]
pub struct Cred {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: Zeroizing<String>,
    /// TOTP seed: base32 or an otpauth:// URI. Empty if none.
    pub totp: Zeroizing<String>,
    pub uris: Vec<String>,
    /// Custom fields, names lowercased and trimmed, values trimmed.
    pub fields: HashMap<String, Zeroizing<String>>,
}

impl Cred {
    /// Hosts of the web URIs (http, https or no scheme): where http_request and browser_login may go.
    pub fn hosts(&self) -> Vec<String> {
        self.uris
            .iter()
            .filter_map(|u| {
                let full = if u.contains("://") { u.clone() } else { format!("https://{u}") };
                let parsed = Url::parse(&full).ok()?;
                if default_port(parsed.scheme()).is_some() {
                    return None;
                }
                parsed.host_str().map(|h| h.to_lowercase())
            })
            .collect()
    }

    /// The ssh://, rdp://, winrm://, winrms:// and mssql:// URIs.
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.uris
            .iter()
            .filter_map(|u| {
                let parsed = Url::parse(u).ok()?;
                let scheme = parsed.scheme().to_lowercase();
                let port = default_port(&scheme)?;
                Some(Endpoint {
                    host: parsed.host_str()?.to_lowercase(),
                    port: parsed.port().unwrap_or(port),
                    scheme,
                })
            })
            .collect()
    }

    /// The item's endpoint for one of `schemes` (and `host`, if given). Credentials only go there.
    pub fn endpoint(&self, schemes: &[&str], host: Option<&str>) -> Result<Endpoint> {
        let all = self.endpoints();
        let host = host.map(str::to_lowercase);
        all.iter()
            .find(|e| schemes.contains(&e.scheme.as_str()) && host.as_ref().is_none_or(|h| *h == e.host))
            .cloned()
            .ok_or_else(|| {
                let listed: Vec<String> = all.iter().map(Endpoint::to_string).collect();
                let listed = if listed.is_empty() { "none".to_string() } else { listed.join(", ") };
                let for_host = host.map(|h| format!(" for host {h:?}")).unwrap_or_default();
                Error::Refused(format!(
                    "credential {:?} has no {}:// URI{for_host} (its endpoints: {listed})",
                    self.name,
                    schemes.join("/")
                ))
            })
    }

    /// Ok if `url` may receive this credential: https (http only for localhost or with
    /// broker_allow_http=yes) on one of the item's web hosts, `*.domain` matching subdomains.
    pub fn check_url(&self, url: &str) -> Result<()> {
        let refuse = |why: String| Err(Error::Refused(why));
        if url.is_empty() {
            return refuse("no URL given and the item has no login URI".into());
        }
        let u = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => return refuse(format!("not a valid URL ({e}); use https://host/path")),
        };
        let host = u.host_str().unwrap_or("").to_lowercase();
        let http_ok = LOCAL_HOSTS.contains(&host.as_str()) || self.flag("broker_allow_http");
        if u.scheme() != "https" && !(u.scheme() == "http" && http_ok) {
            return refuse(format!(
                "{} scheme not allowed; use https (http only for localhost, or items with broker_allow_http=yes)",
                u.scheme()
            ));
        }
        let hosts = self.hosts();
        if !hosts.iter().any(|h| *h == host || (h.starts_with("*.") && host.ends_with(&h[1..]))) {
            let allowed = if hosts.is_empty() { "none".to_string() } else { hosts.join(", ") };
            return refuse(format!("host {host:?} is not allowed for credential {:?} (allowed: {allowed})", self.name));
        }
        Ok(())
    }

    pub fn field(&self, name: &str) -> &str {
        self.fields.get(name).map(|v| v.as_str()).unwrap_or("")
    }

    pub fn flag(&self, name: &str) -> bool {
        matches!(self.field(name).to_lowercase().as_str(), "yes" | "true" | "1")
    }

    /// `broker_auth` as set, or the web tool's default (bearer for http_request, form for browser_login).
    pub fn auth(&self, tool: Tool) -> &str {
        match self.field("broker_auth") {
            "" if tool == Tool::BrowserLogin => "form",
            "" => "bearer",
            a => a,
        }
    }

    pub fn http_auth(&self) -> Result<HttpAuth> {
        let auth = self.auth(Tool::HttpRequest);
        Ok(match auth {
            "bearer" => HttpAuth::Bearer,
            "basic" => HttpAuth::Basic,
            "ntlm" => HttpAuth::Ntlm,
            a if a.starts_with("header:") => HttpAuth::Header(a[7..].trim().to_string()),
            a if a.starts_with("query:") => HttpAuth::Query(a[6..].trim().to_string()),
            _ => {
                return Err(Error::Refused(format!(
                    "credential {:?} has broker_auth={auth:?}, which http_request cannot use",
                    self.name
                )))
            }
        })
    }

    /// "form" or "ntlm" (the browser answers a Windows sign-in challenge); browser_login can use no other.
    pub fn browser_auth(&self) -> Result<&str> {
        match self.auth(Tool::BrowserLogin) {
            a @ ("form" | "ntlm") => Ok(a),
            a => Err(Error::Refused(format!(
                "credential {:?} has broker_auth={a:?}; only form or ntlm items can be used with browser_login",
                self.name
            ))),
        }
    }

    pub fn approval(&self, tool: Tool) -> Result<Policy> {
        match self.field("broker_approval") {
            "" => Ok(tool.default_policy()),
            "never" => Ok(Policy::Never),
            "daily" => Ok(Policy::Daily),
            "always" => Ok(Policy::Always),
            p => Err(Error::Refused(format!("credential {:?} has unknown broker_approval {p:?}", self.name))),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const TOKEN: &str = "tok_test_123";
    pub const PASSWORD: &str = "P@ss-test-456";
    /// RFC 6238 test key "12345678901234567890".
    pub const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    impl Cred {
        /// A test item with username "svc-user" and no TOTP.
        pub fn test(name: &str, uris: &[&str], password: &str, fields: &[(&str, &str)]) -> Cred {
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
    }

    #[test]
    fn scheme_and_wildcard_rules() {
        let c = Cred::test("remote", &["https://api.example.com", "*.example.org", "http://localhost:8080"], "", &[]);
        let why = |c: &Cred, url: &str| c.check_url(url).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(c.check_url("https://api.example.com/v1").is_ok());
        assert!(why(&c, "http://api.example.com/v1").contains("scheme"));
        assert!(why(&c, "ftp://api.example.com/").contains("scheme"));
        assert!(c.check_url("https://a.example.org/").is_ok());
        assert!(c.check_url("https://a.b.example.org/").is_ok());
        assert!(why(&c, "https://example.org/").contains("not allowed"));
        assert!(why(&c, "https://badexample.org/").contains("not allowed"));
        assert!(why(&c, "https://api.example.com.evil.net/").contains("not allowed"));
        assert!(c.check_url("http://localhost:9999/x").is_ok());
        assert!(c.check_url("").is_err() && c.check_url("api.example.com").is_err());
        let lan = Cred::test("n", &["http://10.0.0.5"], "", &[]);
        assert!(why(&lan, "http://10.0.0.5/").contains("scheme"));
        let lan = Cred::test("n", &["http://10.0.0.5"], "", &[("broker_allow_http", "yes")]);
        assert!(lan.check_url("http://10.0.0.5/").is_ok());
        assert!(why(&lan, "ftp://10.0.0.5/").contains("scheme"));
    }

    #[test]
    fn auth_and_policy_fields() {
        let with = |k: &str, v: &str| Cred::test("c", &[], "", &[(k, v)]);
        assert_eq!(Cred::test("c", &[], "", &[]).http_auth().unwrap(), HttpAuth::Bearer);
        assert_eq!(with("broker_auth", "header: X-Key ").http_auth().unwrap(), HttpAuth::Header("X-Key".into()));
        assert_eq!(with("broker_auth", "query:k").http_auth().unwrap(), HttpAuth::Query("k".into()));
        assert!(with("broker_auth", "form").http_auth().is_err() && with("broker_auth", "digest").http_auth().is_err());
        assert_eq!(Cred::test("c", &[], "", &[]).browser_auth().unwrap(), "form");
        assert_eq!(with("broker_auth", "ntlm").browser_auth().unwrap(), "ntlm");
        assert!(with("broker_auth", "basic").browser_auth().is_err());
        assert_eq!(Cred::test("c", &[], "", &[]).approval(Tool::RdpOpen).unwrap(), Policy::Never);
        assert_eq!(Cred::test("c", &[], "", &[]).approval(Tool::Run).unwrap(), Policy::Daily);
        assert_eq!(with("broker_approval", "always").approval(Tool::HttpRequest).unwrap(), Policy::Always);
        assert!(matches!(with("broker_approval", "sometimes").approval(Tool::Run), Err(Error::Refused(_))));
    }
}
