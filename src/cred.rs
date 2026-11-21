//! A vault login as the broker sees it, plus the rules about where it may be used.
//! Shared by every module; owned by core.

use std::collections::HashMap;

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

/// Default `broker_auth` for the web tools.
pub const AUTH: &[(&str, &str)] = &[("http_request", "bearer"), ("browser_login", "form")];
/// Default `broker_approval` per tool.
pub const APPROVAL: &[(&str, &str)] = &[
    ("http_request", "never"),
    ("browser_login", "daily"),
    ("ssh_exec", "daily"),
    ("win_exec", "daily"),
    ("sql_query", "daily"),
    ("rdp_open", "never"),
    ("run", "daily"),
];
/// Non-web URI schemes and their default ports.
pub const PORTS: &[(&str, u16)] = &[("ssh", 22), ("rdp", 3389), ("winrm", 5985), ("winrms", 5986), ("mssql", 1433)];
/// Which tool uses which non-web scheme.
pub const SCHEME_TOOLS: &[(&str, &str)] =
    &[("ssh", "ssh_exec"), ("rdp", "rdp_open"), ("winrm", "win_exec"), ("winrms", "win_exec"), ("mssql", "sql_query")];

pub fn lookup<'a>(table: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

pub fn default_port(scheme: &str) -> Option<u16> {
    PORTS.iter().find(|(s, _)| *s == scheme).map(|(_, p)| *p)
}

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

    pub fn field(&self, name: &str) -> &str {
        self.fields.get(name).map(|v| v.as_str()).unwrap_or("")
    }

    pub fn auth(&self, tool: &str) -> String {
        let f = self.field("broker_auth");
        if f.is_empty() { lookup(AUTH, tool).unwrap_or("").to_string() } else { f.to_string() }
    }

    pub fn approval(&self, tool: &str) -> String {
        let f = self.field("broker_approval");
        if f.is_empty() { lookup(APPROVAL, tool).unwrap_or("always").to_string() } else { f.to_string() }
    }

    pub fn flag(&self, name: &str) -> bool {
        matches!(self.field(name).to_lowercase().as_str(), "yes" | "true" | "1")
    }
}
