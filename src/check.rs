//! check_credentials: try each item's sign-in on each of its URIs, after one approval for the batch.
//! Credentials only go to endpoints the item lists; a URI without a scheme is not signed in to.

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::future::join_all;
use serde_json::{json, Value};
use url::Url;

use crate::audit;
use crate::broker::{opt, Answer, Approval, Broker};
use crate::cred::{default_port, fail, Cred, Endpoint, Error, Result, Tool};
use crate::redact::{scrub, Redactor};
use crate::{http, sql, ssh, winrm};

impl Broker {
    pub(crate) async fn check(&self, args: &Value, caller: &str) -> Result<Value> {
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
                check_one(c, u).await.unwrap_or_else(|e| ("failed", e.to_string().chars().take(300).collect()))
            };
            let r = Redactor::for_cred(c);
            let entry = audit::Entry {
                tool: "check_credentials".into(),
                credential: c.name.clone(),
                target: Some(u.split('?').next().unwrap_or("").into()),
                result: result.into(),
                ..Default::default()
            };
            audit::write(&self.home, entry, &r);
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
}

async fn check_one(c: &Cred, uri: &str) -> Result<(&'static str, String)> {
    if !uri.contains("://") {
        return bare_host(uri).await;
    }
    let u = Url::parse(uri).map_err(fail)?;
    match u.scheme() {
        "http" | "https" => {
            if c.auth(Tool::HttpRequest) == "form" {
                return Ok(("skipped", "web form login (check it with browser_login)".into()));
            }
            c.check_url(uri)?;
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

/// A host without a scheme (e.g. from an import) names no service, so nothing signs in there;
/// the answer only says which server ports are open.
async fn bare_host(uri: &str) -> Result<(&'static str, String)> {
    let host = Url::parse(&format!("http://{uri}"))
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_string()))
        .ok_or_else(|| Error::Refused(format!("{uri:?} is not a host")))?;
    let ports: Vec<(&str, u16)> =
        Tool::ALL.iter().flat_map(|t| t.schemes()).filter_map(|s| Some((*s, default_port(s)?))).collect();
    let open = join_all(ports.iter().map(|(_, p)| port_open(&host, *p))).await;
    let open: Vec<String> = ports.iter().zip(open).filter(|(_, o)| *o).map(|((s, p), _)| format!("{s} {p}")).collect();
    let seen = if open.is_empty() { "no server port open".to_string() } else { format!("open: {}", open.join(", ")) };
    Ok(("skipped", format!("no scheme, so not signed in; give the URI one, e.g. ssh://{host} ({seen})")))
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

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::tests::{assert_clean, broker, items, rt, temp_home};
    use crate::cred::tests::PASSWORD;

    #[test]
    fn check_credentials_skips_and_asks_once() {
        let home = temp_home("check");
        let mut c = items();
        c.push(Cred::test("no-uri", &[], PASSWORD, &[]));
        c.push(Cred::test("odd", &["ftp://files.test"], PASSWORD, &[]));
        c.push(Cred::test("desk", &["rdp://10.0.0.7"], PASSWORD, &[]));
        c.push(Cred::test("bare", &["127.0.0.1"], PASSWORD, &[]));
        let (b, calls) = broker(c, Answer::Once, &home);
        let names = ["web-plain", "desk", "no-uri", "odd", "bare"];
        let out = rt().block_on(b.call("check_credentials", json!({ "credentials": names }), "t"));
        let got: Vec<&str> = out["results"].as_array().unwrap().iter().map(|r| r["result"].as_str().unwrap()).collect();
        assert_eq!(got, ["skipped"; 5]);
        assert_eq!(out["summary"], json!({"ok": 0, "failed": 0, "skipped": 5}));
        let bare = out["results"].as_array().unwrap().iter().find(|r| r["credential"] == "bare").unwrap();
        assert!(bare["detail"].as_str().unwrap().contains("give the URI one, e.g. ssh://127.0.0.1"), "{bare}");
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(calls.lock().unwrap()[0].credential, "5 credentials");
        let (b, _) = broker(items(), Answer::Deny, &home);
        let out = rt().block_on(b.call("check_credentials", json!({"credentials": ["web-plain"]}), "t"));
        assert_eq!(out["error"], "the user denied check_credentials");
        assert_clean(&std::fs::read_to_string(home.join("audit.jsonl")).unwrap());
    }
}
