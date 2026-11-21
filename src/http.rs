//! http_request (owner: winauth). Spec: valet/broker.py `Broker._http`.
//! The broker has already checked the URL against the item and asked approval; this module injects
//! the auth (bearer, basic, header:<Name>, query:<param>, ntlm via `sspi`) and sends the request.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Method, Response, StatusCode};
use serde_json::{json, Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::cred::{fail, Cred, Error, Result};
use crate::sspi;

const MAX_BODY: usize = 20_000;
const KEEP_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "location",
    "www-authenticate",
    "retry-after",
    "etag",
    "last-modified",
    "x-request-id",
    "x-ratelimit-remaining",
];

pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub json: Option<Value>,
    pub timeout: Duration,
}

/// Network errors by kind, without the URL (it may carry a query-string secret).
pub(crate) fn net_err(e: reqwest::Error) -> Error {
    let kind = if e.is_timeout() {
        "Timeout"
    } else if e.is_connect() {
        "ConnectError"
    } else {
        "RequestError"
    };
    let e = e.without_url();
    let mut cause: &dyn std::error::Error = &e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    fail(format!("{kind}: {cause}"))
}

fn secret_header(value: &str) -> Result<HeaderValue> {
    let mut v = HeaderValue::from_str(value).map_err(|_| fail("the secret is not a valid HTTP header value"))?;
    v.set_sensitive(true);
    Ok(v)
}

/// The token in a `WWW-Authenticate: <scheme> <base64>` header, if any.
pub(crate) fn challenge(resp: &Response, scheme: &str) -> Option<Vec<u8>> {
    resp.headers().get_all(WWW_AUTHENTICATE).iter().find_map(|v| {
        let (s, token) = v.to_str().ok()?.split_once(' ')?;
        if s.eq_ignore_ascii_case(scheme) { B64.decode(token.trim()).ok() } else { None }
    })
}

/// Returns {"status", "headers" (selected), "body" (truncated at 20000 chars), "truncated"?}.
pub async fn request(cred: &Cred, req: Request) -> Result<Value> {
    let auth = cred.auth("http_request");
    let mut url = Url::parse(&req.url).map_err(fail)?;
    let mut headers = HeaderMap::new();
    for (k, v) in &req.headers {
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(fail)?;
        headers.insert(name, HeaderValue::from_str(v).map_err(fail)?);
    }
    match auth.as_str() {
        "ntlm" => {}
        "bearer" => {
            headers.insert(AUTHORIZATION, secret_header(&Zeroizing::new(format!("Bearer {}", *cred.password)))?);
        }
        "basic" => {
            let pair = Zeroizing::new(format!("{}:{}", cred.username, *cred.password));
            headers.insert(AUTHORIZATION, secret_header(&Zeroizing::new(format!("Basic {}", B64.encode(&*pair))))?);
        }
        a if a.starts_with("header:") => {
            let name = HeaderName::from_bytes(a[7..].trim().as_bytes()).map_err(fail)?;
            headers.insert(name, secret_header(&cred.password)?);
        }
        a if a.starts_with("query:") => {
            let param = a[6..].trim();
            let kept: Vec<(String, String)> = url.query_pairs().filter(|(k, _)| k != param).map(|(k, v)| (k.into(), v.into())).collect();
            url.query_pairs_mut().clear().extend_pairs(kept).append_pair(param, &cred.password);
        }
        _ => {
            return Err(Error::Refused(format!(
                "credential {:?} has broker_auth={auth:?}, which http_request cannot use",
                cred.name
            )))
        }
    }
    let method = Method::from_bytes(req.method.to_uppercase().as_bytes()).map_err(fail)?;
    // One client per request: the Windows sign-in is bound to its keep-alive connection.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(req.timeout)
        .pool_max_idle_per_host(1)
        .build()
        .map_err(net_err)?;
    let send = |auth: Option<String>| {
        let mut b = client.request(method.clone(), url.clone()).headers(headers.clone());
        if let Some(a) = auth {
            b = b.header(AUTHORIZATION, a);
        }
        if let Some(j) = &req.json {
            b = b.json(j);
        } else if let Some(body) = &req.body {
            b = b.body(body.clone());
        }
        b.send()
    };
    let mut resp = send(None).await.map_err(net_err)?;
    if auth == "ntlm" && resp.status() == StatusCode::UNAUTHORIZED {
        resp = windows_sign_in(cred, &url, resp, send).await?;
    }
    let status = resp.status().as_u16();
    let mut kept = Map::new();
    for (k, v) in resp.headers() {
        if KEEP_HEADERS.contains(&k.as_str()) {
            let v = String::from_utf8_lossy(v.as_bytes());
            let joined = match kept.get(k.as_str()) {
                Some(Value::String(prev)) => format!("{prev}, {v}"),
                _ => v.into_owned(),
            };
            kept.insert(k.as_str().to_string(), Value::String(joined));
        }
    }
    let text = resp.text().await.map_err(net_err)?;
    let len = text.chars().count();
    let mut out = json!({"status": status, "headers": kept, "body": text.chars().take(MAX_BODY).collect::<String>()});
    if len > MAX_BODY {
        out["truncated"] = json!(format!("body truncated to {MAX_BODY} of {len} characters"));
    }
    Ok(out)
}

/// Answer a Negotiate/NTLM challenge on the same connection, resending the request with each token.
async fn windows_sign_in<F, Fut>(cred: &Cred, url: &Url, mut resp: Response, send: F) -> Result<Response>
where
    F: Fn(Option<String>) -> Fut,
    Fut: std::future::Future<Output = reqwest::Result<Response>>,
{
    let offered = |r: &Response, s: &str| {
        r.headers().get_all(WWW_AUTHENTICATE).iter().any(|v| {
            v.to_str().is_ok_and(|v| v.split(' ').next().is_some_and(|w| w.eq_ignore_ascii_case(s)))
        })
    };
    let Some(scheme) = ["Negotiate", "NTLM"].into_iter().find(|s| offered(&resp, s)) else {
        return Ok(resp);
    };
    let host = url.host_str().unwrap_or_default();
    let mut ctx = sspi::Client::new(scheme, &cred.username, &cred.password, &format!("HTTP/{host}"))?;
    let mut input = None;
    while let Some(token) = ctx.step(input.as_deref())? {
        resp.bytes().await.map_err(net_err)?; // drain so the connection is reused
        resp = send(Some(format!("{scheme} {}", B64.encode(token)))).await.map_err(net_err)?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            break;
        }
        input = challenge(&resp, scheme);
        if input.is_none() {
            break;
        }
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TOKEN: &str = "tok_test_123";
    const PASSWORD: &str = "P@ss-test-456";

    fn cred(name: &str, auth: &str, password: &str) -> Cred {
        Cred {
            id: format!("id-{name}"),
            name: name.into(),
            username: "svc-user".into(),
            password: Zeroizing::new(password.into()),
            totp: Zeroizing::new(String::new()),
            uris: vec![],
            fields: HashMap::from([("broker_auth".to_string(), Zeroizing::new(auth.to_string()))]),
        }
    }

    fn req(method: &str, url: String) -> Request {
        Request { method: method.into(), url, headers: BTreeMap::new(), body: None, json: None, timeout: Duration::from_secs(5) }
    }

    /// Minimal HTTP/1.1 server: /echo returns the raw request, /big 50000 chars, /slow never answers.
    async fn server() -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let log = log.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = s.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some(end) = text.find("\r\n\r\n") {
                            let len = text[..end]
                                .lines()
                                .find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                                .unwrap_or(0);
                            if buf.len() >= end + 4 + len || n == 0 {
                                break;
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&buf).to_string();
                    log.lock().unwrap().push(text.clone());
                    let path = text.split(' ').nth(1).unwrap_or("").to_string();
                    let body = if path.starts_with("/slow") {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        String::new()
                    } else if path.starts_with("/big") {
                        "x".repeat(50_000)
                    } else {
                        text
                    };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Request-Id: r1\r\nSet-Cookie: s=1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(body.as_bytes()).await;
                });
            }
        });
        (base, seen)
    }

    #[tokio::test]
    async fn auth_is_injected() {
        let (base, seen) = server().await;
        let basic = format!("Authorization: Basic {}", B64.encode(format!("svc-user:{PASSWORD}")));
        let cases = [
            ("bearer", TOKEN, format!("Authorization: Bearer {TOKEN}")),
            ("basic", PASSWORD, basic),
            ("header:X-Api-Key", TOKEN, format!("x-api-key: {TOKEN}")),
            ("query:api_key", TOKEN, format!("GET /echo?a=1&api_key={TOKEN} ")),
        ];
        for (auth, secret, expect) in cases {
            let mut r = req("get", format!("{base}/echo?a=1&api_key=old"));
            r.headers.insert("Authorization".into(), "mine".into());
            let out = request(&cred("c", auth, secret), r).await.unwrap();
            assert_eq!(out["status"], 200);
            let got = seen.lock().unwrap().last().unwrap().clone();
            assert!(got.to_lowercase().contains(&expect.to_lowercase()), "{auth}: {got}");
            if auth.starts_with("query") {
                assert!(!got.contains("old"), "query param must be replaced");
            }
            if auth == "bearer" || auth == "basic" {
                assert!(!got.contains("mine"), "{auth} must replace the caller's Authorization");
            }
            assert_eq!(out["headers"]["x-request-id"], "r1");
            assert!(out["headers"].get("set-cookie").is_none());
        }
    }

    #[tokio::test]
    async fn post_json_and_truncation() {
        let (base, _) = server().await;
        let mut r = req("POST", format!("{base}/echo"));
        r.json = Some(json!({"k": "v"}));
        let out = request(&cred("c", "bearer", TOKEN), r).await.unwrap();
        let body = out["body"].as_str().unwrap();
        assert!(body.starts_with("POST /echo") && body.ends_with("\r\n\r\n{\"k\":\"v\"}"), "{body}");
        assert!(body.to_lowercase().contains("content-type: application/json"));
        let big = request(&cred("c", "bearer", TOKEN), req("GET", format!("{base}/big"))).await.unwrap();
        assert_eq!(big["body"].as_str().unwrap().len(), 20_000);
        assert!(big["truncated"].as_str().unwrap().contains("50000"));
        assert!(out.get("truncated").is_none());
    }

    #[tokio::test]
    async fn unknown_auth_is_refused() {
        let err = request(&cred("web", "form", TOKEN), req("GET", "http://127.0.0.1:1/".into())).await.unwrap_err();
        assert!(matches!(err, Error::Refused(m) if m.contains("cannot use")));
    }

    #[tokio::test]
    async fn connection_refused_and_timeout_do_not_leak() {
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        // Concurrently: Windows takes about 2 s to report a refused localhost connection.
        let creds = ["query:api_key", "basic", "bearer"].map(|auth| cred("c", auth, TOKEN));
        let errs = futures_util::future::join_all(creds.iter().map(|c| request(c, req("GET", format!("{dead}/x"))))).await;
        for err in errs {
            let err = err.unwrap_err().to_string();
            assert!(err.contains("ConnectError"), "{err}");
            assert!(!err.contains(TOKEN) && !err.contains(&B64.encode(format!("svc-user:{TOKEN}"))), "{err}");
        }
        let (base, _) = server().await;
        let mut r = req("GET", format!("{base}/slow"));
        r.timeout = Duration::from_millis(300);
        let err = request(&cred("c", "query:api_key", TOKEN), r).await.unwrap_err().to_string();
        assert!(err.contains("Timeout") && !err.contains(TOKEN), "{err}");
    }
}
