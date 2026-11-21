//! win_exec: a PowerShell command in a WS-Management shell over http(s), signed in with
//! Negotiate/NTLM via `sspi`; on plain http the messages are encrypted with that security context.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use regex::Regex;
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::{json, Value};

use crate::cred::{fail, Cred, Endpoint, Error, Result};
use crate::crypto::uuid;
use crate::http::{challenge, client, net_err, output};
use crate::sspi;

const SOAP: &str = "application/soap+xml;charset=UTF-8";
const PROTOCOL: &str = "application/HTTP-SPNEGO-session-encrypted";
const BOUNDARY: &[u8] = b"--Encrypted Boundary";
const OCTETS: &[u8] = b"\tContent-Type: application/octet-stream\r\n";
/// WSManFault code for "no output within OperationTimeout"; Receive is simply retried.
const OPERATION_TIMEOUT: &str = "2150858793";

const SHELL: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
const CREATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
const DELETE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

static SHELL_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"Name="ShellId"[^>]*>([^<]+)<"#).unwrap());
static COMMAND_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<(?:\w+:)?CommandId>([^<]+)<").unwrap());
static STREAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<(?:\w+:)?Stream\b([^>]*?)(?:/>|>([^<]*)<)").unwrap());
static EXIT_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<(?:\w+:)?ExitCode>([^<]*)<").unwrap());
static FAULT_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"WSManFault[^>]*\bCode="(\d+)""#).unwrap());
static REASON: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<(?:\w+:)?Text\b[^>]*>([^<]*)<").unwrap());
static CLIXML_S: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"<S S="[^"]*">([^<]*)</S>"#).unwrap());

fn refused(host: &str) -> Error {
    Error::Failed(format!(
        "WinRM on {host} refused the sign-in: wrong password, or the account may not use WinRM there \
         (by default only local Administrators may)"
    ))
}

fn capture(re: &Regex, xml: &str, what: &str) -> Result<String> {
    re.captures(xml).map(|c| c[1].trim().to_string()).ok_or_else(|| fail(format!("WinRM answer has no {what}")))
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// A WS-Management request for the cmd shell resource.
fn envelope(action: &str, shell: Option<&str>, options: &str, body: &str, secs: u64) -> String {
    let selector = shell
        .map(|id| format!(r#"<w:SelectorSet><w:Selector Name="ShellId">{id}</w:Selector></w:SelectorSet>"#))
        .unwrap_or_default();
    let options = if options.is_empty() { String::new() } else { format!("<w:OptionSet>{options}</w:OptionSet>") };
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="{SHELL}" xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config"><env:Header><a:To>http://windows-host:5985/wsman</a:To><a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize><a:MessageID>uuid:{}</a:MessageID><w:Locale mustUnderstand="false" xml:lang="en-US" /><p:DataLocale mustUnderstand="false" xml:lang="en-US" /><w:OperationTimeout>PT{secs}S</w:OperationTimeout><w:ResourceURI mustUnderstand="true">{SHELL}/cmd</w:ResourceURI><a:Action mustUnderstand="true">{action}</a:Action>{selector}{options}</env:Header><env:Body>{body}</env:Body></env:Envelope>"#,
        uuid()
    )
}

fn opt(name: &str, value: &str) -> String {
    format!(r#"<w:Option Name="{name}">{value}</w:Option>"#)
}

/// stdout, stderr and (once the command is done) the exit code of one Receive answer.
fn parse_receive(xml: &str) -> Result<(Vec<u8>, Vec<u8>, Option<i64>)> {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    for c in STREAM.captures_iter(xml) {
        let Some(text) = c.get(2) else { continue };
        let data = B64.decode(text.as_str().trim()).map_err(fail)?;
        if c[1].contains(r#"Name="stdout""#) {
            out.extend(data);
        } else if c[1].contains(r#"Name="stderr""#) {
            err.extend(data);
        }
    }
    let done = xml.contains("CommandState/Done\"");
    let code = done.then(|| EXIT_CODE.captures(xml).and_then(|c| c[1].trim().parse().ok()).unwrap_or(-1));
    Ok((out, err, code))
}

/// PowerShell's CLIXML error stream as plain text: the error records' text, progress records dropped.
fn clean_stderr(err: Vec<u8>) -> Vec<u8> {
    let Some(xml) = err.strip_prefix(b"#< CLIXML\r\n") else { return err };
    let xml = String::from_utf8_lossy(xml);
    let msg: String = CLIXML_S.captures_iter(&xml).map(|c| unescape(&c[1]).replace("_x000D__x000A_", "\n")).collect();
    if msg.is_empty() { err } else { msg.trim().as_bytes().to_vec() }
}

fn fault(status: StatusCode, xml: &str) -> Error {
    let code = FAULT_CODE.captures(xml).map(|c| format!(" {}", &c[1])).unwrap_or_default();
    let reason = REASON.captures(xml).map(|c| unescape(c[1].trim())).unwrap_or_else(|| format!("HTTP {status}"));
    fail(format!("WinRM fault{code}: {reason}"))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// MS-WSMV 2.2.9.1.1: multipart/encrypted body with the sealed SOAP message.
fn seal(ctx: &sspi::Client, msg: &[u8]) -> Result<Vec<u8>> {
    let (sig, sealed) = ctx.encrypt(msg)?;
    let mut out = [BOUNDARY, b"\r\n\tContent-Type: ", PROTOCOL.as_bytes(), b"\r\n"].concat();
    out.extend(format!("\tOriginalContent: type={SOAP};Length={}\r\n", msg.len()).as_bytes());
    out.extend([BOUNDARY, b"\r\n", OCTETS].concat());
    out.extend((sig.len() as u32).to_le_bytes());
    out.extend(sig);
    out.extend(sealed);
    out.extend([BOUNDARY, b"--\r\n"].concat());
    Ok(out)
}

/// Inverse of `seal`; also accepts several encrypted parts in one body.
fn unseal(ctx: &sspi::Client, body: &[u8]) -> Result<Vec<u8>> {
    let bad = || fail("WinRM sent a malformed encrypted message");
    let part = [BOUNDARY, b"\r\n"].concat();
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = find(rest, &part) {
        rest = &rest[i + part.len()..];
        let j = find(rest, &part).ok_or_else(bad)?;
        let header = String::from_utf8_lossy(&rest[..j]);
        rest = &rest[j + part.len()..];
        let end = find(rest, BOUNDARY).unwrap_or(rest.len());
        let payload = rest[..end].strip_prefix(OCTETS).ok_or_else(bad)?;
        rest = &rest[end..];
        let expected: usize = header.split("Length=").nth(1).and_then(|n| n.trim().parse().ok()).ok_or_else(bad)?;
        let sig_len = u32::from_le_bytes(payload.get(..4).ok_or_else(bad)?.try_into().unwrap()) as usize;
        let sig = payload.get(4..4 + sig_len).ok_or_else(bad)?;
        let msg = ctx.decrypt(sig, &payload[4 + sig_len..])?;
        if msg.len() != expected {
            return Err(fail("encrypted length from WinRM does not match the expected size"));
        }
        out.extend(msg);
    }
    Ok(out)
}

struct Session {
    http: reqwest::Client,
    url: String,
    host: String,
    ctx: sspi::Client,
    encrypt: bool,
    secs: u64,
}

impl Session {
    /// Sign in with an empty POST on the connection all later messages use.
    async fn open(cred: &Cred, ep: &Endpoint, timeout: Duration) -> Result<Session> {
        let tls = ep.scheme == "winrms";
        let secs = timeout.as_secs().max(1);
        let http = client(Duration::from_secs(secs + 10), cred.flag("broker_trust_cert")).map_err(net_err)?;
        let url = format!("{}://{}:{}/wsman", if tls { "https" } else { "http" }, ep.host, ep.port);
        let mut ctx = sspi::Client::new("Negotiate", &cred.username, &cred.password, &format!("HTTP/{}", ep.host))?;
        let mut input = None;
        while let Some(token) = ctx.step(input.as_deref())? {
            let resp = http
                .post(&url)
                .header(CONTENT_TYPE, SOAP)
                .header(AUTHORIZATION, format!("Negotiate {}", B64.encode(token)))
                .header(CONTENT_LENGTH, 0) // HTTP.sys answers 411 to a POST without one
                .send()
                .await
                .map_err(net_err)?;
            let (status, answer) = (resp.status(), challenge(&resp, "Negotiate"));
            resp.bytes().await.map_err(net_err)?;
            match (status, answer) {
                (StatusCode::UNAUTHORIZED, Some(t)) => input = Some(t),
                (StatusCode::UNAUTHORIZED, None) => return Err(refused(&ep.host)),
                (s, _) if !s.is_success() => return Err(fail(format!("WinRM on {} answered HTTP {s}", ep.host))),
                (_, answer) => {
                    if let (Some(t), false) = (answer, ctx.is_complete()) {
                        ctx.step(Some(&t))?;
                    }
                    break;
                }
            }
        }
        if !ctx.is_complete() {
            return Err(refused(&ep.host));
        }
        Ok(Session { http, url, host: ep.host.clone(), ctx, encrypt: !tls, secs })
    }

    /// Send one SOAP message; a WS-Management fault becomes an error.
    async fn call(&self, action: &str, shell: Option<&str>, options: &str, body: &str) -> Result<String> {
        let xml = envelope(action, shell, options, body, self.secs);
        let req = self.http.post(&self.url);
        let req = if self.encrypt {
            let ct = format!(r#"multipart/encrypted;protocol="{PROTOCOL}";boundary="Encrypted Boundary""#);
            req.header(CONTENT_TYPE, ct).body(seal(&self.ctx, xml.as_bytes())?)
        } else {
            req.header(CONTENT_TYPE, SOAP).body(xml)
        };
        let resp = req.send().await.map_err(net_err)?;
        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(refused(&self.host));
        }
        let sealed = resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains(PROTOCOL));
        let body = resp.bytes().await.map_err(net_err)?;
        let body = if sealed { unseal(&self.ctx, &body)? } else { body.to_vec() };
        let text = String::from_utf8_lossy(&body).into_owned();
        if status.is_success() { Ok(text) } else { Err(fault(status, &text)) }
    }

    /// Run the command in `shell` until done: (stdout, stderr, exit code).
    async fn run(&self, shell: &str, command: &str, timeout: Duration) -> Result<(Vec<u8>, Vec<u8>, i64)> {
        let utf16: Vec<u8> = command.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let line = format!("<rsp:CommandLine><rsp:Command>powershell -encodedcommand {}</rsp:Command></rsp:CommandLine>", B64.encode(utf16));
        let options = opt("WINRS_CONSOLEMODE_STDIN", "TRUE") + &opt("WINRS_SKIP_CMD_SHELL", "FALSE");
        let xml = self.call(&format!("{SHELL}/Command"), Some(shell), &options, &line).await?;
        let id = capture(&COMMAND_ID, &xml, "CommandId")?;
        let receive = format!(r#"<rsp:Receive><rsp:DesiredStream CommandId="{id}">stdout stderr</rsp:DesiredStream></rsp:Receive>"#);
        let start = Instant::now();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = loop {
            match self.call(&format!("{SHELL}/Receive"), Some(shell), "", &receive).await {
                Ok(xml) => {
                    let (o, e, code) = parse_receive(&xml)?;
                    out.extend(o);
                    err.extend(e);
                    if let Some(code) = code {
                        break code;
                    }
                }
                // No output yet: ask again until our own timeout is used up.
                Err(Error::Failed(m)) if m.contains(OPERATION_TIMEOUT) && start.elapsed() < timeout => {}
                Err(e) => return Err(e),
            }
        };
        let signal = format!(r#"<rsp:Signal CommandId="{id}"><rsp:Code>{SHELL}/signal/terminate</rsp:Code></rsp:Signal>"#);
        self.call(&format!("{SHELL}/Signal"), Some(shell), "", &signal).await?;
        Ok((out, err, code))
    }
}

/// Runs a PowerShell command. Returns {"status", "exit_code", "stdout", "stderr"}.
pub async fn exec(cred: &Cred, ep: &Endpoint, command: &str, timeout: Duration) -> Result<Value> {
    let s = Session::open(cred, ep, timeout).await?;
    let options = opt("WINRS_NOPROFILE", "FALSE") + &opt("WINRS_CODEPAGE", "437");
    let body = "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>";
    let xml = s.call(CREATE, None, &options, body).await?;
    let shell = capture(&SHELL_ID, &xml, "ShellId")?;
    let result = s.run(&shell, command, timeout).await;
    let _ = s.call(DELETE, Some(&shell), "", "").await; // also stops a command that is still running
    let (out, err, code) = result?;
    Ok(json!({"status": code, "exit_code": code, "stdout": output(&out), "stderr": output(&clean_stderr(err))}))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN_SHELL: &str = r#"<?xml version="1.0" ?>
<s:Envelope xml:lang="en-US" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer">
    <s:Body><x:ResourceCreated><a:Address>http://windows-host:5985/wsman</a:Address><a:ReferenceParameters>
        <w:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
        <w:SelectorSet><w:Selector Name="ShellId">11111111-1111-1111-1111-111111111113</w:Selector></w:SelectorSet>
    </a:ReferenceParameters></x:ResourceCreated></s:Body></s:Envelope>"#;

    const COMMAND: &str = r#"<s:Envelope xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Body><rsp:CommandResponse><rsp:CommandId>11111111-1111-1111-1111-111111111114</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>"#;

    const RUNNING: &str = r#"<s:Body><rsp:ReceiveResponse>
        <rsp:Stream Name="stdout" CommandId="1">aGVsbG8g</rsp:Stream>
        <rsp:Stream Name="stderr" CommandId="1">IzwgQ0xJWE1MDQo=</rsp:Stream>
        <rsp:CommandState CommandId="1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
    </rsp:ReceiveResponse></s:Body>"#;

    const DONE: &str = r#"<s:Body><rsp:ReceiveResponse>
        <rsp:Stream CommandId="1" Name="stdout">d29ybGQ=</rsp:Stream>
        <rsp:Stream CommandId="1" End="true" Name="stdout"/>
        <rsp:Stream CommandId="1" End="true" Name="stderr"/>
        <rsp:CommandState CommandId="1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
            <rsp:ExitCode>3</rsp:ExitCode>
        </rsp:CommandState>
    </rsp:ReceiveResponse></s:Body>"#;

    const FAULT: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"><s:Body><s:Fault>
        <s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code>
        <s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot complete the operation within the time specified in OperationTimeout.  </s:Text></s:Reason>
        <s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858793" Machine="host"><f:Message/></f:WSManFault></s:Detail>
    </s:Fault></s:Body></s:Envelope>"#;

    #[test]
    fn builds_messages() {
        let x = envelope(CREATE, None, &(opt("WINRS_NOPROFILE", "FALSE") + &opt("WINRS_CODEPAGE", "437")), "<rsp:Shell/>", 60);
        for part in [
            r#"<a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>"#,
            r#"<w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"#,
            "<w:OperationTimeout>PT60S</w:OperationTimeout>",
            r#"<w:OptionSet><w:Option Name="WINRS_NOPROFILE">FALSE</w:Option><w:Option Name="WINRS_CODEPAGE">437</w:Option></w:OptionSet>"#,
            "<env:Body><rsp:Shell/></env:Body>",
        ] {
            assert!(x.contains(part), "{part}");
        }
        assert!(!x.contains("SelectorSet"));
        let id = Regex::new(r"<a:MessageID>uuid:([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})</a:MessageID>").unwrap();
        assert!(id.is_match(&x), "{x}");
        let x = envelope(DELETE, Some("S-1"), "", "", 5);
        assert!(x.contains(r#"<w:SelectorSet><w:Selector Name="ShellId">S-1</w:Selector></w:SelectorSet></env:Header><env:Body></env:Body>"#));
    }

    #[test]
    fn parses_answers() {
        assert_eq!(capture(&SHELL_ID, OPEN_SHELL, "ShellId").unwrap(), "11111111-1111-1111-1111-111111111113");
        assert_eq!(capture(&COMMAND_ID, COMMAND, "CommandId").unwrap(), "11111111-1111-1111-1111-111111111114");
        assert!(capture(&COMMAND_ID, OPEN_SHELL, "CommandId").unwrap_err().to_string().contains("no CommandId"));
        assert_eq!(parse_receive(RUNNING).unwrap(), (b"hello ".to_vec(), b"#< CLIXML\r\n".to_vec(), None));
        assert_eq!(parse_receive(DONE).unwrap(), (b"world".to_vec(), vec![], Some(3)));
        let e = fault(StatusCode::INTERNAL_SERVER_ERROR, FAULT).to_string();
        assert!(e.starts_with("WinRM fault 2150858793: The WS-Management service") && e.contains(OPERATION_TIMEOUT), "{e}");
        assert_eq!(fault(StatusCode::BAD_REQUEST, "").to_string(), "WinRM fault: HTTP 400 Bad Request");
    }

    #[test]
    fn cleans_clixml_stderr() {
        let msg = br#"#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><S S="Error">fake : The term 'fake' is not recognized &amp; so on. Check _x000D__x000A_</S><S S="Error">At line:1 char:1_x000D__x000A_</S><S S="Error"> _x000D__x000A_</S></Objs>"#;
        let msg = String::from_utf8_lossy(msg).replace("CLIXML\n", "CLIXML\r\n").into_bytes();
        assert_eq!(clean_stderr(msg), b"fake : The term 'fake' is not recognized & so on. Check \nAt line:1 char:1".to_vec());
        let progress_only = b"#< CLIXML\r\n<Objs><Obj S=\"progress\"><MS><AV>x</AV></MS></Obj></Objs>".to_vec();
        assert_eq!(clean_stderr(progress_only.clone()), progress_only);
        assert_eq!(clean_stderr(b"plain".to_vec()), b"plain".to_vec());
    }

    #[test]
    fn encryption_framing_round_trip() {
        let (client, server) = crate::sspi::tests::loopback("Negotiate");
        let msg = envelope(CREATE, None, "", "<rsp:Shell/>", 20);
        let body = seal(&client, msg.as_bytes()).unwrap();
        let head = format!(
            "--Encrypted Boundary\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n",
            msg.len()
        );
        assert!(body.starts_with(head.as_bytes()) && body.ends_with(b"--Encrypted Boundary--\r\n"));
        let sig_len = u32::from_le_bytes(body[head.len()..head.len() + 4].try_into().unwrap()) as usize;
        assert_eq!(body.len(), head.len() + 4 + sig_len + msg.len() + 24);
        assert_eq!(unseal(&server, &body).unwrap(), msg.as_bytes());
        // Tampered length is rejected.
        let (c2, s2) = crate::sspi::tests::loopback("NTLM");
        let mut body = seal(&c2, b"abc").unwrap();
        let at = find(&body, b"Length=3").unwrap();
        body[at + 7] = b'4';
        assert!(unseal(&s2, &body).unwrap_err().to_string().contains("does not match"));
    }
}
