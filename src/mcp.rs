//! MCP over stdio, hand-rolled JSON-RPC: initialize, tools/list, tools/call.
//! A thin shim: every tools/call is forwarded to the agent over `ipc`.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

const INSTRUCTIONS: &str = "Uses credentials from a vault without ever revealing them. Call list_credentials to see what \
exists, where each credential may be used and with which tools. Then use http_request for APIs, browser_login \
for web logins, ssh_exec / win_exec for commands on servers, sql_query for SQL Server, rdp_open to open a \
Remote Desktop window for the user. Secret values never appear in results; anything secret that echoes back \
is shown as [REDACTED:<name>]. Some operations pop up an approval dialog for the user and wait for the answer. \
For scripts that need a password, do not hardcode it: put NAME=valet://<item>/password in the environment \
and start the script with `valet run -- <command>`.";

/// Serve until stdin closes. `call(tool, args)` returns the tool's JSON result.
pub fn serve(input: impl BufRead, mut output: impl Write, mut call: impl FnMut(&str, Value) -> Value) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            let err = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}});
            writeln!(output, "{err}")?;
            output.flush()?;
            continue;
        };
        let Some(id) = msg.get("id").cloned() else { continue }; // notification
        let params = &msg["params"];
        let result = match msg["method"].as_str().unwrap_or("") {
            "initialize" => Ok(json!({
                "protocolVersion": params["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "valet", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS,
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let out = call(params["name"].as_str().unwrap_or(""), args);
                let text = serde_json::to_string_pretty(&out).unwrap_or_default();
                Ok(json!({"content": [{"type": "text", "text": text}]}))
            }
            m => Err(json!({"code": -32601, "message": format!("method not found: {m}")})),
        };
        let resp = match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
        };
        writeln!(output, "{resp}")?;
        output.flush()?;
    }
    Ok(())
}

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required},
    })
}

fn tools() -> Vec<Value> {
    let s = json!({"type": "string"});
    let credential = json!({"type": "string", "description": "credential name or id"});
    let host = json!({"type": "string", "description": "pick one of the item's hosts when it lists several"});
    vec![
        tool(
            "list_credentials",
            "List the credentials available to you: name, id, allowed web hosts, which tools each one works \
with (with auth type, approval policy and, for server tools, the allowed targets), and whether it \
has TOTP. Never returns secret values.",
            json!({}),
            &[],
        ),
        tool(
            "http_request",
            "Send an HTTP request with the named credential (name or id) injected as configured on the item \
(bearer token, basic auth, a custom header, a query parameter, or Windows NTLM). Do not add auth \
yourself. The url must be https (http only for localhost or items that allow it) on one of the \
credential's allowed hosts, otherwise the request is refused. Redirects are not followed (you get the \
status and Location). Pass either body (raw text) or json, not both. Returns status, selected response \
headers and the body text (truncated past 20000 characters, which the result says). Returns \
{\"error\": ...} on refusal, user denial or network failure.",
            json!({
                "credential": credential, "method": s, "url": s,
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": s,
                "json": {"type": ["object", "array"]},
                "timeout": {"type": "number", "default": 30},
            }),
            &["credential", "method", "url"],
        ),
        tool(
            "browser_login",
            "Log in to a website in the shared browser using the named credential (name or id). Reuses an \
open tab on one of the credential's hosts, otherwise opens url (or the item's first URI) in a new \
tab. Fills username and password, a TOTP code if a code field appears, and submits (or answers a \
Windows sign-in challenge). Returns only a status, the resulting page URL and title; continue in that \
tab with your own browser tools. Refuses pages on hosts the credential is not allowed for.",
            json!({"credential": credential, "url": s}),
            &["credential"],
        ),
        tool(
            "ssh_exec",
            "Run a shell command over SSH with the credential's username and password, on the item's ssh:// \
URI (pass host to pick one when it lists several). The server's host key must already be trusted \
in ~/.ssh/known_hosts. Returns exit_code, stdout and stderr. For key-based SSH use the normal ssh \
command instead (the SSH agent handles it).",
            json!({"credential": credential, "command": s, "host": host, "timeout": {"type": "number", "default": 60}}),
            &["credential", "command"],
        ),
        tool(
            "win_exec",
            "Run a PowerShell command on a Windows server over WinRM (NTLM) with the credential, on the item's \
winrm:// (port 5985) or winrms:// (5986) URI. Returns exit_code, stdout and stderr.",
            json!({"credential": credential, "command": s, "host": host, "timeout": {"type": "number", "default": 60}}),
            &["credential", "command"],
        ),
        tool(
            "sql_query",
            "Run T-SQL on SQL Server with the credential, on the item's mssql:// URI. Items whose username has \
a domain (DOMAIN\\user) sign in with Windows auth, others as a SQL login. Autocommit: writes take \
effect immediately. Returns one entry per result set: columns and rows (first max_rows), or \
rows_affected.",
            json!({
                "credential": credential, "query": s, "database": s, "host": host,
                "max_rows": {"type": "integer", "default": 200},
            }),
            &["credential", "query"],
        ),
        tool(
            "rdp_open",
            "Open a Remote Desktop window on the user's screen for the item's rdp:// URI, signed in with the \
credential (handed to Windows directly, nobody types it). For the user to work in; you cannot see \
or drive the session.",
            json!({"credential": credential, "host": host}),
            &["credential"],
        ),
        tool(
            "check_credentials",
            "Try the sign-in of each credential (all, or the given names/ids) on each of its URIs and report \
ok / failed / skipped with a short reason. One approval covers the whole batch. Scheme-less URIs \
(a bare IP) are not signed in to; the result says which server ports are open there. Use after \
importing credentials to find wrong passwords.",
            json!({"credentials": {"type": "array", "items": {"type": "string"}}}),
            &[],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::tests::{assert_clean, broker, rt, temp_home};
    use crate::broker::Answer;
    use crate::cred::tests::TOKEN;
    use crate::cred::Cred;

    #[test]
    fn tools_list_and_call_round_trip() {
        let home = temp_home("mcp");
        let (b, _) = broker(vec![Cred::test("api-header", &["https://api.test"], TOKEN, &[])], Answer::Once, &home);
        let rt = rt();
        let input = [
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_credentials", "arguments": {}}}),
            json!({"jsonrpc": "2.0", "id": 4, "method": "nope"}),
        ]
        .map(|m| m.to_string())
        .join("\n");
        let mut out = Vec::new();
        serve(input.as_bytes(), &mut out, |tool, args| rt.block_on(b.call(tool, args, "test"))).unwrap();
        let resp: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(resp.len(), 4, "the notification gets no answer");
        assert_eq!(resp[0]["result"]["protocolVersion"], "2025-03-26");
        let mut names: Vec<&str> = resp[1]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        names.sort();
        assert_eq!(
            names,
            ["browser_login", "check_credentials", "http_request", "list_credentials", "rdp_open", "sql_query", "ssh_exec", "win_exec"]
        );
        let text = resp[2]["result"]["content"][0]["text"].as_str().unwrap();
        assert_clean(text);
        let result: Value = serde_json::from_str(text).unwrap();
        assert_eq!(result["credentials"][0]["name"], "api-header");
        assert_eq!(resp[3]["error"]["code"], -32601);
        assert_eq!(resp[3]["id"], 4);
    }
}
