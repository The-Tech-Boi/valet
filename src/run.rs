//! `valet run`: starts a command with the valet:// references in its environment replaced by the
//! secrets, and copies its output to ours with every one of those secrets redacted.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::redact::Redactor;

/// The agent's answer to a resolve request: the values per variable, and each item's secrets to redact.
#[derive(Default, Serialize, Deserialize)]
pub struct Resolved {
    pub values: BTreeMap<String, Zeroizing<String>>,
    pub secrets: Vec<(String, Vec<Zeroizing<String>>)>,
}

const USAGE: &str = "usage: valet run [-e NAME=valet://ITEM/FIELD] [--env-file F] -- COMMAND...";

pub fn main(args: &[String]) -> i32 {
    run(args, resolve_via_agent, &mut std::io::stdout(), &mut std::io::stderr())
}

fn resolve_via_agent(refs: BTreeMap<String, String>, what: String) -> Result<Resolved> {
    let r = crate::ipc::send(&json!({"op": "resolve", "refs": refs, "what": what}), true)?;
    if let Some(e) = r["error"].as_str() {
        return Err(anyhow!("{e}"));
    }
    Ok(serde_json::from_value(r)?)
}

/// Exit code of the command; 2 if valet refused or failed before starting it.
fn run(
    args: &[String],
    resolve: impl FnOnce(BTreeMap<String, String>, String) -> Result<Resolved>,
    out: &mut (impl Write + Send),
    err: &mut (impl Write + Send),
) -> i32 {
    let (mut sets, mut files, mut cmd) = (Vec::new(), Vec::new(), Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-e" | "--env" => sets.extend(it.next()),
            "--env-file" => files.extend(it.next()),
            "--" => {
                cmd.extend(it.by_ref());
                break;
            }
            _ => {
                cmd.push(a);
                cmd.extend(it.by_ref());
                break;
            }
        }
    }
    if cmd.is_empty() {
        let _ = writeln!(err, "{USAGE}\nvalet: give the command to run after --");
        return 2;
    }
    let mut env: BTreeMap<String, Zeroizing<String>> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, Zeroizing::new(v.into_string().ok()?))))
        .collect();
    for path in files {
        match std::fs::read_to_string(path) {
            Ok(text) => env.extend(read_env_file(&text)),
            Err(e) => {
                let _ = writeln!(err, "valet: {path}: {e}");
                return 2;
            }
        }
    }
    env.extend(sets.iter().filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string()))));
    env.retain(|k, _| !k.eq_ignore_ascii_case("BW_SESSION")); // the child gets its secrets, not the vault key
    let refs: BTreeMap<String, String> =
        env.iter().filter(|(_, v)| v.starts_with("valet://")).map(|(k, v)| (k.clone(), v.to_string())).collect();
    let what = cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
    let resolved = if refs.is_empty() {
        Resolved::default()
    } else {
        match resolve(refs, what) {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(err, "valet: {e}");
                return 2;
            }
        }
    };
    let redact = Redactor::new(&resolved.secrets);
    env.extend(resolved.values);
    let child = Command::new(which(cmd[0], &env))
        .args(&cmd[1..])
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v.as_str())))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    drop(env);
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "valet: cannot start {}: {e}", cmd[0]);
            return 2;
        }
    };
    let (so, se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    std::thread::scope(|s| {
        s.spawn(|| pump(so, out, &redact));
        pump(se, err, &redact);
    });
    child.wait().ok().and_then(|s| s.code()).unwrap_or(1)
}

/// Line-buffered: a prompt without a newline shows late.
fn pump(src: impl Read, dst: &mut impl Write, redact: &Redactor) {
    let (mut src, mut line) = (BufReader::new(src), Vec::new());
    while src.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
        let _ = dst.write_all(redact.apply(&String::from_utf8_lossy(&line)).as_bytes());
        let _ = dst.flush();
        line.clear();
    }
}

fn read_env_file(text: &str) -> Vec<(String, Zeroizing<String>)> {
    text.trim_start_matches('\u{feff}')
        .lines()
        .filter_map(|l| {
            let (k, v) = l.trim().split_once('=')?;
            let k = k.strip_prefix("export ").unwrap_or(k).trim();
            let v = Zeroizing::new(v.trim().trim_matches(['\'', '"']).to_string());
            (!k.is_empty() && !k.starts_with('#')).then(|| (k.to_string(), v))
        })
        .collect()
}

/// Like shutil.which: find `cmd` on PATH with PATHEXT, so `npm` finds npm.cmd. Else `cmd` as given.
fn which(cmd: &str, env: &BTreeMap<String, Zeroizing<String>>) -> PathBuf {
    let get = |k: &str| env.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str()).unwrap_or("");
    if !cmd.contains(['/', '\\']) && std::path::Path::new(cmd).extension().is_none() {
        for dir in std::env::split_paths(get("PATH")) {
            for ext in get("PATHEXT").split(';').filter(|e| !e.is_empty()) {
                let p = dir.join(format!("{cmd}{ext}"));
                if p.is_file() {
                    return p;
                }
            }
        }
    }
    cmd.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::tests::{broker, rt, temp_home};
    use crate::broker::Answer;
    use crate::cred::tests::PASSWORD;
    use crate::cred::Cred;

    #[test]
    fn injects_redacts_and_strips_bw_session() {
        let home = temp_home("run");
        std::fs::create_dir_all(&home).unwrap();
        let env_file = home.join("x.env");
        std::fs::write(&env_file, "\u{feff}# comment\nexport BW_SESSION='vault-key'\nDB_USER=\"valet://db/username\"\n").unwrap();
        let (b, calls) = broker(vec![Cred::test("db", &[], PASSWORD, &[("broker_approval", "never")])], Answer::Deny, &home);
        let rt = rt();
        let resolve = |refs, what: String| rt.block_on(b.resolve(refs, &what, "test")).map_err(|e| anyhow!("{e}"));
        let args: Vec<String> = [
            "--env-file", env_file.to_str().unwrap(), "-e", "DB_PASS=valet://db/password", "--",
            "cmd", "/c", "echo", "pw", "is", "%DB_PASS%&echo", "user", "%DB_USER%&if", "defined", "BW_SESSION", "exit", "5",
        ]
        .map(String::from)
        .to_vec();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args, resolve, &mut out, &mut err);
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        assert_eq!(String::from_utf8(out).unwrap().lines().collect::<Vec<_>>(), ["pw is [REDACTED:db]", "user svc-user"]);
        assert!(calls.lock().unwrap().is_empty()); // db has broker_approval=never
        let audit = std::fs::read_to_string(home.join("audit.jsonl")).unwrap();
        assert!(audit.contains("\"tool\":\"run\"") && audit.contains("\"result\":\"ok\""));

        let resolve = |refs, what: String| rt.block_on(b.resolve(refs, &what, "test")).map_err(|e| anyhow!("{e}"));
        let args = ["-e", "X=valet://nope/password", "cmd", "/c", "exit", "0"].map(String::from).to_vec();
        let mut err = Vec::new();
        assert_eq!(run(&args, resolve, &mut Vec::new(), &mut err), 2);
        assert!(String::from_utf8(err).unwrap().contains("no credential \"nope\""));
    }
}
