//! Named pipe between the per-session shims (`mcp`, `run`, CLI) and the one agent.
//! Pipe \\.\pipe\valet-<user>, owned by and limited to the current user. One JSON request line, one
//! JSON response line. The client starts the agent if the pipe is not there.
//!
//! Requests: {"op":"call","tool","args"}, {"op":"resolve","refs","what"}, {"op":"unlock"},
//! {"op":"lock"}, {"op":"status"}, {"op":"stop"}.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::Value;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAGS, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;
const DETACHED_PROCESS: u32 = 0x8;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
const HANDLE_FLAG_INHERIT: u32 = 1;

pub fn name() -> String {
    format!(r"\\.\pipe\valet-{}", std::env::var("USERNAME").unwrap_or_default())
}

/// One request to the agent. With `start`, starts the agent first if it is not running.
pub fn send(req: &Value, start: bool) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut started = false;
    let pipe = loop {
        match OpenOptions::new().read(true).write(true).open(name()) {
            Ok(f) => break f,
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) && !start => bail!("the valet agent is not running"),
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) && !started => {
                spawn_agent()?;
                started = true;
            }
            Err(e) if [ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY].contains(&e.raw_os_error().unwrap_or(0)) => {}
            Err(e) => return Err(e).context("cannot reach the valet agent"),
        }
        if Instant::now() > deadline {
            bail!("the valet agent did not answer within 5 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    check_owner(&pipe)?;
    (&pipe).write_all(format!("{req}\n").as_bytes())?;
    let mut line = String::new();
    BufReader::new(&pipe).read_line(&mut line)?;
    serde_json::from_str(&line).context("the valet agent closed the connection")
}

fn spawn_agent() -> Result<()> {
    // Our std handles may be an MCP client's pipes: the agent must not inherit them, or the client
    // never sees EOF after this shim exits.
    for h in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        if let Ok(h) = unsafe { GetStdHandle(h) } {
            let _ = unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAGS(0)) };
        }
    }
    Command::new(std::env::current_exe()?)
        .arg("agent")
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context("cannot start the valet agent")?;
    Ok(())
}

/// The agent sets the pipe's owner to this user; anyone else's pipe under our name is a squatter.
fn check_owner(pipe: &File) -> Result<()> {
    let token = token_user()?;
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        let err = GetSecurityInfo(
            HANDLE(pipe.as_raw_handle()),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        );
        let ours = err.is_ok() && EqualSid(owner, sid(&token)).is_ok();
        LocalFree(Some(HLOCAL(sd.0)));
        if !ours {
            bail!("the pipe {} is not owned by this user; refusing to use it", name());
        }
    }
    Ok(())
}

/// TOKEN_USER of this process, in its own buffer.
fn token_user() -> Result<Vec<u64>> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut len = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let r = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
        let _ = CloseHandle(token);
        r?;
        Ok(buf)
    }
}

fn sid(token_user: &[u64]) -> PSID {
    unsafe { (*(token_user.as_ptr() as *const TOKEN_USER)).User.Sid }
}

fn user_sid_string() -> Result<String> {
    let token = token_user()?;
    unsafe {
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(sid(&token), &mut s)?;
        let out = s.to_string();
        LocalFree(Some(HLOCAL(s.0.cast())));
        Ok(out?)
    }
}

/// A pipe instance for the agent. `first`: fail if any instance exists (another agent runs).
pub fn listen(first: bool) -> Result<NamedPipeServer> {
    let sid = user_sid_string()?;
    let sddl = HSTRING::from(format!("O:{sid}D:P(A;;GA;;;{sid})"));
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &mut sd, None)?;
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let server = ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(name(), (&mut sa as *mut SECURITY_ATTRIBUTES).cast());
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(server?)
    }
}

/// "code.exe (pid 1234)": the parent of the process on the other end of the pipe, i.e. the program
/// that started the shim. The pid comes from the kernel, so a client cannot fake it.
pub fn caller(pipe: &NamedPipeServer) -> String {
    let mut pid = 0;
    if unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }.is_err() {
        return "unknown".into();
    }
    let procs = processes();
    let parent = procs.iter().find(|p| p.0 == pid).map(|p| p.1);
    match parent.and_then(|pp| procs.iter().find(|p| p.0 == pp)) {
        Some((ppid, _, exe)) => format!("{exe} (pid {ppid})"),
        None => format!("unknown (client pid {pid})"),
    }
}

/// (pid, parent pid, exe name) of every process.
fn processes() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snap, &mut e).is_ok();
        while ok {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            out.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..len])));
            ok = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_round_trip_owner_and_caller() {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        // the test owns the pipe name only if no real agent runs; skip quietly otherwise
        let Ok(server) = rt.block_on(async { listen(true) }) else { return };
        assert!(rt.block_on(async { listen(true) }).is_err(), "a second first instance must fail");
        let task = rt.spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
            server.connect().await.unwrap();
            let who = caller(&server);
            let (r, mut w) = tokio::io::split(server);
            let mut line = String::new();
            tokio::io::BufReader::new(r).read_line(&mut line).await.unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            w.write_all(format!("{}\n", serde_json::json!({"echo": req["op"], "caller": who})).as_bytes()).await.unwrap();
        });
        let resp = send(&serde_json::json!({"op": "status"}), false).unwrap();
        rt.block_on(task).unwrap();
        assert_eq!(resp["echo"], "status");
        // the client is this test process; its parent is whatever ran cargo test
        assert!(resp["caller"].as_str().unwrap().contains("(pid "), "{resp}");
    }
}
