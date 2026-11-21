//! Append-only audit log, <home>\audit.jsonl: who used which credential where, and how it went.

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::redact::{scrub, Redactor};

/// One line. `target` is host+path (no query: it may carry a key) or an endpoint.
#[derive(Serialize, Default)]
pub struct Entry {
    pub ts: String,
    pub tool: String,
    pub credential: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The result's "status" (e.g. an exit code), or "denied" / "refused" / "error".
    pub result: Value,
}

/// Appends `entry` with "ts" set (local time, seconds, with offset), every string through `r`.
/// Best effort: a full disk must not turn a finished operation into an error.
pub fn write(home: &Path, mut entry: Entry, r: &Redactor) {
    entry.ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let line = scrub(serde_json::to_value(&entry).unwrap_or_default(), r);
    let _ = std::fs::create_dir_all(home);
    let file = std::fs::OpenOptions::new().create(true).append(true).open(home.join("audit.jsonl"));
    if let Ok(mut f) = file {
        let _ = f.write_all(format!("{line}\n").as_bytes());
    }
}
