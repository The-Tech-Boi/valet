//! Append-only audit log, <home>\audit.jsonl (owner: core). Never secrets: callers pass names,
//! targets (host+path, no query) and results only.

use std::io::Write;
use std::path::Path;

use serde_json::{Map, Value};

/// Appends one line with "ts" (local time, seconds, with offset) added. Best effort: a full disk
/// must not turn a finished operation into an error.
pub fn write(home: &Path, mut entry: Map<String, Value>) {
    entry.insert("ts".into(), chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string().into());
    let _ = std::fs::create_dir_all(home);
    let file = std::fs::OpenOptions::new().create(true).append(true).open(home.join("audit.jsonl"));
    if let Ok(mut f) = file {
        let _ = f.write_all(format!("{}\n", Value::Object(entry)).as_bytes());
    }
}
