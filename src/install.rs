//! `valet install` / `valet uninstall`: the exe in %LOCALAPPDATA%\Programs\valet and
//! that folder on the user's PATH, so `valet` works in any new terminal. No admin rights needed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use windows::core::w;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, LPARAM, WPARAM};
use windows::Win32::System::Registry::{
    RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_EXPAND_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};
use windows::Win32::UI::WindowsAndMessaging::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};

pub fn dir() -> PathBuf {
    PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default()).join("Programs").join("valet")
}

/// Copies this exe into `dir()` (unless it runs from there) and adds `dir()` to PATH. Returns the installed exe.
pub fn install() -> Result<PathBuf> {
    let dir = dir();
    let exe = dir.join("valet.exe");
    let me = std::env::current_exe()?;
    if !same_file(&me, &exe) {
        std::fs::create_dir_all(&dir)?;
        // Old copies still running (MCP clients' shims) cannot be overwritten or deleted, only renamed;
        // leftovers from earlier installs go once nothing runs them.
        for f in std::fs::read_dir(&dir)?.flatten() {
            if f.file_name().to_string_lossy().starts_with("valet.old-") {
                let _ = std::fs::remove_file(f.path());
            }
        }
        if exe.exists() {
            let old = dir.join(format!("valet.old-{}.exe", std::process::id()));
            std::fs::rename(&exe, &old).with_context(|| format!("cannot move the old {} aside", exe.display()))?;
        }
        std::fs::copy(&me, &exe).with_context(|| format!("cannot copy valet to {}", exe.display()))?;
    }
    let path = user_path()?;
    if !on_path(&path, &dir) {
        let entry = dir.display().to_string();
        set_user_path(&if path.trim_end_matches(';').is_empty() { entry } else { format!("{};{entry}", path.trim_end_matches(';')) })?;
    }
    Ok(exe)
}

/// Takes `dir()` off PATH and deletes it. Exes still running (this one, MCP clients' shims) are moved
/// to %TEMP% first: Windows lets a running exe be renamed, not deleted.
pub fn uninstall() -> Result<()> {
    let dir = dir();
    let path = user_path()?;
    if on_path(&path, &dir) {
        let kept: Vec<&str> = path.split(';').filter(|e| !same_dir(e, &dir)).collect();
        set_user_path(&kept.join(";"))?;
    }
    for (i, f) in std::fs::read_dir(&dir).into_iter().flatten().flatten().enumerate() {
        if std::fs::remove_file(f.path()).is_err() {
            let _ = std::fs::rename(f.path(), std::env::temp_dir().join(format!("valet-removed-{}-{i}.exe", std::process::id())));
        }
    }
    match std::fs::remove_dir_all(&dir) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).with_context(|| format!("cannot delete {}", dir.display())),
        _ => Ok(()),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

fn same_dir(entry: &str, dir: &Path) -> bool {
    let entry = entry.trim().trim_end_matches('\\');
    entry.eq_ignore_ascii_case(dir.to_string_lossy().trim_end_matches('\\'))
}

fn on_path(path: &str, dir: &Path) -> bool {
    path.split(';').any(|e| same_dir(e, dir))
}

/// HKCU\Environment\Path as stored (unexpanded); empty if unset.
fn user_path() -> Result<String> {
    let read = |buf: Option<&mut [u16]>, len: &mut u32| unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!("Environment"),
            w!("Path"),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            None,
            buf.map(|b| b.as_mut_ptr().cast()),
            Some(len),
        )
    };
    let mut len = 0;
    match read(None, &mut len) {
        e if e == ERROR_FILE_NOT_FOUND => return Ok(String::new()),
        e => e.ok().context("cannot read the user PATH")?,
    }
    let mut buf = vec![0u16; (len as usize).div_ceil(2)];
    read(Some(&mut buf), &mut len).ok().context("cannot read the user PATH")?;
    Ok(String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string())
}

/// Writes HKCU\Environment\Path and tells running programs (Explorer, new terminals) about it.
fn set_user_path(path: &str) -> Result<()> {
    let wide = crate::wide(path);
    unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            w!("Environment"),
            w!("Path"),
            REG_EXPAND_SZ.0,
            Some(wide.as_ptr().cast()),
            (wide.len() * 2) as u32,
        )
        .ok()
        .context("cannot write the user PATH")?;
        let env = LPARAM(w!("Environment").as_ptr() as isize);
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, WPARAM(0), env, SMTO_ABORTIFHUNG, 2000, None);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_entries() {
        let dir = Path::new(r"C:\Users\x\AppData\Local\Programs\valet");
        assert!(on_path(r"C:\bin;c:\users\X\appdata\local\programs\VALET\;D:\y", dir));
        assert!(!on_path(r"C:\bin;C:\Users\x\AppData\Local\Programs\valet2", dir));
        assert!(!on_path("", dir));
    }
}
