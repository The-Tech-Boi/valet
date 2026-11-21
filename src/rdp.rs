//! rdp_open (owner: core). Spec: valet/broker.py `save_rdp_login`, `rdp_run`.

use serde_json::{json, Value};
use windows::core::PWSTR;
use windows::Win32::Security::Credentials::{CredWriteW, CREDENTIALW, CRED_PERSIST_SESSION, CRED_TYPE_DOMAIN_PASSWORD};
use zeroize::Zeroizing;

use crate::cred::{fail, Cred, Endpoint, Result};

pub fn open(cred: &Cred, ep: &Endpoint) -> Result<Value> {
    save_login(cred, &ep.host)?;
    let port = if ep.port == 3389 { String::new() } else { format!(":{}", ep.port) };
    std::process::Command::new("mstsc").arg(format!("/v:{}{port}", ep.host)).spawn().map_err(fail)?;
    Ok(json!({"status": "opened", "target": format!("{}:{}", ep.host, ep.port)}))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// Store the login for mstsc as TERMSRV/<host>. Domain-password type: only LSA can read the password
/// back (not this user's other programs), and session persistence drops it at sign-out.
fn save_login(cred: &Cred, host: &str) -> Result<()> {
    let mut blob = Zeroizing::new(cred.password.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>());
    let (mut target, mut user) = (wide(&format!("TERMSRV/{host}")), wide(&cred.username));
    let c = CREDENTIALW {
        Type: CRED_TYPE_DOMAIN_PASSWORD,
        TargetName: PWSTR(target.as_mut_ptr()),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_SESSION,
        UserName: PWSTR(user.as_mut_ptr()),
        ..Default::default()
    };
    unsafe { CredWriteW(&c, 0) }.map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::w;
    use windows::Win32::Security::Credentials::{CredDeleteW, CredFree, CredReadW};

    #[test]
    fn login_is_saved_unreadable() {
        let cred = crate::broker::tests::cred("t", &[], crate::broker::tests::PASSWORD, &[]);
        let target = w!("TERMSRV/valet-test.invalid");
        save_login(&cred, "valet-test.invalid").unwrap();
        unsafe {
            let mut p = std::ptr::null_mut();
            let read = CredReadW(target, CRED_TYPE_DOMAIN_PASSWORD, None, &mut p);
            let _ = CredDeleteW(target, CRED_TYPE_DOMAIN_PASSWORD, None);
            read.unwrap();
            assert_eq!((*p).UserName.to_string().unwrap(), "svc-user");
            assert_eq!((*p).CredentialBlobSize, 0); // Windows does not hand the password back to programs
            CredFree(p as _);
        }
    }
}
