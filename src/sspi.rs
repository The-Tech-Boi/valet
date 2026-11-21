//! Windows SSPI client for Negotiate/NTLM with explicit credentials.
//! Used by `http` (Windows sign-in to web apps and APIs) and `winrm` (sign-in plus message
//! encryption). No NTLM implementation of our own: Windows does it.

use std::ffi::c_void;

use anyhow::{bail, Result};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED};
use windows::Win32::Security::Authentication::Identity::*;
use windows::Win32::Security::Credentials::SecHandle;
use zeroize::Zeroizing;

use crate::wide;

/// SEC_WINNT_AUTH_IDENTITY_W; the `windows` crate only has it behind the Win32_System_Rpc feature.
#[repr(C)]
struct Identity {
    user: *const u16,
    user_len: u32,
    domain: *const u16,
    domain_len: u32,
    password: *const u16,
    password_len: u32,
    flags: u32,
}
const SEC_WINNT_AUTH_IDENTITY_UNICODE: u32 = 2;

pub struct Client {
    cred: SecHandle,
    ctx: SecHandle,
    has_ctx: bool,
    complete: bool,
    target: Vec<u16>,
}

fn buffer(kind: u32, data: &mut [u8]) -> SecBuffer {
    SecBuffer { cbBuffer: data.len() as u32, BufferType: kind, pvBuffer: data.as_mut_ptr().cast() }
}

fn desc(buffers: &mut [SecBuffer]) -> SecBufferDesc {
    SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: buffers.len() as u32, pBuffers: buffers.as_mut_ptr() }
}

impl Client {
    /// package: "Negotiate" or "NTLM". username: "DOMAIN\\user" or "user@domain". target: SPN, e.g. "HTTP/host".
    pub fn new(package: &str, username: &str, password: &str, target: &str) -> anyhow::Result<Client> {
        // A UPN goes in whole with no domain: that is what Windows expects for user@domain.
        let (domain, user) = username.split_once('\\').unwrap_or(("", username));
        let (user, domain) = (wide(user), wide(domain));
        let password = Zeroizing::new(wide(password));
        // Lengths without the terminating NUL.
        let id = Identity {
            user: user.as_ptr(),
            user_len: user.len() as u32 - 1,
            domain: domain.as_ptr(),
            domain_len: domain.len() as u32 - 1,
            password: password.as_ptr(),
            password_len: password.len() as u32 - 1,
            flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        };
        Self::open(package, SECPKG_CRED_OUTBOUND, Some(&id as *const Identity as *const c_void), target)
    }

    /// `auth` None = the current Windows user.
    fn open(package: &str, usage: SECPKG_CRED, auth: Option<*const c_void>, target: &str) -> Result<Client> {
        let mut cred = SecHandle::default();
        unsafe {
            AcquireCredentialsHandleW(PCWSTR::null(), &HSTRING::from(package), usage, None, auth, None, None, &mut cred, None)?;
        }
        Ok(Client { cred, ctx: SecHandle::default(), has_ctx: false, complete: false, target: wide(target) })
    }

    /// Feed the server's token (None for the first call). Returns the token to send, if any.
    pub fn step(&mut self, input: Option<&[u8]>) -> anyhow::Result<Option<Vec<u8>>> {
        let mut input = input.unwrap_or_default().to_vec();
        let mut inb = [buffer(SECBUFFER_TOKEN, &mut input)];
        let ind = desc(&mut inb);
        let mut outb = [SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: std::ptr::null_mut() }];
        let mut outd = desc(&mut outb);
        let flags = ISC_REQ_MUTUAL_AUTH
            | ISC_REQ_REPLAY_DETECT
            | ISC_REQ_SEQUENCE_DETECT
            | ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_INTEGRITY
            | ISC_REQ_ALLOCATE_MEMORY;
        let ctx: *mut SecHandle = &mut self.ctx;
        let mut attrs = 0;
        let status = unsafe {
            InitializeSecurityContextW(
                Some(&self.cred),
                self.has_ctx.then_some(ctx as *const _),
                Some(self.target.as_ptr()),
                flags,
                0,
                SECURITY_NATIVE_DREP,
                self.has_ctx.then_some(&ind as *const _),
                0,
                Some(ctx),
                Some(&mut outd),
                &mut attrs,
                None,
            )
        };
        self.finish(status, &outb[0])
    }

    /// Common tail of InitializeSecurityContext/AcceptSecurityContext: take the output token, track state.
    fn finish(&mut self, status: windows::core::HRESULT, out: &SecBuffer) -> Result<Option<Vec<u8>>> {
        let token = (!out.pvBuffer.is_null()).then(|| unsafe {
            let t = std::slice::from_raw_parts(out.pvBuffer as *const u8, out.cbBuffer as usize).to_vec();
            let _ = FreeContextBuffer(out.pvBuffer);
            t
        });
        if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
            status.ok()?;
            bail!("Windows sign-in returned status {:#x}", status.0);
        }
        self.has_ctx = true;
        self.complete = status == SEC_E_OK;
        Ok(token.filter(|t| !t.is_empty()))
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Seal `msg` for WinRM: returns (signature, sealed data). The context must be complete.
    pub fn encrypt(&self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut sizes = SecPkgContext_Sizes::default();
        unsafe { QueryContextAttributesW(&self.ctx, SECPKG_ATTR_SIZES, (&mut sizes as *mut SecPkgContext_Sizes).cast())? };
        let mut sig = vec![0u8; sizes.cbSecurityTrailer as usize];
        let mut data = msg.to_vec();
        let mut bufs = [buffer(SECBUFFER_TOKEN, &mut sig), buffer(SECBUFFER_DATA, &mut data)];
        let d = desc(&mut bufs);
        unsafe { EncryptMessage(&self.ctx, 0, &d, 0).ok()? };
        let (sig_len, data_len) = (bufs[0].cbBuffer as usize, bufs[1].cbBuffer as usize);
        sig.truncate(sig_len);
        data.truncate(data_len);
        Ok((sig, data))
    }

    /// Inverse of `encrypt`.
    pub fn decrypt(&self, sig: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        let (mut sig, mut data) = (sig.to_vec(), sealed.to_vec());
        let mut bufs = [buffer(SECBUFFER_TOKEN, &mut sig), buffer(SECBUFFER_DATA, &mut data)];
        let d = desc(&mut bufs);
        unsafe { DecryptMessage(&self.ctx, &d, 0, None).ok()? };
        let n = bufs[1].cbBuffer as usize;
        data.truncate(n);
        Ok(data)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            if self.has_ctx {
                let _ = DeleteSecurityContext(&self.ctx);
            }
            let _ = FreeCredentialsHandle(&self.cred);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl Client {
        /// Server side of a loopback handshake.
        fn accept(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>> {
            let mut input = input.to_vec();
            let mut inb = [buffer(SECBUFFER_TOKEN, &mut input)];
            let ind = desc(&mut inb);
            let mut outb = [SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: std::ptr::null_mut() }];
            let mut outd = desc(&mut outb);
            let flags = ASC_REQ_CONFIDENTIALITY | ASC_REQ_INTEGRITY | ASC_REQ_ALLOCATE_MEMORY;
            let ctx: *mut SecHandle = &mut self.ctx;
            let mut attrs = 0;
            let status = unsafe {
                AcceptSecurityContext(
                    Some(&self.cred),
                    self.has_ctx.then_some(ctx as *const _),
                    Some(&ind),
                    flags,
                    SECURITY_NATIVE_DREP,
                    Some(ctx),
                    Some(&mut outd),
                    &mut attrs,
                    None,
                )
            };
            self.finish(status, &outb[0])
        }
    }

    /// Client and server contexts for the current Windows user, signed in to each other.
    pub(crate) fn loopback(package: &str) -> (Client, Client) {
        let mut client = Client::open(package, SECPKG_CRED_OUTBOUND, None, "HTTP/localhost").unwrap();
        let mut server = Client::open(package, SECPKG_CRED_INBOUND, None, "").unwrap();
        let mut token = client.step(None).unwrap();
        while let Some(t) = token.take() {
            match server.accept(&t).unwrap() {
                Some(reply) if !client.is_complete() => token = client.step(Some(&reply)).unwrap(),
                _ => {}
            }
        }
        assert!(client.is_complete() && server.is_complete());
        (client, server)
    }

    #[test]
    fn loopback_handshake_and_sealing() {
        for package in ["NTLM", "Negotiate"] {
            let (client, server) = loopback(package);
            let msg = b"<s:Envelope>hello</s:Envelope>".repeat(50);
            let (sig, sealed) = client.encrypt(&msg).unwrap();
            assert_ne!(sealed, msg);
            assert_eq!(server.decrypt(&sig, &sealed).unwrap(), msg);
            let (sig, sealed) = server.encrypt(b"reply").unwrap();
            assert_eq!(client.decrypt(&sig, &sealed).unwrap(), b"reply");
            assert!(client.decrypt(&sig, &sealed).is_err(), "replayed message must fail");
        }
    }

    #[test]
    fn bad_package_is_an_error() {
        assert!(Client::new("NoSuchPackage", "DOM\\u", "pw", "HTTP/x").is_err());
    }
}
