//! Talks to Vaultwarden/Bitwarden directly, replacing `bw serve`.
//!
//! Login with the user's personal API key (client_credentials), stored DPAPI-protected in
//! %LOCALAPPDATA%\valet\login.bin. `unlock` derives the master key from the master password
//! (PBKDF2 or Argon2id per prelogin), decrypts the user key, private key and organization keys, and
//! keeps only keys and still-encrypted ciphers in memory. `creds` decrypts the items of one collection.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cred::Cred;
use crate::crypto::{self, uuid, Kdf, Key};

/// Bitwarden DeviceType 23 = Windows CLI.
const DEVICE_TYPE: &str = "23";

#[derive(serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
struct Login {
    server: String,
    client_id: String,
    client_secret: String,
    device_id: String,
    email: String,
}

impl Login {
    fn save(&self, home: &Path) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(self)?);
        std::fs::create_dir_all(home)?;
        std::fs::write(home.join("login.bin"), &*dpapi(&plain, true)?).context("cannot write login.bin")
    }
}

struct Keys {
    user: Key,
    /// PKCS#8 DER; decrypts organization keys.
    private: Option<Key>,
}

pub struct Vault {
    login: Login,
    http: reqwest::Client,
    token: Option<(Zeroizing<String>, Instant)>,
    keys: Option<Keys>,
    /// The last /api/sync response, still encrypted.
    sync: Option<Value>,
}

impl Vault {
    /// Saved login (server URL, API key) from the home directory, or None if setup never ran.
    pub fn load(home: &Path) -> Result<Option<Vault>> {
        let blob = match std::fs::read(home.join("login.bin")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            r => r.context("cannot read login.bin")?,
        };
        let login = serde_json::from_slice(&dpapi(&blob, false)?).context("login.bin is corrupt; run valet setup")?;
        Ok(Some(Vault::new(login)?))
    }

    /// Signs in with a personal API key and saves it. The result is still locked.
    pub async fn sign_in(home: &Path, server: &str, client_id: &str, client_secret: Zeroizing<String>) -> Result<Vault> {
        if !client_id.starts_with("user.") {
            bail!("{client_id:?} is not a personal API key (an organization key cannot open your vault)");
        }
        let device_id = match Vault::load(home) {
            Ok(Some(v)) => v.login.device_id.clone(),
            _ => uuid(),
        };
        let login = Login {
            server: server.trim_end_matches('/').to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            device_id,
            email: String::new(),
        };
        let mut vault = Vault::new(login)?;
        let sync = vault.fetch().await?;
        vault.login.email = sync["profile"]["email"].as_str().context("sync has no profile email")?.to_string();
        vault.login.save(home)?;
        Ok(vault)
    }

    /// Email used as the KDF salt; shown in the unlock window.
    pub fn email(&self) -> &str {
        &self.login.email
    }

    pub fn server(&self) -> &str {
        &self.login.server
    }

    /// Token + sync + key derivation. Wrong password -> error that says so.
    pub async fn unlock(&mut self, master_password: &Zeroizing<String>) -> Result<()> {
        let sync = self.fetch().await?;
        if let Some(email) = sync["profile"]["email"].as_str() {
            self.login.email = email.to_string();
        }
        let r = self.http.post(self.url("/identity/accounts/prelogin")).json(&json!({"email": self.login.email}));
        let kdf = kdf(&response(r.send().await?).await?)?;
        let (password, profile) = (master_password.clone(), sync["profile"].clone());
        self.keys = Some(tokio::task::spawn_blocking(move || unlock_keys(&password, &kdf, &profile)).await??);
        self.sync = Some(sync);
        Ok(())
    }

    pub fn is_unlocked(&self) -> bool {
        self.keys.is_some()
    }

    /// Drop all keys and decrypted data.
    pub fn lock(&mut self) {
        self.keys = None;
        self.sync = None;
        self.token = None;
    }

    /// Fetch ciphers again (new or changed items).
    pub async fn sync(&mut self) -> Result<()> {
        if !self.is_unlocked() {
            bail!("vault is locked");
        }
        self.sync = Some(self.fetch().await?);
        Ok(())
    }

    /// Login items (type 1) in the collection with this name or id, decrypted.
    pub fn creds(&self, collection: &str) -> Result<Vec<Cred>> {
        match (&self.sync, &self.keys) {
            (Some(sync), Some(keys)) => creds_from(sync, keys, collection),
            _ => bail!("vault is locked"),
        }
    }

    fn new(login: Login) -> Result<Vault> {
        let http = crate::http::client(Duration::from_secs(30), false)?;
        Ok(Vault { login, http, token: None, keys: None, sync: None })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.login.server)
    }

    /// GET /api/sync, logging in first if there is no valid token.
    async fn fetch(&mut self) -> Result<Value> {
        let token = match &self.token {
            Some((t, expires)) if Instant::now() < *expires => t.clone(),
            _ => {
                let l = &self.login;
                let form = Zeroizing::new(
                    url::form_urlencoded::Serializer::new(String::new())
                        .extend_pairs([
                            ("grant_type", "client_credentials"),
                            ("scope", "api"),
                            ("client_id", &l.client_id),
                            ("client_secret", &l.client_secret),
                            ("deviceType", DEVICE_TYPE),
                            ("deviceIdentifier", &l.device_id),
                            ("deviceName", "valet"),
                        ])
                        .finish(),
                );
                let r = self
                    .http
                    .post(self.url("/identity/connect/token"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(form.to_string());
                let sent = r.send().await.with_context(|| format!("cannot reach {}", self.login.server))?;
                let body = response(sent)
                    .await
                    .context("the vault rejected this client_id and secret; copy them again from View API key")?;
                let token = Zeroizing::new(body["access_token"].as_str().context("login: no access_token")?.to_string());
                let ttl = body["expires_in"].as_u64().unwrap_or(3600).saturating_sub(60);
                self.token = Some((token.clone(), Instant::now() + Duration::from_secs(ttl)));
                token
            }
        };
        let r = self.http.get(self.url("/api/sync?excludeDomains=true")).bearer_auth(&*token);
        response(r.send().await?).await
    }
}

/// JSON body, or an error with the server's message.
async fn response(r: reqwest::Response) -> Result<Value> {
    let status = r.status();
    let body = r.text().await?;
    if !status.is_success() {
        let v: Value = serde_json::from_str(&body).unwrap_or_default();
        let msg = v["error_description"].as_str().or(v["message"].as_str()).unwrap_or("");
        bail!("vault server: {status} {msg}");
    }
    serde_json::from_str(&body).context("vault server sent invalid JSON")
}

fn kdf(prelogin: &Value) -> Result<Kdf> {
    let n = |k: &str| -> Result<u32> {
        prelogin[k].as_u64().and_then(|v| u32::try_from(v).ok()).with_context(|| format!("prelogin: no {k}"))
    };
    match prelogin["kdf"].as_u64() {
        Some(0) => Ok(Kdf::Pbkdf2 { iterations: n("kdfIterations")? }),
        Some(1) => Ok(Kdf::Argon2id {
            iterations: n("kdfIterations")?,
            memory_mib: n("kdfMemory")?,
            parallelism: n("kdfParallelism")?,
        }),
        k => bail!("unsupported KDF {k:?}"),
    }
}

fn unlock_keys(password: &str, kdf: &Kdf, profile: &Value) -> Result<Keys> {
    let email = profile["email"].as_str().context("sync has no profile email")?;
    let master = crypto::stretch(&*crypto::master_key(password, email, kdf)?)?;
    let user = crypto::decrypt(profile["key"].as_str().context("sync has no user key")?, &master)
        .map_err(|_| anyhow!("wrong master password"))?;
    let private = profile["privateKey"].as_str().map(|p| crypto::decrypt(p, &user)).transpose()?;
    Ok(Keys { user, private })
}

fn list(v: &Value) -> impl Iterator<Item = &Value> {
    v.as_array().into_iter().flatten()
}

/// Decrypted text of an EncString field; null or missing is "".
fn text(v: &Value, key: &[u8]) -> Result<Zeroizing<String>> {
    v.as_str().map_or(Ok(Zeroizing::default()), |e| crypto::decrypt_str(e, key))
}

fn creds_from(sync: &Value, keys: &Keys, collection: &str) -> Result<Vec<Cred>> {
    let mut orgs = HashMap::new();
    for o in list(&sync["profile"]["organizations"]) {
        let private = keys.private.as_ref().context("no private key to decrypt organization keys")?;
        let key = crypto::rsa_decrypt(o["key"].as_str().context("organization without key")?, private)?;
        orgs.insert(o["id"].as_str().unwrap_or(""), key);
    }
    let key_for = |item: &Value| -> Result<&Key> {
        match item["organizationId"].as_str() {
            Some(org) => orgs.get(org).context("no key for organization"),
            None => Ok(&keys.user),
        }
    };
    let mut ids = Vec::new();
    for c in list(&sync["collections"]) {
        let id = c["id"].as_str().unwrap_or("");
        if id == collection || *text(&c["name"], key_for(c)?)? == collection {
            ids.push(id);
        }
    }
    let [cid] = ids[..] else {
        bail!("collection {collection:?} matched {} collections; use the collection id", ids.len())
    };
    list(&sync["ciphers"])
        .filter(|c| c["type"] == 1 && c["deletedDate"].is_null() && list(&c["collectionIds"]).any(|x| x == cid))
        .map(|c| cred(c, key_for(c)?))
        .collect()
}

fn cred(c: &Value, base: &Key) -> Result<Cred> {
    let own;
    let key = match c["key"].as_str() {
        Some(k) => {
            own = crypto::decrypt(k, base)?;
            &own
        }
        None => base,
    };
    let s = |v: &Value| text(v, key);
    let login = &c["login"];
    let mut uris = Vec::new();
    for u in list(&login["uris"]) {
        let u = s(&u["uri"])?;
        if !u.is_empty() {
            uris.push(u.to_string());
        }
    }
    let mut fields = HashMap::new();
    for f in list(&c["fields"]) {
        let name = s(&f["name"])?.trim().to_lowercase();
        if !name.is_empty() {
            fields.insert(name, Zeroizing::new(s(&f["value"])?.trim().to_string()));
        }
    }
    Ok(Cred {
        id: c["id"].as_str().unwrap_or("").to_string(),
        name: s(&c["name"])?.to_string(),
        username: s(&login["username"])?.to_string(),
        password: s(&login["password"])?,
        totp: s(&login["totp"])?,
        uris,
        fields,
    })
}

/// DPAPI (current user) protect or unprotect.
fn dpapi(data: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::*;
    let input = CRYPT_INTEGER_BLOB { cbData: u32::try_from(data.len())?, pbData: data.as_ptr().cast_mut() };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` points at `data` for the call; `out` is allocated by DPAPI and freed here.
    unsafe {
        if protect {
            CryptProtectData(&input, PCWSTR::null(), None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        } else {
            CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        }
        .map_err(|e| anyhow!("DPAPI failed: {}", e.message()))?;
        let bytes = Zeroizing::new(std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec());
        std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        LocalFree(Some(HLOCAL(out.pbData.cast())));
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDF: Kdf = Kdf::Pbkdf2 { iterations: 5000 };
    /// Fake account "Tester@Example.com" / "correct horse": one org, collections "Valet" and "Other".
    const SYNC: &str = r#"{"profile": {"email": "Tester@Example.com", "key": "2.nN9pKkGcNGwaX1DGAbAIrg==|WA9kgKRozkPqxmD1f8nMmRvok7V905Qrtdi5ZAhSlqqC6Vh5OHiFDythCTw5qs3xsXN1HmmZvhj2ZYdQ+iJrYkMxInyVZs9/mDbL/okUans=|P2hWr+Dqk4uPR4j6n+oz+O65gafLlMBHbcTzcQ1DJbo=", "privateKey": "2.MCza6eckIFkt/ayEYbNkOw==|oEri5WMd+Vk8qlqTUGMxnY3+O0bKe10D+TPdGBHMTtDgvrQBye6RgKw4j2PJi8iyTD/Ms/bxfUxyLGzGWQpEyWujCWjylHiOwOokyY+AiR+QDh5ixI8PGwTFxZFipOkA+c8YPb79RTa6aJpIoa2kONnoGBzz6WWr1kexoJ7R8plkanhjlP0Sd8eiqYp6iTmbwX3BBj01MNc01cqTPPD8kqmD5x8nqx9JF0apkTSlyg89Zg1rCFBBXqcKseygFC/fKBev5Tl+On8yIT7ahz9ga96vv19/G7Ek8msavCdLtdT4COoAMcgUDsBR2RmocS6IO1YMO6gSAhHgUGraFGJYUABWDOmVj/0NSy02hI0GdWPUm1Qi8Vy+MAPVaIb5D9GLk/Zdz3S5LeuEK11OKF4qoNg9uE60I7GlD+5c6hXbKZCVUuDngB7HXxk7JcQBztOfepzSqBNG8iY/4I12F2SwGL7f1HYUvEP8gyfYTDMldlWACUGRgi6TqD69y8OAtCrU2uEfXwUg51k38g9NseyZbQcwqpG7fDZ1RwtEsqciHo4CC1hIZGyXMPOV6DpbkYpuNAxeiKKKU+nEqWeJEuAo0QurI4fZnVVZo7+kFn2w7HzWWOcRmu34XJeHMgCBACxhxxFkGkujBJcw5OHgqMYG0t6NDeyULmtJzENtBk2VW0ruimLxKcOB/2TxgCu1ij6mcq55Mb6A0aY6paH5Utzm9bhnrRbEELIcQH5vO0t5ewV89+bP29qIiswWxSWBwVVIc9JxrAafTBYkBnnHiRHWd19PW18wj7ZstT2vHzvq/w9yuYQ98Q20cMmbb4spwzd8LX6RIqexdIKWABKcl268wY5pPQcZlLuHe6SsU5cE4ziWHh3rUrJtPQ7WwlMesetVWIxuM5Y0s0y4EjnQ0HHwkRYzLazRltUU3752NwRhfZCUfffArriTIioCP63Fk1GCU/Ic6Yi2WOlcExWi/bL8FA40Y/ZfTVnuyxhmyPNW1pmZYKCy9qFILqdyic4V4LyXxNczqYmk3p5i005K2DuuN5fjwTP+FRc9Z8KFaPx8WL0X871TTrCLdkTzqThpSdh44eo2m+YPQpuLbRr9JjSwg5Md0Hwf8uKnV1Bq/5lF5wgxfnFJYQIMzI8rIzwgh1cnDkAWgQgcQi1eodCiby6cKBgAzsHaWFVwC+3XDH23O8Yw7EmKcHPToNPSHFs2dyc2Vhgq9IL4EmuH0B7GsQbC89FMO7Y/MXLEaoWG5zhVFhg0W4m7APEfzt0h6Ovy18o84U4apzCyVLurpWIaNDjwnDHglEm3IugBDqJpq8LZubOhtyte+YiqVMzz+q0T+HhLy7cXFdn1dqgePIfqEENKnd5Sngnko2V7wfFIKsPQ1VkcrvJCp9ePGdf+5KPxScLpYZHSC+bRzVuhojf8BHqjUNDs3A+uIm0PYMaVCGdNY7FBcOC2KTpCLFCkZVq238C1sEBlocWD5NesWIhItuLRVydJ4ld6l6rrGlsIf5iCUhYbqXopuwCi//RacdlTLI8/S+l8boJ4et9Nyirsu6uPFU8ucHQ9vhW83iLP/RbE77dZi+j3yJ4I6DK/uG3Qwocc5GWStfx5dbQ1D+7jmTNnhUAY3CMQVPbCpBkwqtrsaPE=|r5lcNknGs9TOKzcAG6OSKSAWQjlKyMt9NyeKKg39+B8=", "organizations": [{"id": "0a000000-0000-4000-8000-000000000001", "key": "4.lUsUKC8r/8NXxhbQV3HdA6Y1Esshi92GSZwclvHEkQcYGK+ISl/VaXU/q01JTRUo8QyLKhEfbfLsRWZ5DUGb0DadqbeyqYJRLiG3wUfbCuGYY+NTHOtnezatGnROKLjBhWNyD8ljoqKKE86iKN4G+7DifXRCaRIDvZjVfy6qTNDXvSlAfIVG2PpfcdUkf766xeqJlRb+U7Wp2kmBfVf/65JVdfLdDomH6rMnmz09U2Bg9seg1vdgFxxc/uixzJFXWHsDt2/kuiwQrS3N3WrmK4XGCcD44lTC3NpOsYEZqZlM+KWPRkCPlPIJwHc05/TJM7wC6m4nRGkTbAYGIEFxjg=="}]}, "collections": [{"id": "0c000000-0000-4000-8000-000000000001", "organizationId": "0a000000-0000-4000-8000-000000000001", "name": "2.YHvogjQrjM1uOIDTDj0UVw==|GRgx4pBDbcj6ixinGD1vBQ==|afnoO36JgI8JicwjAZWR8+FHC8AmlFNrqWBqgvbj+V4="}, {"id": "0c000000-0000-4000-8000-000000000002", "organizationId": "0a000000-0000-4000-8000-000000000001", "name": "2.uDWhpMsBDOhcGc8IVRUXeQ==|YqcsIc420ophsOdto/T9EA==|9S1RLQU6e2BisryA0atz/zgIp+oH2OEYFszzKUcxKH0="}], "ciphers": [{"id": "a", "type": 1, "organizationId": "0a000000-0000-4000-8000-000000000001", "collectionIds": ["0c000000-0000-4000-8000-000000000001"], "key": "2.INAU0cSSkYntUFp6IsB7XQ==|sLTDmhxpTbaal8hASwkRhhlNJUVh3AZyagaWPR/nSkJlY1eIN5zX7K/f/1Rzq0KJVdOO/96GmDmkzman4KIXXiqNFG2NFQq/CWlxHtco6kE=|Z7PW12BVdiFsx0bDoTuqJ6p+xGhsUh4vqmKbjFrEtew=", "deletedDate": null, "name": "2.SjJTPcWyE4BReFgHrkVm9Q==|WwKwO1NPxKm1VzSeqArDHg==|ejX2vPm3sCtpk7IQoY7z969m7BKEKaNKIJ6eKJVE3rg=", "login": {"username": "2.R3zmi4ePzpldBk1W4Mi9iw==|3ugAWYhLLuYGsyGNMtQokQ==|E1T1DA/n9mM6PZBYUBZeZtYe4efHJIXPsccQG4gwI98=", "password": "2.FvUm+EVJHhV7TXDqUMPc+g==|1zzy+Tkkf8tEIBpT/Zly9g==|xg4Yob52VyRu7eEcnG8fnR+pq1oSchEpVL4QS1w3hr0=", "totp": "2.ZiDfZfDR3kJHKtAnhjSRNw==|eO3O3W0zozu1/Qv+vQJAMD+muU0jY4S3WQuOR2shAvU=|6Vibnfn+1AV/skw+eyo/g0ZT0DdRcSqX/igaqBtgE3c=", "uris": [{"uri": "2.71Ex5SpkCrS/oIsA/tKXmw==|hNcV03ifrZgzCbwDJK1cFTSMfwfaZZlfk634gI64qEM=|K0Vc5JHbZuY5cFR1DcIZZ/URbzbpIXE5Y4Oa+F0Qd2s="}, {"uri": "2.NnuBUmcMFz20n8ieOmOUqA==|xaFzns6yMhL8oOk0ucsHp3p7vptmdY8nnb9/FHbd0wI=|OjOiYL8VsE6adHL6ReUjC0jgriel6L6fFCxCg8ZP0bA="}]}, "fields": [{"name": "2.sQIyXYJIJ7x6qkuysXAYJQ==|psOs6FvSIrJ6wYh6No2BSQ==|HYS2RW/dK/0R+O1IkA77jFgdkWovROPq5NQpxzCt9Ro=", "value": "2.O3ArqorZv+HOv8TbvLYuyA==|jZfjFRtsqZuFRSh2gACzlQ==|JEAjcPn03GnRhs+AUquGaJma+UW1o6e0lojXafZMquE=", "type": 0}]}, {"id": "b", "type": 1, "organizationId": "0a000000-0000-4000-8000-000000000001", "collectionIds": ["0c000000-0000-4000-8000-000000000001"], "key": null, "name": "2.OB9ZKQZbElVTUrMm2qtP9g==|bxGql8KkwYojBb/2SFtYlg==|X5WqGux93HWWscx2G0UXc9hPv/tRGTAeWPERrhKfDcY=", "login": {"username": "2.4hsxM876Hhi2Sd/s1Kx6Pw==|O+9l3+AexTeXXReB2XgkWQ==|1e3NH5BIAgjAhTDusKb3Kwq7mHCPRivWDPP3eqNKWxE=", "password": null, "totp": null, "uris": null}, "fields": [{"name": "2./hiFwD29xnhXMxUz57NhVw==|zJFEWG5a2MzqUHAB3EA6jg==|72ONqVlUZ0ayekBd3AElOtzeYII4Lbm1GWBFld/jYps=", "value": null, "type": 0}]}, {"id": "x", "type": 1, "organizationId": "0a000000-0000-4000-8000-000000000001", "collectionIds": ["0c000000-0000-4000-8000-000000000002"], "name": "2.29l+Z89QNIkJ0VLfRVLMyQ==|X3WTWTJzvr76cfJHuSdNxw==|0pca+tGKR8d1mZ6LTyPP0gly5BFWiuMcpz47J73c/9g=", "login": {"username": "2.WJez9qXgrpsHR42EaFUg1w==|WmJfWM3qfduoNfs8w/t9CQ==|lBC8x+0AADwNRUH18AAHiABUlcld5kRADCcBWa//d3U="}}, {"id": "n", "type": 2, "organizationId": "0a000000-0000-4000-8000-000000000001", "collectionIds": ["0c000000-0000-4000-8000-000000000001"], "name": "2.5s7oamVQYzARpdR7/llvjQ==|4OWcj/gfscSzLY+7CmHQLw==|miheD4kZvJG+8OxrUwoQFkOchgWUEWy0e6DT8Vm5MRc=", "login": null}, {"id": "d", "type": 1, "organizationId": "0a000000-0000-4000-8000-000000000001", "collectionIds": ["0c000000-0000-4000-8000-000000000001"], "name": "2.HGMcFpQA/A9fEsyAh0Fyfw==|l6HR+/YHaAIRrUm/Z4Ch4g==|ADORpeY6MjWBL9fvz4xbLFb4Cr6lNVSLK22ul7D6oYs=", "deletedDate": "2026-01-01T00:00:00Z", "login": {}}, {"id": "p", "type": 1, "organizationId": null, "collectionIds": [], "name": "2.XPYn7TrQwn1GgVZPnDnCiQ==|815kYlW0A5tAN09rwoSvbQ==|HeS7LWom62CODq+p/7+qEoXuNk9ku2kVnRjMDhf3mXc=", "login": {}}]}"#;

    fn keys(password: &str) -> Result<(Value, Keys)> {
        let sync: Value = serde_json::from_str(SYNC).unwrap();
        let keys = unlock_keys(password, &KDF, &sync["profile"])?;
        Ok((sync, keys))
    }

    #[test]
    fn unlock_to_creds() {
        let (sync, keys) = keys("correct horse").unwrap();
        let creds = creds_from(&sync, &keys, "Valet").unwrap();
        // "x" is in another collection, "n" is a note, "d" is trashed, "p" is personal.
        assert_eq!(creds.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        let a = &creds[0];
        assert_eq!((a.name.as_str(), a.username.as_str(), a.password.as_str()), ("Server A", "alice", "pa55"));
        assert_eq!(a.totp.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(a.uris, ["https://a.example.com", "ssh://a.example.com"]);
        assert_eq!(a.field("broker_auth"), "header:X-Key");
        let b = &creds[1];
        assert_eq!((b.name.as_str(), b.username.as_str(), b.password.as_str()), ("Server B", "bob", ""));
        assert!(b.uris.is_empty());
        assert_eq!(b.fields.get("empty").map(|v| v.as_str()), Some(""));

        let by_id = creds_from(&sync, &keys, "0c000000-0000-4000-8000-000000000001").unwrap();
        assert_eq!(by_id.len(), 2);
        let other = creds_from(&sync, &keys, "Other").unwrap();
        assert_eq!(other.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Elsewhere"]);
        assert!(creds_from(&sync, &keys, "Nope").err().unwrap().to_string().contains("matched 0"));
    }

    #[test]
    fn wrong_password() {
        let err = keys("wrong horse").err().unwrap();
        assert_eq!(err.to_string(), "wrong master password");
    }

    #[test]
    fn prelogin_kdf() {
        assert!(matches!(kdf(&json!({"kdf": 0, "kdfIterations": 600000})).unwrap(), Kdf::Pbkdf2 { iterations: 600000 }));
        let a = json!({"kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4});
        assert!(matches!(kdf(&a).unwrap(), Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 }));
        assert!(kdf(&json!({"kdf": 1, "kdfIterations": 3})).is_err());
    }

    #[test]
    fn login_file_round_trip() {
        let secret = b"client secret";
        let blob = dpapi(secret, true).unwrap();
        assert_ne!(&blob[..], secret);
        assert_eq!(&dpapi(&blob, false).unwrap()[..], secret);

        let home = std::env::temp_dir().join(format!("valet-vault-test-{}", uuid()));
        assert!(Vault::load(&home).unwrap().is_none());
        let login = Login {
            server: "https://vault.test".into(),
            client_id: "user.x".into(),
            client_secret: "s".into(),
            device_id: uuid(),
            email: "t@example.com".into(),
        };
        login.save(&home).unwrap();
        let v = Vault::load(&home).unwrap().unwrap();
        assert_eq!((v.email(), v.login.device_id.as_str()), ("t@example.com", login.device_id.as_str()));
        assert!(!v.is_unlocked());
        std::fs::remove_dir_all(&home).unwrap();
    }
}
