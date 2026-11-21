//! Bitwarden encryption: KDF, key stretching, EncString (types 2 and 4) (owner: vault).

use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use rsa::{pkcs8::DecodePrivateKey, Oaep, PrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// 64-byte symmetric key: AES-256 key, then HMAC-SHA256 key.
pub type Key = Zeroizing<Vec<u8>>;

/// Key derivation from prelogin. Argon2id memory is in MiB.
pub enum Kdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

/// 32-byte master key; the salt is the email, lowercased and trimmed (Argon2id: its SHA-256).
pub fn master_key(password: &str, email: &str, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    let salt = email.trim().to_lowercase();
    let mut key = Zeroizing::new([0u8; 32]);
    match *kdf {
        Kdf::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations, &mut *key)
        }
        Kdf::Argon2id { iterations, memory_mib, parallelism } => {
            let params = argon2::Params::new(memory_mib.saturating_mul(1024), iterations, parallelism, Some(32))
                .map_err(|e| anyhow!("bad Argon2 parameters: {e}"))?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &Sha256::digest(salt.as_bytes()), &mut *key)
                .map_err(|e| anyhow!("Argon2 failed: {e}"))?;
        }
    }
    Ok(key)
}

/// HKDF-Expand the master key into enc|mac.
pub fn stretch(master: &[u8; 32]) -> Result<Key> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(master).map_err(|_| anyhow!("HKDF: bad key length"))?;
    let mut key = Zeroizing::new(vec![0u8; 64]);
    hk.expand(b"enc", &mut key[..32]).map_err(|_| anyhow!("HKDF failed"))?;
    hk.expand(b"mac", &mut key[32..]).map_err(|_| anyhow!("HKDF failed"))?;
    Ok(key)
}

/// Type 2 EncString "2.iv|ct|mac": the MAC is verified (constant time) before decrypting.
pub fn decrypt(enc: &str, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 64 {
        bail!("bad key length {}", key.len());
    }
    let parts: Vec<&str> = enc.strip_prefix("2.").context("unsupported EncString type")?.split('|').collect();
    let [iv, ct, mac] = parts[..] else { bail!("malformed EncString") };
    let (iv, mut ct, mac) = (b64(iv)?, Zeroizing::new(b64(ct)?), b64(mac)?);
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&key[32..]).map_err(|_| anyhow!("bad MAC key"))?;
    m.update(&iv);
    m.update(&ct);
    m.verify_slice(&mac).map_err(|_| anyhow!("EncString MAC mismatch"))?;
    let n = cbc::Decryptor::<Aes256>::new_from_slices(&key[..32], &iv)
        .map_err(|_| anyhow!("bad IV length"))?
        .decrypt_padded::<Pkcs7>(&mut ct)
        .map_err(|_| anyhow!("bad padding"))?
        .len();
    ct.truncate(n);
    Ok(ct)
}

/// `decrypt` as UTF-8 text.
pub fn decrypt_str(enc: &str, key: &[u8]) -> Result<Zeroizing<String>> {
    let mut bytes = decrypt(enc, key)?;
    String::from_utf8(std::mem::take(&mut *bytes)).map(Zeroizing::new).map_err(|e| {
        e.into_bytes().zeroize();
        anyhow!("decrypted text is not UTF-8")
    })
}

/// Type 4 EncString "4.b64" (RSA-OAEP-SHA1), e.g. an organization key, with a PKCS#8 DER private key.
pub fn rsa_decrypt(enc: &str, private_der: &[u8]) -> Result<Key> {
    let ct = b64(enc.strip_prefix("4.").context("unsupported RSA EncString type")?)?;
    let key = PrivateKey::from_pkcs8_der(private_der).map_err(|_| anyhow!("bad private key"))?;
    Ok(Zeroizing::new(key.decrypt(Oaep::<Sha1>::new(), &ct).map_err(|_| anyhow!("RSA decryption failed"))?))
}

fn b64(s: &str) -> Result<Vec<u8>> {
    STANDARD.decode(s).context("bad base64 in EncString")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    const PBKDF2: &str = "acb6ea576275454518707494168a0d06a33d7deb95ff3b7456be140e3ffaac09";

    #[test]
    fn pbkdf2_and_stretch() {
        let mk = master_key("correct horse", " Tester@Example.com ", &Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
        assert_eq!(hex(&*mk), PBKDF2);
        assert_eq!(
            hex(&stretch(&mk).unwrap()),
            "d2a675b9365fee47d89432d230ae850d64c667675caa0c3de12e5e1998d7152e\
             35662dff01d84e151a91e08fa53a104b9b4cf5b292176c09c80fd5486373afd4"
        );
    }

    #[test]
    fn argon2id() {
        let kdf = Kdf::Argon2id { iterations: 2, memory_mib: 1, parallelism: 1 };
        let mk = master_key("correct horse", "tester@example.com", &kdf).unwrap();
        assert_eq!(hex(&*mk), "97946b8895ac944f6348a85c02e339da7256a7f304af39b881b61982aa7118bc");
    }

    #[test]
    fn enc_string() {
        let key: Vec<u8> = (0..64).collect();
        let enc = "2.AAAAAAAAAAAAAAAAAAAAAA==|52XurryroAy3/eQ4G4sfvQ==|opHQncJ2gjRgi8srQ1EfxyCCCwrzmdjJ++iKW0L63xE=";
        assert_eq!(&*decrypt_str(enc, &key).unwrap(), "hello valet");
        let tampered = enc.replace("opHQ", "opHR");
        assert!(decrypt(&tampered, &key).unwrap_err().to_string().contains("MAC"));
        let mut wrong = key.clone();
        wrong[40] ^= 1;
        assert!(decrypt(enc, &wrong).is_err());
        assert!(decrypt("0.abc|def", &key).is_err());
    }
}
