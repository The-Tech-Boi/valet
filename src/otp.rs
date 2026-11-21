//! TOTP codes (RFC 6238) from an item's seed: a base32 secret or an otpauth:// URI.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use url::Url;
use zeroize::Zeroizing;

/// The current code, if the seed is valid.
pub fn totp_now(seed: &str) -> Option<Zeroizing<String>> {
    Otp::parse(seed).map(|o| o.at(unix_now()))
}

/// What a seed can leak: the normalized secret and the codes valid around now. Empty if not a seed.
pub fn secrets(seed: &str) -> Vec<Zeroizing<String>> {
    let Some(otp) = Otp::parse(seed) else { return Vec::new() };
    let codes = [-30, 0, 30].map(|d| otp.at(unix_now() + d));
    [otp.secret].into_iter().chain(codes).collect()
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

struct Otp {
    secret: Zeroizing<String>,
    key: Zeroizing<Vec<u8>>,
    digits: u32,
    period: u64,
    algorithm: String,
}

impl Otp {
    fn parse(seed: &str) -> Option<Otp> {
        let (mut secret, mut digits, mut period, mut algorithm) =
            (Zeroizing::new(seed.to_string()), 6, 30, "SHA1".to_string());
        if seed.starts_with("otpauth://") {
            secret = Zeroizing::new(String::new());
            for (k, v) in Url::parse(seed).ok()?.query_pairs() {
                match &*k {
                    "secret" => secret = Zeroizing::new(v.into_owned()),
                    "digits" => digits = v.parse().ok()?,
                    "period" => period = v.parse().ok()?,
                    "algorithm" => algorithm = v.to_uppercase(),
                    _ => {}
                }
            }
        }
        let secret = Zeroizing::new(secret.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase());
        let key = Zeroizing::new(base32(&secret)?);
        let valid = !key.is_empty()
            && (1..=10).contains(&digits)
            && period > 0
            && ["SHA1", "SHA256", "SHA512"].contains(&algorithm.as_str());
        valid.then_some(Otp { secret, key, digits, period, algorithm })
    }

    fn at(&self, t: i64) -> Zeroizing<String> {
        let counter = (t.max(0) as u64 / self.period).to_be_bytes();
        let h: Zeroizing<Vec<u8>> = Zeroizing::new(match self.algorithm.as_str() {
            "SHA256" => Hmac::<sha2::Sha256>::new_from_slice(&self.key).unwrap().chain_update(counter).finalize().into_bytes().to_vec(),
            "SHA512" => Hmac::<sha2::Sha512>::new_from_slice(&self.key).unwrap().chain_update(counter).finalize().into_bytes().to_vec(),
            _ => Hmac::<sha1::Sha1>::new_from_slice(&self.key).unwrap().chain_update(counter).finalize().into_bytes().to_vec(),
        });
        let o = (h[h.len() - 1] & 0xf) as usize;
        let n = u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff;
        Zeroizing::new(format!("{:0w$}", n as u64 % 10u64.pow(self.digits), w = self.digits as usize))
    }
}

/// RFC 4648 base32, uppercase, padding optional. None on any other character.
fn base32(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5 | v as u32) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred::tests::SEED;

    #[test]
    fn totp_matches_rfc6238() {
        let o = Otp::parse(SEED).unwrap();
        assert_eq!(*o.at(59), "287082");
        let o = Otp::parse(&format!("otpauth://totp/x?secret={}&digits=8", SEED.to_lowercase())).unwrap();
        assert_eq!(*o.at(59), "94287082");
        assert_eq!(*o.at(1111111109), "07081804");
        // SHA256 test key is the 32-byte "1234567890" * 3 + "12".
        let o = Otp::parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256").unwrap();
        assert_eq!(*o.at(59), "46119246");
        assert!(Otp::parse("not base32!").is_none() && Otp::parse("").is_none());
        assert!(secrets("").is_empty() && secrets(SEED).len() == 4);
    }
}
