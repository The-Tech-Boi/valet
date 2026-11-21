//! Redaction: every form in which a credential's secrets could come back, replaced by
//! `[REDACTED:<name>]` before a result, an audit line or a `valet run` output line leaves valet.

use base64::Engine;
use regex::{Captures, Regex, RegexBuilder};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::cred::Cred;
use crate::otp;

/// Case-insensitive, longest secret first. Each secret is its own regex group, so no copy of it is
/// kept to find the item it belongs to.
#[derive(Default)]
pub struct Redactor {
    re: Option<Regex>,
    /// `[REDACTED:<name>]` per regex group.
    tags: Vec<String>,
}

impl Redactor {
    /// `named`: (item name, its secrets).
    pub fn new(named: &[(String, Vec<Zeroizing<String>>)]) -> Self {
        let mut pairs: Vec<(&str, &str)> = named
            .iter()
            .flat_map(|(n, s)| s.iter().filter(|s| !s.is_empty()).map(move |s| (s.as_str(), n.as_str())))
            .collect();
        if pairs.is_empty() {
            return Redactor::default();
        }
        pairs.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        let alts: Vec<String> = pairs.iter().map(|(s, _)| format!("({})", regex::escape(s))).collect();
        let re = RegexBuilder::new(&alts.join("|"))
            .case_insensitive(true)
            .size_limit(1 << 28)
            .build()
            .expect("escaped literals always compile");
        Redactor { re: Some(re), tags: pairs.iter().map(|(_, n)| format!("[REDACTED:{n}]")).collect() }
    }

    pub fn for_cred(cred: &Cred) -> Self {
        Redactor::new(&[(cred.name.clone(), secrets(cred))])
    }

    pub fn apply(&self, text: &str) -> String {
        let Some(re) = &self.re else { return text.to_string() };
        re.replace_all(text, |c: &Captures| {
            let group = c.iter().skip(1).position(|g| g.is_some()).unwrap_or(0);
            self.tags[group].clone()
        })
        .into_owned()
    }
}

/// Every string inside `v` (keys too) through the redactor.
pub fn scrub(v: Value, r: &Redactor) -> Value {
    match v {
        Value::String(s) => Value::String(r.apply(&s)),
        Value::Array(a) => Value::Array(a.into_iter().map(|v| scrub(v, r)).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (r.apply(&k), scrub(v, r))).collect()),
        v => v,
    }
}

/// Every string a caller may see for this credential's secrets: password, TOTP seed and current
/// codes, base64(user:pass), and their URL/JSON-escaped forms. Longest first.
pub fn secrets(cred: &Cred) -> Vec<Zeroizing<String>> {
    let mut s = vec![cred.password.clone(), cred.totp.clone()];
    if !cred.password.is_empty() {
        let pair = Zeroizing::new(format!("{}:{}", cred.username, cred.password.as_str()));
        s.push(Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())));
    }
    s.extend(otp::secrets(&cred.totp));
    let escaped: Vec<Zeroizing<String>> = s
        .iter()
        .flat_map(|v| [quote(v, false), quote(v, true), json_escaped(v, false), json_escaped(v, true)])
        .map(Zeroizing::new)
        .collect();
    s.extend(escaped);
    s.retain(|v| !v.is_empty());
    s.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.as_str().cmp(b.as_str())));
    s.dedup();
    s
}

/// Python's `quote(v, safe="")` (or `quote_plus` when `plus`).
fn quote(v: &str, plus: bool) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => (b as char).to_string(),
            b' ' if plus => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The inside of a JSON string literal; `ascii` escapes non-ASCII as \uXXXX like Python's json.dumps.
fn json_escaped(v: &str, ascii: bool) -> String {
    let quoted = serde_json::to_string(v).unwrap_or_default();
    let inner = &quoted[1..quoted.len() - 1];
    if !ascii {
        return inner.to_string();
    }
    inner
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                c.encode_utf16(&mut [0; 2]).iter().map(|u| format!("\\u{u:04x}")).collect()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred::tests::SEED;
    use crate::otp::totp_now;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.into())
    }

    #[test]
    fn secrets_cover_escaped_forms_and_totp() {
        let mut c = Cred::test("web", &[], "p ä\"/", &[]);
        c.totp = z(SEED);
        let s = secrets(&c);
        let code = totp_now(SEED).unwrap();
        for want in ["p ä\"/", "p%20%C3%A4%22%2F", "p+%C3%A4%22%2F", "p ä\\\"/", "p \\u00e4\\\"/", SEED, code.as_str()] {
            assert!(s.iter().any(|x| x.as_str() == want), "missing {want:?}");
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode("svc-user:p ä\"/");
        assert!(s.iter().any(|x| *x.as_str() == b64));
        let r = Redactor::new(&[("web".into(), s)]);
        assert_eq!(r.apply(&format!("a P%20%c3%a4%22%2f b {} c", code.as_str())), "a [REDACTED:web] b [REDACTED:web] c");
    }

    #[test]
    fn redactor_longest_first_and_case_insensitive() {
        let r = Redactor::new(&[("a".into(), vec![z("abc")]), ("b".into(), vec![z("abcdef")])]);
        assert_eq!(r.apply("xABCDEFx abc"), "x[REDACTED:b]x [REDACTED:a]");
        assert_eq!(Redactor::default().apply("same"), "same");
    }
}
