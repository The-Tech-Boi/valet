//! ssh_exec: password SSH. The host key must already be in ~/.ssh/known_hosts, so the password never
//! goes to a server that cannot be verified.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::known_hosts::known_host_keys_path;
use russh::keys::{Algorithm, PublicKey, PublicKeyOrCertificate};
use russh::{client, ChannelMsg, Disconnect, Preferred};
use serde_json::{json, Value};

use crate::cred::{fail, within, Cred, Endpoint, Error, Result};
use crate::http::output;

/// command None = sign in only ({"status": "signed in"}); else {"status", "exit_code", "stdout", "stderr"}.
/// `timeout` covers connecting, signing in and the command together.
pub async fn exec(cred: &Cred, ep: &Endpoint, command: Option<&str>, timeout: Duration) -> Result<Value> {
    let home = std::env::var_os("USERPROFILE").ok_or_else(|| fail("USERPROFILE is not set"))?;
    let known: Vec<PublicKey> = known_host_keys_path(&ep.host, ep.port, PathBuf::from(home).join(".ssh/known_hosts"))
        .map_err(fail)?
        .into_iter()
        .map(|(_, k)| k)
        .collect();
    let unknown = || {
        Error::Refused(format!(
            "the host key of {} is not in ~/.ssh/known_hosts; connect once with ssh to check and trust it",
            ep.host
        ))
    };
    if known.is_empty() {
        return Err(unknown());
    }
    // Ask for the key types known_hosts has, so a server with several keys shows one we can check.
    let mut algs = Preferred::default().key.to_vec();
    algs.sort_by_key(|a| !known.iter().any(|k| same_type(&k.algorithm(), a)));
    let config = client::Config {
        preferred: Preferred { key: algs.into(), ..Default::default() },
        ..Default::default()
    };
    within(timeout, "SSH", async {
        let mut session = match client::connect(Arc::new(config), (ep.host.as_str(), ep.port), Known(known)).await {
            Ok(s) => s,
            Err(russh::Error::UnknownKey) => return Err(unknown()),
            Err(russh::Error::KeyChanged { .. }) => {
                return Err(Error::Refused(format!(
                    "the host key of {} changed: it does not match ~/.ssh/known_hosts; check the server, then update the entry with ssh",
                    ep.host
                )))
            }
            Err(e) => return Err(fail(e)),
        };
        let auth = session.authenticate_password(&cred.username, cred.password.as_str()).await.map_err(fail)?;
        if !auth.success() {
            return Err(Error::Failed(format!("Authentication failed for {} on {}", cred.username, ep.host)));
        }
        let result = match command {
            None => Ok(json!({"status": "signed in"})),
            Some(cmd) => run(&session, cmd).await,
        };
        let _ = session.disconnect(Disconnect::ByApplication, "", "en").await;
        result
    })
    .await?
}

async fn run(session: &client::Handle<Known>, command: &str) -> Result<Value> {
    let mut channel = session.channel_open_session().await.map_err(fail)?;
    channel.exec(true, command).await.map_err(fail)?;
    let (mut stdout, mut stderr, mut code) = (Vec::new(), Vec::new(), -1i64);
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => code = exit_status.into(),
            ChannelMsg::Failure => return Err(fail("the server refused to run the command")),
            _ => {}
        }
    }
    Ok(json!({"status": code, "exit_code": code, "stdout": output(&stdout), "stderr": output(&stderr)}))
}

/// Accepts only a key listed in known_hosts; another key of a listed type means it changed.
struct Known(Vec<PublicKey>);

impl client::Handler for Known {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> std::result::Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        if self.0.iter().any(|k| k.key_data() == key.key_data()) {
            Ok(true)
        } else if self.0.iter().any(|k| k.algorithm() == key.algorithm()) {
            Err(russh::Error::KeyChanged { line: 0 })
        } else {
            Ok(false)
        }
    }
}

/// RSA keys are listed as ssh-rsa but negotiated as rsa-sha2-*.
fn same_type(known: &Algorithm, offered: &Algorithm) -> bool {
    matches!((known, offered), (Algorithm::Rsa { .. }, Algorithm::Rsa { .. })) || known == offered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred::tests::PASSWORD;
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    use russh::keys::PrivateKey;
    use russh::server::{self, Auth, Msg, Session};
    use russh::{Channel, ChannelId};

    #[derive(Clone)]
    struct Fake;

    impl server::Handler for Fake {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> std::result::Result<Auth, Self::Error> {
            Ok(if (user, password) == ("svc-user", PASSWORD) { Auth::Accept } else { Auth::reject() })
        }

        async fn channel_open_session(
            &mut self,
            _: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _: &mut Session,
        ) -> std::result::Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(&mut self, ch: ChannelId, cmd: &[u8], s: &mut Session) -> std::result::Result<(), Self::Error> {
            s.channel_success(ch)?;
            s.data(ch, [b"ran ", cmd, b" as ", PASSWORD.as_bytes(), b"\n"].concat())?;
            s.extended_data(ch, 1, &b"warn\n"[..])?;
            s.exit_status_request(ch, 3)?;
            s.eof(ch)?;
            s.close(ch)
        }
    }

    async fn serve(key: PrivateKey) -> u16 {
        let config = Arc::new(server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(running) = server::run_stream(config, sock, Fake).await {
                        let _ = running.await;
                    }
                });
            }
        });
        port
    }

    fn cred(password: &str, port: u16) -> (Cred, Endpoint) {
        let cred = Cred::test("box", &[&format!("ssh://127.0.0.1:{port}")], password, &[]);
        (cred, Endpoint { scheme: "ssh".into(), host: "127.0.0.1".into(), port })
    }

    /// A known_hosts entry hashed the way `ssh-keygen -H` writes it.
    fn hashed(host: &str, key: &PrivateKey) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt = [7u8; 20];
        let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&salt).unwrap();
        mac.update(host.as_bytes());
        let hash = b64.encode(mac.finalize().into_bytes());
        format!("|1|{}|{hash} {}\n", b64.encode(salt), key.public_key().to_openssh().unwrap())
    }

    // One test: the scenarios share the process-wide USERPROFILE.
    #[tokio::test]
    async fn exec_checks_host_key_and_password() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let port = serve(key.clone()).await;
        let home = std::env::temp_dir().join(format!("valet-ssh-test-{}", std::process::id()));
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::env::set_var("USERPROFILE", &home);
        let trust = |line: String| std::fs::write(home.join(".ssh/known_hosts"), line).unwrap();
        let t = Duration::from_secs(10);
        let (good, ep) = cred(PASSWORD, port);
        let (wrong, _) = cred("not-it", port);

        trust(hashed(&format!("[127.0.0.1]:{port}"), &key));
        let r = exec(&good, &ep, Some("uptime"), t).await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            r,
            json!({"status": 3, "exit_code": 3, "stdout": format!("ran uptime as {PASSWORD}\n"), "stderr": "warn\n"})
        );
        assert_eq!(exec(&good, &ep, None, t).await.unwrap(), json!({"status": "signed in"}));
        let e = exec(&wrong, &ep, Some("uptime"), t).await.unwrap_err().to_string();
        assert!(e.contains("Authentication") && !e.contains("not-it"), "{e}");

        trust(format!("[127.0.0.1]:{} {}\n", port + 1, key.public_key().to_openssh().unwrap()));
        assert!(matches!(exec(&good, &ep, Some("x"), t).await, Err(Error::Refused(m)) if m.contains("is not in ~/.ssh/known_hosts")));

        trust(format!("[127.0.0.1]:{port} {}\n", other.public_key().to_openssh().unwrap()));
        assert!(matches!(exec(&good, &ep, Some("x"), t).await, Err(Error::Refused(m)) if m.contains("changed")));

        let _ = std::fs::remove_dir_all(&home);
    }
}
