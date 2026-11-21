//! sql_query (owner: servers). Spec: valet/broker.py `sql_run`.
//! SQL Server over TDS. DOMAIN\user items use Windows auth (NTLM) with the item's password; others
//! are SQL logins. `broker_trust_cert=yes` accepts a self-signed certificate.

use std::fmt::Display;
use std::time::Duration;

use futures_util::TryStreamExt;
use serde_json::{json, Value};
use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime};
use tiberius::{AuthMethod, Client, ColumnData, Command, CommandItem, Config, EncryptionLevel, FromSql};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use crate::cred::{fail, Cred, Endpoint, Result};
use crate::ssh::within;

/// Returns {"status": "ok", "results": [{"columns", "rows", "truncated"?} | {"rows_affected"}]}.
pub async fn query(
    cred: &Cred,
    ep: &Endpoint,
    query: &str,
    database: Option<&str>,
    max_rows: usize,
    timeout: Duration,
) -> Result<Value> {
    let config = config(cred, ep, database, timeout);
    let mut client = within(timeout, "SQL Server sign-in", async {
        let tcp = TcpStream::connect((ep.host.as_str(), ep.port)).await?;
        tcp.set_nodelay(true)?;
        anyhow::Ok(Client::connect(config, tcp.compat_write()).await?)
    })
    .await??;
    let results = within(timeout, "SQL query", run(&mut client, query, max_rows)).await?.map_err(fail)?;
    let _ = client.close().await;
    Ok(json!({"status": "ok", "results": results}))
}

fn config(cred: &Cred, ep: &Endpoint, database: Option<&str>, timeout: Duration) -> Config {
    let mut c = Config::new();
    c.host(&ep.host);
    c.port(ep.port);
    c.database(database.unwrap_or("master"));
    c.encryption(EncryptionLevel::Required);
    if cred.flag("broker_trust_cert") {
        c.trust_cert();
    }
    c.authentication(if cred.username.contains('\\') {
        AuthMethod::windows(&cred.username, cred.password.as_str())
    } else {
        AuthMethod::sql_server(&cred.username, cred.password.as_str())
    });
    c.handshake_timeout(Some(timeout));
    c.command_timeout(Some(timeout));
    c
}

/// Runs the batch through sp_executesql: unlike a plain batch, its stream reports row counts too.
async fn run(client: &mut Client<tokio_util::compat::Compat<TcpStream>>, query: &str, max_rows: usize) -> tiberius::Result<Vec<Value>> {
    let mut cmd = Command::new("sp_executesql");
    cmd.bind_param("@stmt", query);
    let mut stream = cmd.exec(client).await?;
    let mut sets: Vec<Value> = Vec::new();
    let mut in_set = false; // the next row count is the result set's own
    while let Some(item) = stream.try_next().await? {
        match item {
            CommandItem::Metadata(m) => {
                let columns: Vec<&str> = m.columns().iter().map(|c| c.name()).collect();
                sets.push(json!({"columns": columns, "rows": []}));
                in_set = true;
            }
            CommandItem::Row(row) => {
                let set = sets.last_mut().expect("rows follow metadata");
                let rows = set["rows"].as_array_mut().expect("rows array");
                if rows.len() < max_rows {
                    rows.push(row.into_iter().map(|v| to_json(&v)).collect());
                } else {
                    set["truncated"] = format!("only the first {max_rows} rows").into();
                }
            }
            CommandItem::RowsAffected(_) if in_set => in_set = false,
            CommandItem::RowsAffected(n) => sets.push(json!({"rows_affected": n})),
            _ => {}
        }
    }
    Ok(sets)
}

fn to_json(v: &ColumnData<'static>) -> Value {
    fn text<T: Display>(r: tiberius::Result<Option<T>>) -> Value {
        r.ok().flatten().map_or(Value::Null, |t| t.to_string().into())
    }
    match v {
        ColumnData::U8(x) => json!(x),
        ColumnData::I16(x) => json!(x),
        ColumnData::I32(x) => json!(x),
        ColumnData::I64(x) => json!(x),
        ColumnData::F32(x) => json!(x),
        ColumnData::F64(x) => json!(x),
        ColumnData::Bit(x) => json!(x),
        ColumnData::String(x) => json!(x),
        ColumnData::Guid(x) => json!(x.map(|g| g.to_string())),
        ColumnData::Binary(x) => json!(x.as_ref().map(|b| b.iter().map(|b| format!("{b:02x}")).collect::<String>())),
        ColumnData::Numeric(x) => json!(x.map(|n| n.to_string())),
        ColumnData::Xml(x) => json!(x.as_ref().map(|x| x.to_string())),
        ColumnData::DateTime(_) | ColumnData::SmallDateTime(_) | ColumnData::DateTime2(_) => text(NaiveDateTime::from_sql(v)),
        ColumnData::Date(_) => text(NaiveDate::from_sql(v)),
        ColumnData::Time(_) => text(NaiveTime::from_sql(v)),
        ColumnData::DateTimeOffset(_) => text(DateTime::<FixedOffset>::from_sql(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use tiberius::numeric::Numeric;
    use tiberius::{IntoSql, Uuid};
    use zeroize::Zeroizing;

    fn cred(username: &str, fields: &[(&str, &str)]) -> Cred {
        Cred {
            id: "1".into(),
            name: "db".into(),
            username: username.into(),
            password: Zeroizing::new("s3cret-test-pass".into()),
            totp: Zeroizing::new(String::new()),
            uris: vec!["mssql://db.example.test:1444".into()],
            fields: fields.iter().map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string()))).collect(),
        }
    }

    #[test]
    fn config_picks_auth_and_trust() {
        let ep = Endpoint { scheme: "mssql".into(), host: "db.example.test".into(), port: 1444 };
        let t = Duration::from_secs(5);
        let win = config(&cred("CORP\\svc-user", &[]), &ep, None, t);
        let sql = config(&cred("app", &[("broker_trust_cert", "yes")]), &ep, Some("crm"), t);
        assert_eq!(win.get_addr(), "db.example.test:1444");
        let (win, sql) = (format!("{win:?}"), format!("{sql:?}"));
        assert!(win.contains("Windows(") && win.contains("\"svc-user\"") && win.contains("\"CORP\""), "{win}");
        assert!(win.contains("\"master\"") && win.contains("Required") && win.contains("bypass: false"), "{win}");
        assert!(sql.contains("SqlServer(") && sql.contains("\"crm\"") && sql.contains("bypass: true"), "{sql}");
        assert!(!win.contains("s3cret") && !sql.contains("s3cret"));
    }

    #[test]
    fn values_become_json() {
        let when = NaiveDate::from_ymd_opt(2024, 1, 2).unwrap().and_hms_milli_opt(3, 4, 5, 600).unwrap();
        let cases = [
            (ColumnData::I32(Some(5)), json!(5)),
            (ColumnData::I64(None), Value::Null),
            (ColumnData::F64(Some(1.5)), json!(1.5)),
            (ColumnData::Bit(Some(true)), json!(true)),
            (ColumnData::String(Some(Cow::Borrowed("x"))), json!("x")),
            (ColumnData::Guid(Some(Uuid::nil())), json!("00000000-0000-0000-0000-000000000000")),
            (ColumnData::Binary(Some(Cow::Borrowed(&[0xde, 0xad][..]))), json!("dead")),
            (ColumnData::Numeric(Some(Numeric::new_with_scale(12345, 2))), json!("123.45")),
            (when.into_sql(), json!("2024-01-02 03:04:05.600")),
            (when.date().into_sql(), json!("2024-01-02")),
            (ColumnData::DateTime2(None), Value::Null),
        ];
        for (data, want) in cases {
            assert_eq!(to_json(&data), want, "{data:?}");
        }
    }
}
