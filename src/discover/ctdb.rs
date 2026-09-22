use std::time::Duration;

use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct DbRow {
    pub cert_id: i64,
    pub serial: String,
    pub dns_name: Option<String>,
    pub common_name: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_size: Option<i64>,
    pub sig_key_algorithm: Option<String>,
    pub sig_hash_algorithm: Option<String>,
    pub issuer_ca_name: Option<String>,
}

const CT_SQL_TEMPLATE: &str = "
WITH matching AS (
    SELECT c.id, c.issuer_ca_id, c.certificate
    FROM certificate c
    WHERE identities(c.certificate) @@ plainto_tsquery('certwatch', '{domain}')
      AND x509_notAfter(c.certificate) >= now()
)
SELECT
    m.id,
    encode(x509_serialnumber(m.certificate), 'hex'),
    n.name_value,
    x509_commonName(m.certificate),
    x509_notBefore(m.certificate)::text,
    x509_notAfter(m.certificate)::text,
    x509_keyAlgorithm(m.certificate),
    x509_keySize(m.certificate),
    x509_signatureKeyAlgorithm(m.certificate),
    x509_signatureHashAlgorithm(m.certificate),
    ca.name
FROM matching m
LEFT JOIN ca ON ca.id = m.issuer_ca_id
CROSS JOIN LATERAL (
    SELECT encode(raw_value, 'escape') AS name_value, 2 AS src
    FROM x509_altNames_raw(m.certificate)
    WHERE type_num = 2
    UNION ALL
    SELECT x509_commonName(m.certificate), 1
) n
WHERE lower(n.name_value) = lower('{domain}')
   OR lower(n.name_value) LIKE '%.{domain}'";

pub fn ct_sql(domain: &str) -> Result<String, String> {
    let domain = domain.to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return Err(format!("invalid domain: {domain}"));
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!("invalid characters in domain: {domain}"));
    }
    Ok(CT_SQL_TEMPLATE.replace("{domain}", &domain))
}

pub async fn fetch_rows(domain: &str, cfg: &Config) -> Result<Vec<DbRow>, String> {
    let mut last_error = String::from("not attempted");
    for attempt in 1..=cfg.retries {
        eprintln!(
            "CT: querying certwatch DB at {}:{} (attempt {attempt}/{})",
            cfg.db_host, cfg.db_port, cfg.retries
        );
        match attempt_once(domain, cfg).await {
            Ok(rows) => return Ok(rows),
            Err(e) => {
                last_error = e;
                if attempt < cfg.retries {
                    let delay = db_backoff_secs(attempt, cfg.retry_delay);
                    eprintln!(
                        "CT: {last_error}; retrying in {delay}s (attempt {attempt}/{} failed)",
                        cfg.retries
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
            }
        }
    }
    eprintln!(
        "CT: certwatch DB unreachable after {} attempts",
        cfg.retries
    );
    Err(last_error)
}

pub fn db_backoff_secs(attempt: u32, retry_delay: u64) -> u64 {
    retry_delay
        .saturating_mul(1u64 << (attempt + 1).min(6))
        .min(60)
}

async fn attempt_once(domain: &str, cfg: &Config) -> Result<Vec<DbRow>, String> {
    let conninfo = format!(
        "host={} port={} user={} dbname={}",
        cfg.db_host, cfg.db_port, cfg.db_user, cfg.db_name
    );
    let connect = tokio_postgres::connect(&conninfo, NoTls);
    let (client, connection) = tokio::time::timeout(Duration::from_secs(cfg.db_connect_timeout), connect)
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(db_err)?;
    let drive = tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("CT: db connection dropped: {}", db_err(e));
        }
    });

    let rows = query_once(&client, domain, cfg).await;

    drop(client);
    let _ = drive.await;
    rows
}

async fn query_once(client: &Client, domain: &str, cfg: &Config) -> Result<Vec<DbRow>, String> {
    let sql = ct_sql(domain)?;
    let query = client.simple_query(&sql);
    let rows = tokio::time::timeout(Duration::from_secs(cfg.db_query_timeout), query)
        .await
        .map_err(|_| "query timeout".to_string())?
        .map_err(db_err)?;

    rows.iter()
        .filter_map(|m| match m {
            SimpleQueryMessage::Row(r) => Some(r),
            _ => None,
        })
        .map(|r| {
            Ok(DbRow {
                cert_id: r
                    .get(0)
                    .ok_or("missing cert id")?
                    .parse()
                    .map_err(|_| "bad cert id")?,
                serial: r.get(1).ok_or("missing serial")?.to_string(),
                dns_name: r.get(2).map(str::to_string),
                common_name: r.get(3).map(str::to_string),
                not_before: r.get(4).map(str::to_string),
                not_after: r.get(5).map(str::to_string),
                key_algorithm: r.get(6).map(str::to_string),
                key_size: r.get(7).and_then(|v| v.parse().ok()),
                sig_key_algorithm: r.get(8).map(str::to_string),
                sig_hash_algorithm: r.get(9).map(str::to_string),
                issuer_ca_name: r.get(10).map(str::to_string),
            })
        })
        .collect()
}

fn db_err(e: tokio_postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        let mut s = format!("db error {:?}: {}", db.code(), db.message());
        if let Some(detail) = db.detail() {
            s.push_str(&format!(" ({detail})"));
        }
        return s;
    }
    format!("db error: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_backoff_starts_at_2_cubed_and_caps() {
        assert_eq!(db_backoff_secs(1, 2), 8);
        assert_eq!(db_backoff_secs(2, 2), 16);
        assert_eq!(db_backoff_secs(3, 2), 32);
        assert_eq!(db_backoff_secs(4, 2), 60, "capped at 60s");
        assert_eq!(db_backoff_secs(5, 2), 60);
        assert_eq!(db_backoff_secs(1, 120), 60);
    }
}
