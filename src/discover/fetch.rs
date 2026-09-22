use std::collections::BTreeMap;
use std::io::Read;
use std::thread;
use std::time::Duration;

use chrono::Utc;

use crate::config::Config;
use crate::model::{Certificate, Provenance};

use super::cache;
use super::ct;
use super::ctdb;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to retrieve CT data and no usable cache exists")]
    NoCtData,
    #[error("invalid CT data: {0}")]
    CtParse(String),
    #[error("task join failed")]
    Join,
}

pub struct FetchOutcome {
    pub certs: BTreeMap<String, Certificate>,
    pub provenance: Provenance,
    /// "db" or "http" for a fresh snapshot; None when served from cache.
    pub source: Option<&'static str>,
}

pub async fn obtain(domain: &str, cfg: &Config, refresh: bool) -> Result<FetchOutcome, Error> {
    let file = cache::cache_file(domain);

    if !refresh {
        if let Some(snap) = cache::load_snapshot(&file) {
            if let Some(age) = cache::age(&file).filter(|a| *a < cfg.cache_ttl) {
                eprintln!(
                    "CT: using cached snapshot for {domain} ({} min old, source {})",
                    age / 60,
                    snap.source
                );
                return Ok(FetchOutcome {
                    certs: ct::revive_certs(snap.certs, Utc::now()),
                    provenance: Provenance::Cached { age_secs: age },
                    source: None,
                });
            }
        }
    }

    match ctdb::fetch_rows(domain, cfg).await {
        Ok(rows) if !rows.is_empty() => {
            let certs = ct::certificates_from_db(&rows, Utc::now());
            if !certs.is_empty() {
                store(&file, "db", &certs);
                return Ok(FetchOutcome {
                    certs,
                    provenance: Provenance::Fresh,
                    source: Some("db"),
                });
            }
            eprintln!("CT: certwatch DB returned no usable certificates");
        }
        Ok(_) => eprintln!("CT: certwatch DB returned an empty result; not caching"),
        Err(e) => eprintln!("CT: falling back to crt.sh HTTP: {e}"),
    }

    let owned = domain.to_string();
    let cfg_http = cfg.clone();
    let http = tokio::task::spawn_blocking(move || http_obtain(&owned, &cfg_http))
        .await
        .map_err(|_| Error::Join)?;
    match http {
        Ok(body) => {
            let rows =
                ct::parse_rows(&body).map_err(|e| Error::CtParse(e.to_string()))?;
            let certs = ct::certificates(&rows, Utc::now());
            if !certs.is_empty() {
                store(&file, "http", &certs);
                return Ok(FetchOutcome {
                    certs,
                    provenance: Provenance::Fresh,
                    source: Some("http"),
                });
            }
            eprintln!("CT: crt.sh returned no usable certificates");
        }
        Err(e) => eprintln!("CT: {e}"),
    }

    if let Some(snap) = cache::load_snapshot(&file) {
        eprintln!("WARNING: CT sources unavailable; using stale cached snapshot");
        return Ok(FetchOutcome {
            certs: ct::revive_certs(snap.certs, Utc::now()),
            provenance: Provenance::Stale {
                age_secs: cache::age(&file),
            },
            source: None,
        });
    }
    Err(Error::NoCtData)
}

/// Failure of a single crt.sh request.
enum FetchFailure {
    /// HTTP status response, with Retry-After seconds when the server sent one.
    Status(u16, Option<u64>),
    /// Transport or read failure.
    Other(String),
}

/// Exponential backoff: retry_delay * 2^(attempt-1), capped at 60s.
pub fn backoff_secs(attempt: u32, retry_delay: u64) -> u64 {
    retry_delay
        .saturating_mul(1u64 << (attempt - 1).min(6))
        .min(60)
}

fn http_obtain(domain: &str, cfg: &Config) -> Result<String, Error> {
    for attempt in 1..=cfg.retries {
        eprintln!(
            "CT: querying crt.sh for *.{domain} (attempt {attempt}/{})",
            cfg.retries
        );
        match fetch_once(domain, cfg) {
            Ok(body) => match ct::parse_rows(&body) {
                Ok(rows) if !rows.is_empty() => return Ok(body),
                Ok(_) => eprintln!("CT: crt.sh returned an empty result; not caching"),
                Err(_) => eprintln!("CT: crt.sh returned invalid JSON"),
            },
            Err(FetchFailure::Status(code, retry_after)) => {
                let base = backoff_secs(attempt, cfg.retry_delay);
                let (why, delay) = match code {
                    // Rate limited: honor Retry-After when sane, otherwise back
                    // off twice as hard as for plain server errors.
                    429 => (
                        "rate limited",
                        retry_after.unwrap_or(base * 2).min(300),
                    ),
                    502 | 503 => ("server error", base),
                    _ => ("HTTP error", base),
                };
                if attempt < cfg.retries {
                    eprintln!(
                        "CT: {why} (HTTP {code}); retrying in {delay}s (attempt {attempt}/{} failed)",
                        cfg.retries
                    );
                    thread::sleep(Duration::from_secs(delay));
                } else {
                    eprintln!("CT: {why} (HTTP {code}); giving up after {} attempts", cfg.retries);
                }
            }
            Err(FetchFailure::Other(e)) => {
                eprintln!("CT: {e}");
                if attempt < cfg.retries {
                    let delay = backoff_secs(attempt, cfg.retry_delay);
                    eprintln!(
                        "CT: retrying in {delay}s (attempt {}/{} failed)",
                        attempt, cfg.retries
                    );
                    thread::sleep(Duration::from_secs(delay));
                }
            }
        }
    }
    Err(Error::NoCtData)
}

fn fetch_once(domain: &str, cfg: &Config) -> Result<String, FetchFailure> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(cfg.connect_timeout))
        .timeout(Duration::from_secs(cfg.max_time))
        .build();
    let url = format!("https://crt.sh/?q=%25.{domain}&exclude=expired&output=json");
    let response = match agent.get(&url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, resp)) => {
            let retry_after = resp
                .header("retry-after")
                .and_then(|v| v.trim().parse::<u64>().ok());
            return Err(FetchFailure::Status(code, retry_after));
        }
        Err(ureq::Error::Transport(t)) => {
            return Err(FetchFailure::Other(format!("crt.sh request failed: {t}")))
        }
    };
    let mut reader = response.into_reader().take(256 * 1024 * 1024);
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .map_err(|e| FetchFailure::Other(format!("crt.sh read failed: {e}")))?;
    Ok(body)
}

fn store(file: &std::path::Path, source: &str, certs: &BTreeMap<String, Certificate>) {
    let snapshot = cache::Snapshot {
        version: cache::SNAPSHOT_VERSION,
        source: source.to_string(),
        fetched_at: Utc::now().to_rfc3339(),
        certs: certs.values().cloned().collect(),
    };
    match cache::store_snapshot(file, &snapshot) {
        Ok(()) => eprintln!(
            "CT: snapshot cached (source {source}): {}",
            file.display()
        ),
        Err(e) => eprintln!("CT: caching failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_secs(1, 2), 2);
        assert_eq!(backoff_secs(2, 2), 4);
        assert_eq!(backoff_secs(3, 2), 8);
        assert_eq!(backoff_secs(4, 2), 16);
        assert_eq!(backoff_secs(6, 2), 60, "capped at 60s");
        assert_eq!(backoff_secs(20, 2), 60);
        assert_eq!(backoff_secs(1, 120), 60, "capped at 60s");
    }
}
