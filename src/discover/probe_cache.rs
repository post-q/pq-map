use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::Endpoint;

use super::cache;

pub const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub fetched_at: DateTime<Utc>,
    pub probes: BTreeMap<String, Endpoint>,
}

fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PROBE_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    let base = std::env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cache"))
        });
    base.unwrap_or_else(std::env::temp_dir)
        .join("pq-map")
        .join("probe")
}

fn cache_file(domain: &str) -> PathBuf {
    cache_dir().join(format!("{domain}.json"))
}

pub fn load(domain: &str) -> Option<Snapshot> {
    let body = fs::read_to_string(cache_file(domain)).ok()?;
    let snap: Snapshot = serde_json::from_str(&body).ok()?;
    (snap.version == SNAPSHOT_VERSION).then_some(snap)
}

pub fn store(domain: &str, probes: &BTreeMap<String, Endpoint>) {
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        fetched_at: Utc::now(),
        probes: probes.clone(),
    };
    let Ok(body) = serde_json::to_string_pretty(&snapshot) else {
        eprintln!("probes: caching failed: serialization error");
        return;
    };
    let file = cache_file(domain);
    if let Some(dir) = file.parent() {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("probes: caching failed: {e}");
            return;
        }
    }
    match cache::store(&file, &body) {
        Ok(()) => eprintln!("probes: snapshot cached: {}", file.display()),
        Err(e) => eprintln!("probes: caching failed: {e}"),
    }
}

pub fn is_fresh(endpoint: &Endpoint, ttl: u64, now: DateTime<Utc>) -> bool {
    endpoint
        .observed_at
        .map(|t| ((now - t).num_seconds().max(0) as u64) <= ttl)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProbeStatus;

    fn timeout_endpoint() -> Endpoint {
        let mut ep = Endpoint::failed(ProbeStatus::Timeout { secs: 8 });
        ep.observed_at = Some(Utc::now());
        ep
    }

    #[test]
    fn snapshot_roundtrip_keeps_failure_endpoints() {
        let dir = std::env::temp_dir().join("pq-scope-probe-cache-test");
        fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("PROBE_CACHE_DIR", &dir) };

        let mut probes = BTreeMap::new();
        probes.insert("vpn.nbp.pl".to_string(), timeout_endpoint());

        store("roundtrip.nbp.pl", &probes);
        let loaded = load("roundtrip.nbp.pl").expect("snapshot loads");
        let ep = loaded.probes.get("vpn.nbp.pl").unwrap();
        assert_eq!(ep.status, ProbeStatus::Timeout { secs: 8 });
        assert!(is_fresh(ep, 86_400, Utc::now()));

        fs::remove_dir_all(&dir).unwrap();
        unsafe { std::env::remove_var("PROBE_CACHE_DIR") };
    }

    #[test]
    fn is_fresh_respects_ttl_and_missing_time() {
        let now = Utc::now();
        let mut ep = timeout_endpoint();
        ep.observed_at = Some(now - chrono::Duration::hours(23));
        assert!(is_fresh(&ep, 86_400, now));

        ep.observed_at = Some(now - chrono::Duration::hours(25));
        assert!(!is_fresh(&ep, 86_400, now));

        ep.observed_at = None;
        assert!(
            !is_fresh(&ep, 86_400, now),
            "synthesized endpoints never reusable"
        );
    }
}
