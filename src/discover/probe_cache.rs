use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{Endpoint, PortScan};

use super::cache;

pub const SNAPSHOT_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub fetched_at: DateTime<Utc>,
    pub probes: BTreeMap<String, Endpoint>,
    #[serde(default)]
    pub ports: BTreeMap<String, BTreeMap<u16, PortScan>>,
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

pub fn load(domain: &str) -> Option<Snapshot> {
    cache::migrate_legacy_file(&cache_dir(), domain);
    let file = cache::latest_file(&cache_dir(), domain)?;
    let body = fs::read_to_string(&file).ok()?;
    let snap: Snapshot = serde_json::from_str(&body).ok()?;
    if snap.version != SNAPSHOT_VERSION {
        return None;
    }
    match cache::age(&file) {
        Some(age) => eprintln!(
            "probes: loading snapshot {} ({} min old)",
            file.display(),
            age / 60
        ),
        None => eprintln!("probes: loading snapshot {}", file.display()),
    }
    Some(snap)
}

pub fn store(
    domain: &str,
    probes: &BTreeMap<String, Endpoint>,
    ports: &BTreeMap<String, BTreeMap<u16, PortScan>>,
) {
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        fetched_at: Utc::now(),
        probes: probes.clone(),
        ports: ports.clone(),
    };
    let Ok(body) = serde_json::to_string_pretty(&snapshot) else {
        eprintln!("probes: caching failed: serialization error");
        return;
    };
    cache::migrate_legacy_file(&cache_dir(), domain);
    match cache::domain_store(&cache_dir(), domain, &body) {
        Ok(path) => eprintln!("probes: snapshot cached: {}", path.display()),
        Err(e) => eprintln!("probes: caching failed: {e}"),
    }
}

pub fn is_fresh(endpoint: &Endpoint, ttl: u64, now: DateTime<Utc>) -> bool {
    endpoint
        .observed_at
        .map(|t| ((now - t).num_seconds().max(0) as u64) <= ttl)
        .unwrap_or(false)
}

pub fn scan_fresh(scan: &PortScan, ttl: u64, now: DateTime<Utc>) -> bool {
    is_fresh_time(scan.observed_at, ttl, now)
}

fn is_fresh_time(t: Option<DateTime<Utc>>, ttl: u64, now: DateTime<Utc>) -> bool {
    t.map(|t| ((now - t).num_seconds().max(0) as u64) <= ttl)
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
        probes.insert("vpn.example.com".to_string(), timeout_endpoint());

        let mut ports = BTreeMap::new();
        let mut scans = BTreeMap::new();
        scans.insert(
            465u16,
            crate::model::PortScan {
                port: 465,
                state: crate::model::ScanState::Open,
                served: None,
                negotiated: None,
                observed_at: Some(Utc::now()),
            },
        );
        ports.insert("mx1.example.com".to_string(), scans);

        store("roundtrip.example.com", &probes, &ports);
        let loaded = load("roundtrip.example.com").expect("snapshot loads");
        let ep = loaded.probes.get("vpn.example.com").unwrap();
        assert_eq!(ep.status, ProbeStatus::Timeout { secs: 8 });
        assert!(is_fresh(ep, 86_400, Utc::now()));
        let scans = loaded.ports.get("mx1.example.com").unwrap();
        let scan = scans.get(&465).unwrap();
        assert_eq!(scan.state, crate::model::ScanState::Open);
        assert!(scan_fresh(scan, 86_400, Utc::now()));

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
