use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::ChainEntry;

use super::cache;

pub const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub fetched_at: DateTime<Utc>,
    pub chains: BTreeMap<u64, Vec<ChainEntry>>,
}

fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CHAIN_CACHE_DIR") {
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
        .join("chain")
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
            "CT: loading chain snapshot {} ({domain}, {} min old)",
            file.display(),
            age / 60
        ),
        None => eprintln!("CT: loading chain snapshot {} ({domain})", file.display()),
    }
    Some(snap)
}

pub fn age(domain: &str) -> Option<u64> {
    cache::age(&cache::latest_file(&cache_dir(), domain)?)
}

pub fn store(domain: &str, chains: &BTreeMap<u64, Vec<ChainEntry>>) {
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        fetched_at: Utc::now(),
        chains: chains.clone(),
    };
    let Ok(body) = serde_json::to_string_pretty(&snapshot) else {
        eprintln!("CT: chain caching failed: serialization error");
        return;
    };
    cache::migrate_legacy_file(&cache_dir(), domain);
    match cache::domain_store(&cache_dir(), domain, &body) {
        Ok(path) => eprintln!("CT: chain snapshot cached: {}", path.display()),
        Err(e) => eprintln!("CT: chain caching failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(leaf: u64, depth: u32) -> (u64, ChainEntry) {
        (
            leaf,
            ChainEntry {
                depth,
                certificate_id: leaf * 10 + depth as u64,
                common_name: Some(format!("ca{depth}")),
                ski: Some("aa".to_string()),
                aki: None,
                not_before: None,
                not_after: None,
                key_algorithm: Some("RSA".to_string()),
                key_size: Some(2048),
                signature_key_algorithm: Some("RSA".to_string()),
                signature_hash_algorithm: Some("SHA-256".to_string()),
                issuer_ca_name: None,
            },
        )
    }

    #[test]
    fn snapshot_roundtrip() {
        let dir = std::env::temp_dir().join("pq-chain-cache-test");
        fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("CHAIN_CACHE_DIR", &dir) };

        let mut chains = BTreeMap::new();
        let (leaf, e0) = entry(9612296601, 0);
        let (_, e1) = entry(9612296601, 1);
        chains.insert(leaf, vec![e0, e1]);

        store("roundtrip.example.pl", &chains);
        let loaded = load("roundtrip.example.pl").expect("snapshot loads");
        let entries = loaded.chains.get(&leaf).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].depth, 1);
        assert_eq!(entries[1].common_name.as_deref(), Some("ca1"));

        fs::remove_dir_all(&dir).unwrap();
        unsafe { std::env::remove_var("CHAIN_CACHE_DIR") };
    }
}
