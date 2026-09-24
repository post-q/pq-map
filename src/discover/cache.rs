use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::model::Certificate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub source: String,
    pub fetched_at: String,
    pub certs: Vec<Certificate>,
}

pub const SNAPSHOT_VERSION: u32 = 2;

pub fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CT_CACHE_DIR") {
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
        .join("ct")
}

pub fn cache_file(domain: &str) -> PathBuf {
    cache_dir().join(format!("{domain}.json"))
}

pub fn age(path: &Path) -> Option<u64> {
    let mtime = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now()
        .duration_since(mtime)
        .ok()
        .map(|d| d.as_secs())
}

pub fn is_valid(path: &Path) -> bool {
    load_snapshot(path).is_some()
}

pub fn is_fresh(path: &Path, ttl: u64) -> bool {
    match age(path) {
        Some(a) if a < ttl => is_valid(path),
        _ => false,
    }
}

pub fn load(path: &Path) -> std::io::Result<String> {
    fs::read_to_string(path)
}

pub fn load_snapshot(path: &Path) -> Option<Snapshot> {
    let body = fs::read_to_string(path).ok()?;
    let snap: Snapshot = serde_json::from_str(&body).ok()?;
    (snap.version == SNAPSHOT_VERSION).then_some(snap)
}

pub fn store_snapshot(path: &Path, snapshot: &Snapshot) -> std::io::Result<()> {
    let body = serde_json::to_string_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    store(path, &body)
}

pub fn store(path: &Path, body: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, body)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::time::{Duration, UNIX_EPOCH};

    fn snap_body() -> String {
        serde_json::to_string(&Snapshot {
            version: SNAPSHOT_VERSION,
            source: "db".to_string(),
            fetched_at: "2026-09-22T00:00:00Z".to_string(),
            certs: Vec::new(),
        })
        .unwrap()
    }

    fn write(path: &Path, body: &str, mtime: SystemTime) {
        fs::write(path, body).unwrap();
        let f = File::options().write(true).open(path).unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(mtime)
                .set_modified(mtime),
        )
        .unwrap();
    }

    #[test]
    fn freshness_follows_ttl_and_validity() {
        let dir = std::env::temp_dir().join("pq-scope-cache-test");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("fresh.example.com.json");

        write(&file, &snap_body(), SystemTime::now());
        assert!(is_valid(&file));
        assert!(is_fresh(&file, 60));

        write(&file, &snap_body(), UNIX_EPOCH);
        assert!(is_valid(&file));
        assert!(!is_fresh(&file, 60));

        write(&file, "not json", SystemTime::now());
        assert!(!is_valid(&file));
        assert!(!is_fresh(&file, 60));

        write(&file, "[]", SystemTime::now());
        assert!(!is_valid(&file));

        fs::remove_file(&file).unwrap();

        let empty = dir.join("empty.example.com.json");
        write(&empty, "", SystemTime::now());
        assert!(!is_valid(&empty));
        fs::remove_file(&empty).unwrap();
    }

    #[test]
    fn snapshot_roundtrip_preserves_facts() {
        let dir = std::env::temp_dir().join("pq-scope-cache-snap-test");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("roundtrip.example.com.json");
        let mut cert = crate::model::Certificate {
            serial: "aa11".to_string(),
            in_ct: true,
            served_live: false,
            currently_valid: true,
            ct_ids: vec![7],
            common_name: Some("www.example.com".to_string()),
            identities: vec!["example.com".to_string(), "www.example.com".to_string()],
            not_before: None,
            not_after: None,
            pubkey_alg: None,
            sig_alg: None,
            issuer: Some("CN=Test CA".to_string()),
            key_algorithm: Some("RSA".to_string()),
            key_size: Some(2048),
            sig_key_algorithm: Some("RSA".to_string()),
            sig_hash_algorithm: Some("SHA-256".to_string()),
            cert_signature: Some("RSA-SHA256".to_string()),
            chain: Vec::new(),
        };
        cert.not_before = Some(chrono::Utc::now() - chrono::Duration::days(1));
        cert.not_after = Some(chrono::Utc::now() + chrono::Duration::days(1));
        let snapshot = Snapshot {
            version: SNAPSHOT_VERSION,
            source: "db".to_string(),
            fetched_at: "2026-09-22T00:00:00Z".to_string(),
            certs: vec![cert],
        };
        store_snapshot(&file, &snapshot).unwrap();
        let loaded = load_snapshot(&file).unwrap();
        assert_eq!(loaded.source, "db");
        assert_eq!(
            loaded.certs[0].cert_signature.as_deref(),
            Some("RSA-SHA256")
        );
        assert_eq!(loaded.certs[0].ct_ids, vec![7]);
        fs::remove_file(&file).unwrap();
    }

    #[test]
    fn store_is_atomic_rename() {
        let dir = std::env::temp_dir().join("pq-scope-cache-store-test");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("example.com.json");
        store(&file, "[]").unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "[]");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp."))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_file(&file).unwrap();
    }

    #[test]
    fn age_of_missing_file_is_none() {
        assert!(age(Path::new("/nonexistent/x.json")).is_none());
    }

    #[test]
    fn age_rejects_future_mtime() {
        let dir = std::env::temp_dir().join("pq-scope-cache-age-test");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("future.example.com.json");
        let future = SystemTime::now()
            .checked_add(Duration::from_secs(40 * 365 * 86400))
            .unwrap();
        write(&file, "[]", future);
        assert!(age(&file).is_none());
        fs::remove_file(&file).unwrap();
    }
}
