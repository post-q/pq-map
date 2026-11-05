use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
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

/// UTC timestamp used in snapshot file names: `YYYYMMDDTHHMMSS.NNNNNNNNNZ`.
/// Fixed width, so lexicographic order matches chronological order.
pub fn timestamp_of(t: SystemTime) -> String {
    let dt: DateTime<Utc> = t.into();
    format!(
        "{}.{:09}Z",
        dt.format("%Y%m%dT%H%M%S"),
        dt.timestamp_subsec_nanos()
    )
}

pub fn timestamp_now() -> String {
    timestamp_of(SystemTime::now())
}

/// True when a file stem follows the `YYYYMMDDTHHMMSS.NNNNNNNNNZ` layout.
fn is_timestamp_name(stem: &str) -> bool {
    let b = stem.as_bytes();
    b.len() == 26
        && b[8] == b'T'
        && b[15] == b'.'
        && b[25] == b'Z'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 15 | 25) || c.is_ascii_digit())
}

/// Path of the newest snapshot file for a domain, or None when none exists.
///
/// Snapshots are append-only: one directory per domain, one new timestamped
/// file per store. Existing snapshot files are never rewritten or removed.
pub fn latest_file(base: &Path, domain: &str) -> Option<PathBuf> {
    let mut best: Option<(String, PathBuf)> = None;
    for entry in fs::read_dir(base.join(domain)).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") || !path.is_file() {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !is_timestamp_name(stem) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(newest, _)| stem > newest.as_str())
        {
            best = Some((stem.to_string(), path));
        }
    }
    best.map(|(_, path)| path)
}

/// Move a legacy flat `{domain}.json` cache file into the append-only layout
/// as `{domain}/{timestamp}.json`. The file content is never touched; only
/// its path changes. The snapshot timestamp comes from the file's mtime, so
/// freshness is preserved. Idempotent: a no-op when no legacy file exists.
pub fn migrate_legacy_file(base: &Path, domain: &str) {
    let legacy = base.join(format!("{domain}.json"));
    if !legacy.exists() {
        return;
    }
    let ts = fs::metadata(&legacy)
        .and_then(|m| m.modified())
        .map(timestamp_of)
        .unwrap_or_else(|_| timestamp_now());
    let dir = base.join(domain);
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("cache: migration failed: {e}");
        return;
    }
    let target = dir.join(format!("{ts}.json"));
    if target.exists() {
        eprintln!(
            "cache: leaving legacy snapshot in place: {}",
            legacy.display()
        );
        return;
    }
    match fs::rename(&legacy, &target) {
        Ok(()) => eprintln!("cache: migrated snapshot to {}", target.display()),
        Err(e) => eprintln!("cache: migration failed for {}: {e}", legacy.display()),
    }
}

/// Write a new snapshot file into `base/{domain}/`; never touches existing ones.
pub fn domain_store(base: &Path, domain: &str, body: &str) -> std::io::Result<PathBuf> {
    let dir = base.join(domain);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", timestamp_now()));
    store(&path, body)?;
    Ok(path)
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

/// Serialize a CT snapshot into a fresh timestamped file. Any previous
/// snapshots remain on disk untouched.
pub fn store_snapshot_for(domain: &str, snapshot: &Snapshot) -> std::io::Result<PathBuf> {
    migrate_legacy_file(&cache_dir(), domain);
    let body = serde_json::to_string_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    domain_store(&cache_dir(), domain, &body)
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
        unsafe { std::env::set_var("CT_CACHE_DIR", &dir) };
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
        let path = store_snapshot_for("roundtrip.example.com", &snapshot).unwrap();
        let loaded = load_snapshot(&path).unwrap();
        assert_eq!(loaded.source, "db");
        assert_eq!(
            loaded.certs[0].cert_signature.as_deref(),
            Some("RSA-SHA256")
        );
        assert_eq!(loaded.certs[0].ct_ids, vec![7]);
        fs::remove_dir_all(&dir).unwrap();
        unsafe { std::env::remove_var("CT_CACHE_DIR") };
    }

    #[test]
    fn latest_file_prefers_newest_timestamp() {
        let dir = std::env::temp_dir().join("pq-scope-cache-latest-test");
        let domain = "latest.example.com";
        let dom_dir = dir.join(domain);
        fs::create_dir_all(&dom_dir).unwrap();
        fs::write(dom_dir.join("20260101T000000.000000000Z.json"), "old").unwrap();
        fs::write(dom_dir.join("20260102T000000.000000000Z.json"), "new").unwrap();
        // Noise that must be ignored: partial writes and non-snapshot files.
        fs::write(
            dom_dir.join("20260103T000000.000000000Z.json.tmp.42"),
            "junk",
        )
        .unwrap();
        fs::write(dom_dir.join("notes.txt"), "x").unwrap();
        let latest = latest_file(&dir, domain).unwrap();
        assert_eq!(
            latest.file_name().unwrap(),
            "20260102T000000.000000000Z.json"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn migrate_legacy_moves_flat_file_into_domain_dir() {
        let dir = std::env::temp_dir().join("pq-scope-cache-migrate-test");
        fs::create_dir_all(&dir).unwrap();
        let domain = "migrate.example.com";
        let legacy = dir.join(format!("{domain}.json"));
        fs::write(&legacy, "{}").unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = File::options().write(true).open(&legacy).unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(old)
                .set_modified(old),
        )
        .unwrap();

        migrate_legacy_file(&dir, domain);
        assert!(!legacy.exists(), "legacy file moved, not copied");
        let target = latest_file(&dir, domain).expect("migrated snapshot found");
        assert_eq!(fs::read_to_string(&target).unwrap(), "{}");
        // mtime preserved so freshness survives the rename.
        assert!(age(&target).unwrap() > 10);

        // Idempotent: no legacy file left, second run is a no-op.
        migrate_legacy_file(&dir, domain);
        assert_eq!(
            latest_file(&dir, domain).unwrap(),
            target,
            "no new snapshot created"
        );
        fs::remove_dir_all(&dir).unwrap();
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
