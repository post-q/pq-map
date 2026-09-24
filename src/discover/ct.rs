use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::model::{CertRef, Certificate, MatchKind, cert_signature_from_db};

use super::ctdb::DbRow;

#[derive(Debug, Deserialize)]
pub struct CtRow {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(default)]
    pub common_name: Option<String>,
    #[serde(default)]
    pub name_value: Option<String>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    #[serde(default)]
    pub serial_number: Option<String>,
}

pub fn parse_rows(body: &str) -> Result<Vec<CtRow>, serde_json::Error> {
    serde_json::from_str(body)
}

/// crt.sh timestamps carry no zone ("2014-04-23T12:16:09"); RFC 3339 requires one.
/// jq's fromdateiso8601 also accepts compact offsets (+0200); chrono needs +02:00.
pub fn ctdate(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let with_t = raw.replace(' ', "T");
    let with_zone = if has_explicit_zone(&with_t) {
        normalize_zone(with_t)
    } else {
        format!("{with_t}Z")
    };
    DateTime::parse_from_rfc3339(&with_zone)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// +HHMM → +HH:MM so that RFC 3339 parsing succeeds.
fn normalize_zone(s: String) -> String {
    let b = s.as_bytes();
    if b.len() >= 5 {
        let tail = &b[b.len() - 5..];
        if (tail[0] == b'+' || tail[0] == b'-') && tail[1..].iter().all(u8::is_ascii_digit) {
            return format!(
                "{}{}:{}",
                &s[..s.len() - 5],
                &s[s.len() - 5..s.len() - 2],
                &s[s.len() - 2..]
            );
        }
    }
    s
}

fn has_explicit_zone(s: &str) -> bool {
    let b = s.as_bytes();
    if b.ends_with(b"Z") || b.ends_with(b"z") {
        return true;
    }
    // +HH:MM (6 bytes) or +HHMM (5 bytes)
    let check = |len: usize| -> bool {
        if b.len() < len {
            return false;
        }
        let t = &b[b.len() - len..];
        if t[0] != b'+' && t[0] != b'-' {
            return false;
        }
        let rest = &t[1..];
        match len {
            6 => {
                rest[0].is_ascii_digit()
                    && rest[1].is_ascii_digit()
                    && rest[2] == b':'
                    && rest[3].is_ascii_digit()
                    && rest[4].is_ascii_digit()
            }
            5 => rest.iter().all(u8::is_ascii_digit),
            _ => false,
        }
    };
    check(6) || check(5)
}

pub fn names(name_value: &str) -> Vec<String> {
    let mut out: Vec<String> = name_value
        .split('\n')
        .map(|n| n.trim().to_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn is_wildcard(name: &str) -> bool {
    name.starts_with("*.")
}

/// RFC 6125 single-label wildcard: `*.base` covers `x.base` only - not `a.b.base`, not `base`.
pub fn coverage(identities: &[String], host: &str) -> Option<MatchKind> {
    if identities.iter().any(|n| n == host) {
        return Some(MatchKind::Exact);
    }
    for n in identities {
        if let Some(base) = n.strip_prefix("*.") {
            let host_labels = host.split('.').count();
            let base_labels = base.split('.').count();
            if host_labels == base_labels + 1 && host.ends_with(&format!(".{base}")) {
                return Some(MatchKind::Wildcard);
            }
        }
    }
    None
}

fn epoch(dt: Option<DateTime<Utc>>) -> i64 {
    dt.map_or(0, |d| d.timestamp())
}

/// Missing dates behave like epoch 0 (crt.sh jq semantics): no `not_after` means not valid.
pub fn currently_valid(
    nb: Option<DateTime<Utc>>,
    na: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    let now = now.timestamp();
    epoch(nb) <= now && epoch(na) >= now
}

pub fn future_valid(nb: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    epoch(nb) > now.timestamp()
}

pub fn serial_norm(raw: &str) -> String {
    let hex: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let stripped = hex.trim_start_matches('0');
    if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped.to_string()
    }
}

pub fn certificates(rows: &[CtRow], now: DateTime<Utc>) -> BTreeMap<String, Certificate> {
    let mut certs: BTreeMap<String, Certificate> = BTreeMap::new();
    for row in rows {
        let nb = row.not_before.as_deref().and_then(ctdate);
        let na = row.not_after.as_deref().and_then(ctdate);
        let valid = currently_valid(nb, na, now);
        let future = future_valid(nb, now);
        if !valid && !future {
            continue;
        }
        let Some(serial_raw) = &row.serial_number else {
            continue;
        };
        let serial = serial_norm(serial_raw);
        if serial == "0" {
            continue;
        }
        let identities = row.name_value.as_deref().map(names).unwrap_or_default();
        let entry = certs.entry(serial.clone()).or_insert_with(|| Certificate {
            serial: serial.clone(),
            in_ct: true,
            served_live: false,
            currently_valid: valid,
            ct_ids: Vec::new(),
            common_name: row.common_name.clone(),
            identities: identities.clone(),
            not_before: nb,
            not_after: na,
            pubkey_alg: None,
            sig_alg: None,
            issuer: None,
            key_algorithm: None,
            key_size: None,
            sig_key_algorithm: None,
            sig_hash_algorithm: None,
            cert_signature: None,
            chain: Vec::new(),
        });
        if let Some(id) = row.id {
            if !entry.ct_ids.contains(&id) {
                entry.ct_ids.push(id);
            }
        }
        if valid {
            entry.currently_valid = true;
        }
        if entry.common_name.is_none() {
            entry.common_name = row.common_name.clone();
        }
    }
    for cert in certs.values_mut() {
        cert.ct_ids.sort_unstable();
        cert.ct_ids.dedup();
    }
    certs
}

pub fn certificates_from_db(rows: &[DbRow], now: DateTime<Utc>) -> BTreeMap<String, Certificate> {
    let mut certs: BTreeMap<String, Certificate> = BTreeMap::new();
    for row in rows {
        let nb = row.not_before.as_deref().and_then(ctdate);
        let na = row.not_after.as_deref().and_then(ctdate);
        let valid = currently_valid(nb, na, now);
        let future = future_valid(nb, now);
        if !valid && !future {
            continue;
        }
        let serial = serial_norm(&row.serial);
        if serial == "0" {
            continue;
        }
        let Some(name) = row
            .dns_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        let name = name.to_lowercase();
        let cert_signature = cert_signature_from_db(
            row.key_algorithm.as_deref(),
            row.key_size,
            row.sig_key_algorithm.as_deref(),
            row.sig_hash_algorithm.as_deref(),
        );
        let key_algorithm = row.key_algorithm.clone();
        let entry = certs.entry(serial.clone()).or_insert_with(|| Certificate {
            serial: serial.clone(),
            in_ct: true,
            served_live: false,
            currently_valid: valid,
            ct_ids: Vec::new(),
            common_name: row.common_name.clone(),
            identities: Vec::new(),
            not_before: nb,
            not_after: na,
            pubkey_alg: None,
            sig_alg: None,
            issuer: row.issuer_ca_name.clone(),
            key_algorithm,
            key_size: row.key_size,
            sig_key_algorithm: row.sig_key_algorithm.clone(),
            sig_hash_algorithm: row.sig_hash_algorithm.clone(),
            cert_signature,
            chain: Vec::new(),
        });
        if !entry.ct_ids.contains(&(row.cert_id as u64)) {
            entry.ct_ids.push(row.cert_id as u64);
        }
        if !entry.identities.contains(&name) {
            entry.identities.push(name);
        }
        if valid {
            entry.currently_valid = true;
        }
        if entry.common_name.is_none() {
            entry.common_name = row.common_name.clone();
        }
    }
    for cert in certs.values_mut() {
        cert.ct_ids.sort_unstable();
        cert.identities.sort();
    }
    certs
}

pub fn revive_certs(certs: Vec<Certificate>, now: DateTime<Utc>) -> BTreeMap<String, Certificate> {
    certs
        .into_iter()
        .map(|mut c| {
            c.currently_valid = currently_valid(c.not_before, c.not_after, now);
            c
        })
        .map(|c| (c.serial.clone(), c))
        .collect()
}

pub fn cert_refs(certs: &BTreeMap<String, Certificate>, host: &str) -> Vec<CertRef> {
    let mut refs = Vec::new();
    for cert in certs.values().filter(|c| c.currently_valid) {
        if let Some(kind) = coverage(&cert.identities, host) {
            refs.push(CertRef {
                serial: cert.serial.clone(),
                kind,
            });
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn ctdate_appends_zone_when_missing() {
        assert_eq!(
            ctdate("2014-04-23T12:16:09").unwrap(),
            utc("2014-04-23T12:16:09Z")
        );
        assert_eq!(
            ctdate("2014-04-23 12:16:09").unwrap(),
            utc("2014-04-23T12:16:09Z")
        );
        // certwatch DB ::text shape: naive, no zone suffix.
        assert_eq!(
            ctdate("2026-05-27 00:00:00").unwrap(),
            utc("2026-05-27T00:00:00Z")
        );
        assert_eq!(
            ctdate("2014-04-23T12:16:09Z").unwrap(),
            utc("2014-04-23T12:16:09Z")
        );
        assert_eq!(
            ctdate("2014-04-23T12:16:09+02:00").unwrap(),
            utc("2014-04-23T10:16:09Z")
        );
        assert_eq!(
            ctdate("2014-04-23T12:16:09+0200").unwrap(),
            utc("2014-04-23T10:16:09Z")
        );
        assert!(ctdate("").is_none());
        assert!(ctdate("not a date").is_none());
    }

    #[test]
    fn names_splits_lowers_and_dedups() {
        assert_eq!(
            names("WWW.NBP.pl\r\nmail.nbp.pl\n\nmail.nbp.pl"),
            vec!["mail.nbp.pl", "www.nbp.pl"]
        );
        assert_eq!(names(""), Vec::<String>::new());
    }

    #[test]
    fn coverage_follows_rfc_6125_single_label() {
        let idents = vec!["nbp.pl".to_string(), "*.nbp.pl".to_string()];
        assert_eq!(coverage(&idents, "nbp.pl"), Some(MatchKind::Exact));
        assert_eq!(coverage(&idents, "www.nbp.pl"), Some(MatchKind::Wildcard));
        assert_eq!(coverage(&idents, "a.b.nbp.pl"), None);
        assert_eq!(coverage(&idents, "other.pl"), None);

        let deep = vec!["*.a.nbp.pl".to_string()];
        assert_eq!(coverage(&deep, "x.a.nbp.pl"), Some(MatchKind::Wildcard));
        assert_eq!(coverage(&deep, "a.nbp.pl"), None);
        assert_eq!(coverage(&deep, "x.y.a.nbp.pl"), None);
    }

    #[test]
    fn serial_norm_strips_separators_and_zeros() {
        assert_eq!(serial_norm("0A:0B:0C"), "a0b0c");
        assert_eq!(serial_norm("00ABC"), "abc");
        assert_eq!(serial_norm("0abc"), "abc");
        assert_eq!(serial_norm("0000"), "0");
        assert_eq!(serial_norm(""), "0");
        assert_eq!(serial_norm("deadbeef"), "deadbeef");
    }

    #[test]
    fn validity_semantics_match_jq_epoch_zero() {
        let now = utc("2026-09-21T12:00:00Z");
        let nb = utc("2026-01-01T00:00:00Z");
        let na = utc("2027-01-01T00:00:00Z");
        assert!(currently_valid(Some(nb), Some(na), now));
        assert!(!future_valid(Some(nb), now));

        let future_nb = utc("2027-06-01T00:00:00Z");
        assert!(!currently_valid(Some(future_nb), Some(na), now));
        assert!(future_valid(Some(future_nb), now));

        assert!(!currently_valid(Some(nb), None, now));
        assert!(!currently_valid(None, None, now));
    }

    #[test]
    fn certificates_dedups_by_serial_and_collects_ids() {
        let rows = vec![
            CtRow {
                id: Some(2),
                common_name: Some("www.nbp.pl".into()),
                name_value: Some("www.nbp.pl\nnbp.pl".into()),
                not_before: Some("2026-01-01T00:00:00".into()),
                not_after: Some("2027-01-01T00:00:00".into()),
                serial_number: Some("0AA11".into()),
            },
            CtRow {
                id: Some(1),
                common_name: Some("www.nbp.pl".into()),
                name_value: Some("www.nbp.pl".into()),
                not_before: Some("2026-01-01T00:00:00".into()),
                not_after: Some("2027-01-01T00:00:00".into()),
                serial_number: Some("AA11".into()),
            },
            CtRow {
                id: Some(3),
                common_name: Some("future".into()),
                name_value: Some("future.nbp.pl".into()),
                not_before: Some("2027-06-01T00:00:00".into()),
                not_after: Some("2028-01-01T00:00:00".into()),
                serial_number: Some("BB22".into()),
            },
            CtRow {
                id: Some(4),
                common_name: Some("expired".into()),
                name_value: Some("expired.nbp.pl".into()),
                not_before: Some("2020-01-01T00:00:00".into()),
                not_after: Some("2021-01-01T00:00:00".into()),
                serial_number: Some("CC33".into()),
            },
        ];
        let now = utc("2026-09-21T12:00:00Z");
        let certs = certificates(&rows, now);
        assert_eq!(certs.len(), 2);
        let aa = &certs["aa11"];
        assert_eq!(aa.ct_ids, vec![1, 2]);
        assert!(aa.currently_valid);
        assert_eq!(aa.identities, vec!["nbp.pl", "www.nbp.pl"]);
        let bb = &certs["bb22"];
        assert!(!bb.currently_valid);
    }

    #[test]
    fn certificates_from_db_group_by_serial_and_name_facts() {
        let rows = vec![
            DbRow {
                cert_id: 27387939567,
                serial: "069ee4d86e61f5bc610cd369ea2e8784".into(),
                dns_name: Some("3dsecure.bankmillennium.pl".into()),
                common_name: Some("3dsecure.bankmillennium.pl".into()),
                not_before: Some("2026-05-27 00:00:00".into()),
                not_after: Some("2026-12-11 23:59:59".into()),
                key_algorithm: Some("RSA".into()),
                key_size: Some(2048),
                sig_key_algorithm: Some("RSA".into()),
                sig_hash_algorithm: Some("SHA-256".into()),
                issuer_ca_name: Some("C=US, O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1".into()),
            },
            DbRow {
                cert_id: 26679999700,
                serial: "069ee4d86e61f5bc610cd369ea2e8784".into(),
                dns_name: Some("www.bankmillennium.pl".into()),
                common_name: Some("3dsecure.bankmillennium.pl".into()),
                not_before: Some("2026-05-27 00:00:00".into()),
                not_after: Some("2026-12-11 23:59:59".into()),
                key_algorithm: Some("RSA".into()),
                key_size: Some(2048),
                sig_key_algorithm: Some("RSA".into()),
                sig_hash_algorithm: Some("SHA-256".into()),
                issuer_ca_name: Some("C=US, O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1".into()),
            },
            DbRow {
                cert_id: 28833473386,
                serial: "0e0058034625f04166936598b0748415".into(),
                dns_name: Some("*.api.bankmillennium.pl".into()),
                common_name: Some("*.api.bankmillennium.pl".into()),
                not_before: Some("2026-08-19 00:00:00".into()),
                not_after: Some("2027-03-05 23:59:59".into()),
                key_algorithm: Some("EC".into()),
                key_size: Some(384),
                sig_key_algorithm: Some("ECDSA".into()),
                sig_hash_algorithm: Some("SHA-384".into()),
                issuer_ca_name: Some("CN=Test EC CA".into()),
            },
            DbRow {
                cert_id: 1,
                serial: "0deadbeef".into(),
                dns_name: Some("gone.bankmillennium.pl".into()),
                common_name: None,
                not_before: Some("2020-01-01 00:00:00".into()),
                not_after: Some("2021-01-01 00:00:00".into()),
                key_algorithm: None,
                key_size: None,
                sig_key_algorithm: None,
                sig_hash_algorithm: None,
                issuer_ca_name: None,
            },
        ];
        let now = utc("2026-09-21T12:00:00Z");
        let certs = certificates_from_db(&rows, now);
        assert_eq!(certs.len(), 2, "expired row dropped, duplicates merged");

        let rsa = &certs["69ee4d86e61f5bc610cd369ea2e8784"];
        assert_eq!(rsa.ct_ids, vec![26679999700, 27387939567]);
        assert_eq!(
            rsa.identities,
            vec!["3dsecure.bankmillennium.pl", "www.bankmillennium.pl"]
        );
        assert!(rsa.currently_valid);
        assert_eq!(rsa.cert_signature.as_deref(), Some("RSA-SHA256"));
        assert_eq!(rsa.key_size, Some(2048));
        assert_eq!(
            rsa.issuer.as_deref(),
            Some("C=US, O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1")
        );

        let ec = &certs["e0058034625f04166936598b0748415"];
        assert_eq!(ec.cert_signature.as_deref(), Some("ECDSA-P384"));
    }

    #[test]
    fn cert_refs_exact_and_wildcard() {
        let now = utc("2026-09-21T12:00:00Z");
        let rows = vec![
            CtRow {
                id: Some(1),
                common_name: Some("www.nbp.pl".into()),
                name_value: Some("www.nbp.pl".into()),
                not_before: Some("2026-01-01T00:00:00".into()),
                not_after: Some("2027-01-01T00:00:00".into()),
                serial_number: Some("AA11".into()),
            },
            CtRow {
                id: Some(2),
                common_name: Some("*.nbp.pl".into()),
                name_value: Some("*.nbp.pl".into()),
                not_before: Some("2026-01-01T00:00:00".into()),
                not_after: Some("2027-01-01T00:00:00".into()),
                serial_number: Some("BB22".into()),
            },
        ];
        let certs = certificates(&rows, now);
        let refs = cert_refs(&certs, "vpn.nbp.pl");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].serial, "bb22");
        assert_eq!(refs[0].kind, MatchKind::Wildcard);
        let refs = cert_refs(&certs, "www.nbp.pl");
        assert_eq!(refs.len(), 2);
    }
}
