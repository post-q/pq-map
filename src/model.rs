use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Origins(u8);

impl Origins {
    pub const NONE: Self = Self(0);
    pub const CT: Self = Self(1);
    pub const DNS: Self = Self(2);
    pub const APEX: Self = Self(4);

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    fn labels(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.contains(Self::CT) {
            out.push("ct");
        }
        if self.contains(Self::DNS) {
            out.push("dns");
        }
        if self.contains(Self::APEX) {
            out.push("apex");
        }
        out
    }
}

impl Serialize for Origins {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.labels())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Exact,
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum ProbeStatus {
    Ok,
    DnsFailure,
    TcpRefused,
    TcpUnreachable,
    Timeout { secs: u64 },
    TlsHandshakeFailed,
    ConnectedNoCert,
    Unknown { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub serial: String,
    pub in_ct: bool,
    pub served_live: bool,
    pub currently_valid: bool,
    pub ct_ids: Vec<u64>,
    pub common_name: Option<String>,
    pub identities: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub pubkey_alg: Option<String>,
    pub sig_alg: Option<String>,
    pub issuer: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_size: Option<i64>,
    pub sig_key_algorithm: Option<String>,
    pub sig_hash_algorithm: Option<String>,
    pub cert_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertRef {
    pub serial: String,
    pub kind: MatchKind,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum DnsRef {
    Srv { service: String },
    Https,
}

/// DNS response status for the A/AAAA lookup of a host (RFC 1035 rcodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsStatus {
    /// NOERROR with address records.
    Ok,
    /// NOERROR, name exists, but no A/AAAA records (NODATA).
    NoData,
    /// NXDOMAIN — the name does not exist.
    NxDomain,
    ServFail,
    Refused,
    /// Resolver gave up within its timeout budget.
    Timeout,
    /// Any other response code or transport failure.
    Other,
}

impl DnsStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "resolves",
            Self::NoData => "no data",
            Self::NxDomain => "nxdomain",
            Self::ServFail => "servfail",
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Other => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServedCert {
    pub serial: String,
    pub common_name: Option<String>,
    pub identities: Vec<String>,
    pub pubkey_alg: Option<String>,
    pub sig_alg: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    /// Signature algorithms of the served chain, leaf first.
    pub chain_sigs: Vec<String>,
    pub pubkey_curve: Option<String>,
    pub cert_signature: Option<String>,
}

/// Crypto negotiated during the live handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Negotiated {
    pub tls_version: Option<String>,
    pub kx_group: Option<String>,
    pub cipher: Option<String>,
}

impl ServedCert {
    pub fn into_certificate(self) -> Certificate {
        let currently_valid =
            crate::discover::ct::currently_valid(self.not_before, self.not_after, Utc::now());
        Certificate {
            serial: self.serial,
            in_ct: false,
            served_live: true,
            currently_valid,
            ct_ids: Vec::new(),
            common_name: self.common_name,
            identities: self.identities,
            not_before: self.not_before,
            not_after: self.not_after,
            pubkey_alg: self.pubkey_alg,
            sig_alg: self.sig_alg,
            issuer: self.issuer,
            key_algorithm: None,
            key_size: None,
            sig_key_algorithm: None,
            sig_hash_algorithm: None,
            cert_signature: self.cert_signature,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub status: ProbeStatus,
    pub ip: Option<IpAddr>,
    pub served: Option<ServedCert>,
    pub served_not_in_ct: bool,
    pub negotiated: Option<Negotiated>,
    pub observed_at: Option<DateTime<Utc>>,
}

impl Endpoint {
    pub fn failed(status: ProbeStatus) -> Self {
        Self {
            status,
            ip: None,
            served: None,
            served_not_in_ct: false,
            negotiated: None,
            observed_at: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Host {
    pub name: String,
    pub origins: Origins,
    pub resolves: Option<bool>,
    pub dns_status: Option<DnsStatus>,
    pub ct_refs: Vec<CertRef>,
    pub dns_refs: Vec<DnsRef>,
    pub endpoint: Option<Endpoint>,
    pub ports: Vec<PortScan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScan {
    pub port: u16,
    pub state: ScanState,
    pub served: Option<ServedCert>,
    pub negotiated: Option<Negotiated>,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SrvRecord {
    pub service: String,
    pub fqdn: String,
    pub priority: u32,
    pub weight: u32,
    pub port: u16,
    pub target: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct MxRecord {
    pub priority: u32,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpsRecord {
    pub rr_type: String,
    pub priority: u16,
    pub target: String,
    pub params: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Fresh,
    Cached { age_secs: u64 },
    Stale { age_secs: Option<u64> },
}

fn hash_norm(raw: &str) -> String {
    raw.trim().to_ascii_uppercase().replace('-', "")
}

pub fn alg_class_of(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("ed25519") {
        "Ed25519".to_string()
    } else if lower.contains("ed448") {
        "Ed448".to_string()
    } else if lower.starts_with("ml-dsa") || lower.contains("mldsa") {
        raw.trim().to_string()
    } else if lower.contains("ecdsa") || lower.contains("ecpublickey") || lower == "ec" {
        "ECDSA".to_string()
    } else if lower.contains("rsa") {
        "RSA".to_string()
    } else {
        raw.trim().to_string()
    }
}

pub fn curve_from_key_size(size: i64) -> Option<&'static str> {
    match size {
        256 => Some("P256"),
        384 => Some("P384"),
        521 => Some("P521"),
        _ => None,
    }
}

pub fn cert_key_name(
    alg: Option<&str>,
    key_size: Option<i64>,
    curve: Option<&str>,
) -> Option<String> {
    let class = alg_class_of(alg?);
    if class == "ECDSA" {
        let bits = key_size.or_else(|| {
            curve.and_then(|c| c.trim().trim_start_matches(['P', 'p', '-']).parse().ok())
        });
        return Some(match bits {
            Some(b) => format!("EC-{b}"),
            None => "EC".to_string(),
        });
    }
    Some(match key_size {
        Some(b) => format!("{class}-{b}"),
        None => class,
    })
}

pub fn cert_signature_name(class: &str, hash: Option<&str>, curve: Option<&str>) -> Option<String> {
    let class = alg_class_of(class);
    match class.as_str() {
        "RSA" => Some(match hash.map(hash_norm) {
            Some(h) => format!("RSA-{h}"),
            None => "RSA".to_string(),
        }),
        "ECDSA" => Some(match curve {
            Some(c) => format!("ECDSA-{c}"),
            None => "ECDSA".to_string(),
        }),
        other => Some(other.to_string()),
    }
}

pub fn cert_signature_from_db(
    key_algorithm: Option<&str>,
    key_size: Option<i64>,
    sig_key_algorithm: Option<&str>,
    sig_hash_algorithm: Option<&str>,
) -> Option<String> {
    let class = sig_key_algorithm.or(key_algorithm)?;
    let curve = if alg_class_of(class) == "ECDSA" {
        key_size.and_then(curve_from_key_size)
    } else {
        None
    };
    cert_signature_name(class, sig_hash_algorithm, curve)
}

pub fn port_service(port: u16) -> &'static str {
    match port {
        25 | 587 => "SMTP",
        465 => "SMTPS",
        993 => "IMAPS",
        995 => "POP3S",
        636 => "LDAPS",
        5061 => "SIPS",
        8883 => "MQTTS",
        5222 => "XMPP",
        5223 => "XMPPS",
        _ => "TLS",
    }
}

pub fn symmetric_name(cipher: &str) -> Option<String> {
    let upper = cipher.to_ascii_uppercase();
    if upper.contains("CHACHA20") {
        return Some("CHACHA20-POLY1305".to_string());
    }
    let bits = if upper.contains("AES_128") {
        "AES128"
    } else if upper.contains("AES_256") {
        "AES256"
    } else {
        return None;
    };
    let mode = if upper.contains("GCM") {
        "GCM"
    } else if upper.contains("CBC") {
        "CBC"
    } else {
        return None;
    };
    Some(format!("{bits}-{mode}"))
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CtStats {
    /// Number of raw crt.sh log entries in the snapshot.
    pub rows: usize,
    /// Log entries currently valid (not_before <= now <= not_after).
    pub valid: usize,
    /// Log entries that are not valid yet.
    pub future: usize,
}

#[derive(Debug, Serialize)]
pub struct DomainState {
    pub domain: String,
    pub checked_at: DateTime<Local>,
    pub provenance: Provenance,
    pub ct_stats: CtStats,
    pub certs: BTreeMap<String, Certificate>,
    pub hosts: BTreeMap<String, Host>,
    pub srv: Vec<SrvRecord>,
    pub https: Vec<HttpsRecord>,
    pub mx: Vec<MxRecord>,
}

impl DomainState {
    pub fn host_names(&self) -> Vec<String> {
        self.hosts.keys().cloned().collect()
    }
}

#[cfg(test)]
pub fn fixture() -> DomainState {
    use chrono::TimeZone;

    let now = Utc::now();
    let nb = now - chrono::Duration::days(30);
    let na = now + chrono::Duration::days(30);
    let observed = Utc.with_ymd_and_hms(2026, 9, 21, 12, 0, 0).unwrap();

    let mut certs = BTreeMap::new();
    certs.insert(
        "aa11".to_string(),
        Certificate {
            serial: "aa11".to_string(),
            in_ct: true,
            served_live: true,
            currently_valid: true,
            ct_ids: vec![9612296601],
            common_name: Some("www.nbp.pl".to_string()),
            identities: vec!["nbp.pl".to_string(), "www.nbp.pl".to_string()],
            not_before: Some(nb),
            not_after: Some(na),
            pubkey_alg: Some("RSA".to_string()),
            sig_alg: Some("SHA256/RSA".to_string()),
            issuer: Some("CN=DigiCert TLS RSA SHA256 2020 CA-1".to_string()),
            key_algorithm: Some("RSA".to_string()),
            key_size: Some(2048),
            sig_key_algorithm: Some("RSA".to_string()),
            sig_hash_algorithm: Some("SHA-256".to_string()),
            cert_signature: Some("RSA-SHA256".to_string()),
        },
    );
    certs.insert(
        "cc33".to_string(),
        Certificate {
            serial: "cc33".to_string(),
            in_ct: true,
            served_live: false,
            currently_valid: true,
            ct_ids: vec![9612300001],
            common_name: Some("eas.nbp.pl".to_string()),
            identities: vec!["eas.nbp.pl".to_string()],
            not_before: Some(nb),
            not_after: Some(na - chrono::Duration::days(10)),
            pubkey_alg: None,
            sig_alg: None,
            issuer: Some("CN=Certum OV TLS G2 R39 CA".to_string()),
            key_algorithm: Some("RSA".to_string()),
            key_size: Some(2048),
            sig_key_algorithm: Some("RSA".to_string()),
            sig_hash_algorithm: Some("SHA-256".to_string()),
            cert_signature: Some("RSA-SHA256".to_string()),
        },
    );
    certs.insert(
        "bb22".to_string(),
        Certificate {
            serial: "bb22".to_string(),
            in_ct: true,
            served_live: false,
            currently_valid: true,
            ct_ids: vec![9612297416, 9612300000],
            common_name: Some("*.nbp.pl".to_string()),
            identities: vec!["*.nbp.pl".to_string()],
            not_before: Some(nb),
            not_after: Some(na),
            pubkey_alg: None,
            sig_alg: None,
            issuer: None,
            key_algorithm: Some("EC".to_string()),
            key_size: Some(256),
            sig_key_algorithm: Some("ECDSA".to_string()),
            sig_hash_algorithm: Some("SHA-256".to_string()),
            cert_signature: Some("ECDSA-P256".to_string()),
        },
    );

    let mut hosts = BTreeMap::new();
    let mut www = Host {
        name: "www.nbp.pl".to_string(),
        origins: Origins::CT,
        resolves: Some(true),
        dns_status: Some(DnsStatus::Ok),
        ct_refs: vec![CertRef {
            serial: "aa11".to_string(),
            kind: MatchKind::Exact,
        }],
        dns_refs: Vec::new(),
        ports: Vec::new(),
        endpoint: Some(Endpoint {
            status: ProbeStatus::Ok,
            negotiated: Some(Negotiated {
                tls_version: Some("TLS1.3".to_string()),
                kx_group: Some("X25519MLKEM768".to_string()),
                cipher: Some("TLS13_AES_256_GCM_SHA384".to_string()),
            }),
            ip: Some("104.94.222.171".parse().unwrap()),
            served: Some(ServedCert {
                serial: "aa11".to_string(),
                common_name: Some("www.nbp.pl".to_string()),
                identities: vec!["nbp.pl".to_string(), "www.nbp.pl".to_string()],
                pubkey_alg: Some("RSA".to_string()),
                sig_alg: Some("SHA256/RSA".to_string()),
                issuer: Some("CN=DigiCert TLS RSA SHA256 2020 CA-1".to_string()),
                not_before: Some(nb),
                not_after: Some(na),
                chain_sigs: vec!["SHA256/RSA".to_string()],
                pubkey_curve: None,
                cert_signature: Some("RSA-SHA256".to_string()),
            }),
            served_not_in_ct: false,
            observed_at: Some(observed),
        }),
    };
    www.origins.insert(Origins::DNS);
    hosts.insert("www.nbp.pl".to_string(), www);
    hosts.insert(
        "nbp.pl".to_string(),
        Host {
            name: "nbp.pl".to_string(),
            origins: Origins::APEX,
            resolves: Some(true),
            dns_status: Some(DnsStatus::Ok),
            ct_refs: vec![CertRef {
                serial: "aa11".to_string(),
                kind: MatchKind::Exact,
            }],
            dns_refs: Vec::new(),
            ports: Vec::new(),
            endpoint: Some(Endpoint {
                status: ProbeStatus::Ok,
                ip: Some("104.94.222.1".parse().unwrap()),
                served: Some(ServedCert {
                    serial: "aa11".to_string(),
                    common_name: Some("www.nbp.pl".to_string()),
                    identities: vec!["nbp.pl".to_string(), "www.nbp.pl".to_string()],
                    pubkey_alg: Some("RSA".to_string()),
                    sig_alg: Some("SHA256/RSA".to_string()),
                    issuer: Some("CN=DigiCert TLS RSA SHA256 2020 CA-1".to_string()),
                    not_before: Some(nb),
                    not_after: Some(na),
                    chain_sigs: vec!["SHA256/RSA".to_string()],
                    pubkey_curve: None,
                    cert_signature: Some("RSA-SHA256".to_string()),
                }),
                served_not_in_ct: false,
                observed_at: Some(observed),
                negotiated: Some(Negotiated {
                    tls_version: Some("TLS1.3".to_string()),
                    kx_group: Some("X25519MLKEM768".to_string()),
                    cipher: Some("TLS13_AES_256_GCM_SHA384".to_string()),
                }),
            }),
        },
    );
    hosts.insert(
        "old.nbp.pl".to_string(),
        Host {
            name: "old.nbp.pl".to_string(),
            origins: Origins::CT,
            resolves: Some(false),
            dns_status: Some(DnsStatus::NxDomain),
            ct_refs: vec![CertRef {
                serial: "bb22".to_string(),
                kind: MatchKind::Wildcard,
            }],
            dns_refs: Vec::new(),
            ports: Vec::new(),
            endpoint: Some(Endpoint::failed(ProbeStatus::DnsFailure)),
        },
    );
    hosts.insert(
        "vpn.nbp.pl".to_string(),
        Host {
            name: "vpn.nbp.pl".to_string(),
            origins: Origins::CT,
            resolves: Some(true),
            dns_status: Some(DnsStatus::Ok),
            ct_refs: vec![CertRef {
                serial: "bb22".to_string(),
                kind: MatchKind::Wildcard,
            }],
            dns_refs: Vec::new(),
            ports: Vec::new(),
            endpoint: Some(Endpoint::failed(ProbeStatus::TcpRefused)),
        },
    );
    hosts.insert(
        "eas.nbp.pl".to_string(),
        Host {
            name: "eas.nbp.pl".to_string(),
            origins: Origins::CT,
            resolves: Some(true),
            dns_status: Some(DnsStatus::Ok),
            ct_refs: vec![
                CertRef {
                    serial: "bb22".to_string(),
                    kind: MatchKind::Wildcard,
                },
                CertRef {
                    serial: "cc33".to_string(),
                    kind: MatchKind::Exact,
                },
            ],
            dns_refs: Vec::new(),
            ports: vec![
                PortScan {
                    port: 465,
                    state: ScanState::Open,
                    served: Some(ServedCert {
                        serial: "cc33".to_string(),
                        common_name: Some("eas.nbp.pl".to_string()),
                        identities: vec!["eas.nbp.pl".to_string()],
                        pubkey_alg: Some("RSA".to_string()),
                        sig_alg: Some("SHA256/RSA".to_string()),
                        issuer: Some("CN=Certum OV TLS G2 R39 CA".to_string()),
                        not_before: Some(nb),
                        not_after: Some(na - chrono::Duration::days(10)),
                        chain_sigs: vec!["SHA256/RSA".to_string()],
                        pubkey_curve: None,
                        cert_signature: Some("RSA-SHA256".to_string()),
                    }),
                    negotiated: Some(Negotiated {
                        tls_version: Some("TLS1.3".to_string()),
                        kx_group: Some("X25519".to_string()),
                        cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
                    }),
                    observed_at: Some(observed),
                },
                PortScan {
                    port: 25,
                    state: ScanState::Open,
                    served: Some(ServedCert {
                        serial: "cc33".to_string(),
                        common_name: Some("eas.nbp.pl".to_string()),
                        identities: vec!["eas.nbp.pl".to_string()],
                        pubkey_alg: Some("RSA".to_string()),
                        sig_alg: Some("SHA256/RSA".to_string()),
                        issuer: Some("CN=Certum OV TLS G2 R39 CA".to_string()),
                        not_before: Some(nb),
                        not_after: Some(na - chrono::Duration::days(10)),
                        chain_sigs: vec!["SHA256/RSA".to_string()],
                        pubkey_curve: None,
                        cert_signature: Some("RSA-SHA256".to_string()),
                    }),
                    negotiated: Some(Negotiated {
                        tls_version: Some("TLS1.3".to_string()),
                        kx_group: Some("X25519".to_string()),
                        cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
                    }),
                    observed_at: Some(observed),
                },
            ],
            endpoint: Some(Endpoint::failed(ProbeStatus::TcpRefused)),
        },
    );
    let mut apex = hosts.get("nbp.pl").cloned().unwrap();
    apex.origins.insert(Origins::CT);
    hosts.insert("nbp.pl".to_string(), apex);

    DomainState {
        domain: "nbp.pl".to_string(),
        checked_at: Local.with_ymd_and_hms(2026, 9, 21, 12, 0, 0).unwrap(),
        provenance: Provenance::Cached { age_secs: 2520 },
        certs,
        hosts,
        mx: vec![MxRecord {
            priority: 10,
            target: "eas.nbp.pl".to_string(),
        }],
        srv: vec![SrvRecord {
            service: "_sip._tls".to_string(),
            fqdn: "_sip._tls.nbp.pl".to_string(),
            priority: 1,
            weight: 100,
            port: 443,
            target: "sipdir.online.lync.com".to_string(),
        }],
        https: vec![HttpsRecord {
            rr_type: "HTTPS".to_string(),
            priority: 1,
            target: ".".to_string(),
            params: "alpn=h2,h3".to_string(),
        }],
        ct_stats: CtStats {
            rows: 2,
            valid: 1,
            future: 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_signature_names_are_canonical() {
        assert_eq!(
            cert_signature_from_db(Some("RSA"), Some(2048), Some("RSA"), Some("SHA-256")),
            Some("RSA-SHA256".to_string())
        );
        assert_eq!(
            cert_signature_from_db(Some("EC"), Some(256), Some("ECDSA"), Some("SHA-256")),
            Some("ECDSA-P256".to_string())
        );
        assert_eq!(
            cert_signature_from_db(Some("EC"), Some(384), Some("ECDSA"), Some("SHA-384")),
            Some("ECDSA-P384".to_string())
        );
        assert_eq!(
            cert_signature_name("rsaEncryption", Some("sha256"), None),
            Some("RSA-SHA256".to_string())
        );
        assert_eq!(
            cert_signature_name("id-ecPublicKey", Some("ecdsa-with-SHA384"), Some("P384")),
            Some("ECDSA-P384".to_string())
        );
        assert_eq!(
            cert_signature_name("Ed25519", None, None),
            Some("Ed25519".to_string())
        );
        assert_eq!(
            cert_signature_name("ML-DSA-65", None, None),
            Some("ML-DSA-65".to_string())
        );
        assert_eq!(
            cert_signature_name("1.2.3.4.5", None, None),
            Some("1.2.3.4.5".to_string())
        );
        assert_eq!(cert_signature_from_db(None, None, None, None), None);
    }

    #[test]
    fn curve_from_key_size_maps_nist_curves() {
        assert_eq!(curve_from_key_size(256), Some("P256"));
        assert_eq!(curve_from_key_size(384), Some("P384"));
        assert_eq!(curve_from_key_size(521), Some("P521"));
        assert_eq!(curve_from_key_size(2048), None);
        assert_eq!(curve_from_key_size(512), None);
    }

    #[test]
    fn cert_key_names_are_canonical() {
        assert_eq!(
            cert_key_name(Some("RSA"), Some(2048), None),
            Some("RSA-2048".to_string())
        );
        assert_eq!(
            cert_key_name(Some("EC"), Some(256), None),
            Some("EC-256".to_string())
        );
        assert_eq!(
            cert_key_name(Some("EC"), Some(384), None),
            Some("EC-384".to_string())
        );
        assert_eq!(
            cert_key_name(Some("ECDSA"), None, Some("P256")),
            Some("EC-256".to_string())
        );
        assert_eq!(
            cert_key_name(Some("id-ecPublicKey"), None, Some("P521")),
            Some("EC-521".to_string())
        );
        assert_eq!(
            cert_key_name(Some("RSA"), None, None),
            Some("RSA".to_string())
        );
        assert_eq!(
            cert_key_name(Some("Ed25519"), None, None),
            Some("Ed25519".to_string())
        );
        assert_eq!(cert_key_name(None, None, None), None);
    }

    #[test]
    fn symmetric_names_from_suite_names() {
        assert_eq!(
            symmetric_name("TLS13_AES_256_GCM_SHA384"),
            Some("AES256-GCM".to_string())
        );
        assert_eq!(
            symmetric_name("TLS_AES_128_GCM_SHA256"),
            Some("AES128-GCM".to_string())
        );
        assert_eq!(
            symmetric_name("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            Some("AES128-GCM".to_string())
        );
        assert_eq!(
            symmetric_name("TLS13_CHACHA20_POLY1305_SHA256"),
            Some("CHACHA20-POLY1305".to_string())
        );
        assert_eq!(
            symmetric_name("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
            Some("AES256-CBC".to_string())
        );
        assert_eq!(symmetric_name("TLS_UNKNOWN"), None);
    }

    #[test]
    fn fixture_facts_are_consistent() {
        let state = fixture();
        let aa = &state.certs["aa11"];
        assert_eq!(aa.cert_signature.as_deref(), Some("RSA-SHA256"));
        assert_eq!(aa.key_size, Some(2048));
        let bb = &state.certs["bb22"];
        assert_eq!(bb.cert_signature.as_deref(), Some("ECDSA-P256"));
    }
}
