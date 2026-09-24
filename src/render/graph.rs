use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use crate::model::{
    ChainEntry, DomainState, Host, MatchKind, ProbeStatus, cert_key_name, cert_signature_from_db,
};

use serde::Serialize;

#[derive(Debug, Serialize)]
struct Node {
    id: String,
    label: String,
    #[serde(rename = "type")]
    node_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<CertMetadata>,
}

#[derive(Debug, Serialize)]
struct CertMetadata {
    ca_role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sans: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct Link {
    source: String,
    target: String,
    label: &'static str,
}

#[derive(Debug, Serialize)]
struct Graph {
    nodes: Vec<Node>,
    links: Vec<Link>,
}

struct CertNode {
    id: String,
    label: String,
    metadata: Option<CertMetadata>,
    cert_signature: Option<String>,
    cert_key: Option<String>,
    issuer: Option<String>,
    chain: Vec<ChainEntry>,
}

struct CertFacts<'a> {
    common_name: Option<String>,
    serial: &'a str,
    ct_id: Option<u64>,
    cert_signature: Option<String>,
    key_alg: Option<&'a str>,
    key_size: Option<i64>,
    curve: Option<&'a str>,
    issuer: Option<String>,
    identities: Vec<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    chain: Vec<ChainEntry>,
}

fn cert_node(f: CertFacts<'_>) -> CertNode {
    let cn = f.common_name.unwrap_or_else(|| f.serial.to_string());
    let id = match f.ct_id {
        Some(id) => format!("cert:{cn}:{id}"),
        None => format!("cert:{cn}"),
    };
    let sans: Vec<String> = f.identities.iter().filter(|i| **i != cn).cloned().collect();
    let label = match sans.len() {
        0 => cn.clone(),
        1 => format!("{cn} +1 SAN"),
        n => format!("{cn} +{n} SANs"),
    };
    let metadata = CertMetadata {
        ca_role: "leaf",
        sans: (!sans.is_empty()).then_some(sans),
        not_before: f.not_before,
        not_after: f.not_after,
    };
    CertNode {
        id,
        label,
        metadata: Some(metadata),
        cert_signature: f.cert_signature,
        cert_key: cert_key_name(f.key_alg, f.key_size, f.curve),
        issuer: f.issuer,
        chain: f.chain,
    }
}

fn is_self_issued(entry: &ChainEntry) -> bool {
    match (entry.ski.as_deref(), entry.aki.as_deref()) {
        (Some(ski), Some(aki)) if !ski.is_empty() && ski == aki => true,
        _ => match (&entry.common_name, &entry.issuer_ca_name) {
            (Some(cn), Some(issuer)) => ca_cn(issuer) == *cn,
            _ => false,
        },
    }
}

fn ca_slug(cn: &str) -> String {
    let mut slug = String::new();
    let mut prev_dash = true;
    for c in cn.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

fn ca_id(dn: &str) -> (String, String) {
    let cn = ca_cn(dn);
    (format!("ca:{}", ca_slug(&cn)), cn)
}

fn ca_cn(dn: &str) -> String {
    for part in split_unescaped_commas(dn) {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.trim().to_string();
        }
    }
    dn.to_string()
}

fn split_unescaped_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if c == ',' && !s[..i].ends_with('\\') {
            out.push(&s[start..i]);
            start = i + 1;
        }
    }
    out.push(&s[start..]);
    out
}

/// The certificate to attribute to a host: the leaf it served live (resolved
/// through the CT map for CT ids and merged facts), or the covering CT
/// certificate with the latest expiry.
fn host_cert(state: &DomainState, host: &Host) -> Option<(CertNode, &'static str)> {
    if let Some(served) = host.endpoint.as_ref().and_then(|e| e.served.as_ref()) {
        let facts = match state.certs.get(&served.serial) {
            Some(ct) => CertFacts {
                common_name: ct.common_name.clone(),
                serial: &served.serial,
                ct_id: ct.ct_ids.first().copied(),
                cert_signature: ct.cert_signature.clone(),
                key_alg: ct.key_algorithm.as_deref(),
                key_size: ct.key_size,
                curve: None,
                issuer: ct.issuer.clone(),
                identities: ct.identities.clone(),
                not_before: ct.not_before,
                not_after: ct.not_after,
                chain: ct.chain.clone(),
            },
            None => CertFacts {
                common_name: served.common_name.clone(),
                serial: &served.serial,
                ct_id: None,
                cert_signature: served.cert_signature.clone(),
                key_alg: served.pubkey_alg.as_deref(),
                key_size: None,
                curve: served.pubkey_curve.as_deref(),
                issuer: served.issuer.clone(),
                identities: served.identities.clone(),
                not_before: served.not_before,
                not_after: served.not_after,
                chain: Vec::new(),
            },
        };
        return Some((cert_node(facts), "presents_certificate"));
    }
    let exact: Vec<_> = host
        .ct_refs
        .iter()
        .filter(|r| r.kind == MatchKind::Exact)
        .collect();
    let pool: Vec<_> = if exact.is_empty() {
        host.ct_refs.iter().collect()
    } else {
        exact
    };
    let covering = pool
        .iter()
        .filter_map(|r| state.certs.get(&r.serial))
        .max_by_key(|c| c.not_after)?;
    Some((
        cert_node(CertFacts {
            common_name: covering.common_name.clone(),
            serial: &covering.serial,
            ct_id: covering.ct_ids.first().copied(),
            cert_signature: covering.cert_signature.clone(),
            key_alg: covering.key_algorithm.as_deref(),
            key_size: covering.key_size,
            curve: None,
            issuer: covering.issuer.clone(),
            identities: covering.identities.clone(),
            not_before: covering.not_before,
            not_after: covering.not_after,
            chain: covering.chain.clone(),
        }),
        "certificate_for",
    ))
}

pub fn graph(state: &DomainState) -> String {
    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    let mut links: BTreeSet<(String, String, &'static str)> = BTreeSet::new();

    let node = |nodes: &mut BTreeMap<String, Node>,
                id: &str,
                label: String,
                node_type: &'static str,
                group: &'static str| {
        nodes.entry(id.to_string()).or_insert_with(|| Node {
            id: id.to_string(),
            label,
            node_type,
            group: (group != node_type).then_some(group),
            metadata: None,
        });
    };

    for host in state.hosts.values() {
        let exposed = matches!(
            host.endpoint.as_ref().map(|e| &e.status),
            Some(ProbeStatus::Ok)
        );
        let host_id = format!("host:{}", host.name);
        nodes.entry(host_id.clone()).or_insert_with(|| Node {
            id: host_id.clone(),
            label: host.name.clone(),
            node_type: "host",
            group: None,
            metadata: None,
        });

        if exposed {
            node(
                &mut nodes,
                "service:tcp/443",
                "TCP/443".to_string(),
                "service",
                "tcp_service",
            );
            links.insert((host_id.clone(), "service:tcp/443".to_string(), "exposes"));
        }
        for scan in &host.ports {
            if scan.state != crate::model::ScanState::Open {
                continue;
            }
            let id = format!("service:tcp/{}", scan.port);
            let label = format!("{}:{}", crate::model::port_service(scan.port), scan.port);
            node(&mut nodes, &id, label, "service", "tcp_service");
            links.insert((host_id.clone(), id, "exposes"));
        }

        if let Some(negotiated) = host.endpoint.as_ref().and_then(|e| e.negotiated.as_ref()) {
            if let Some(kx) = &negotiated.kx_group {
                let id = format!("kx:{kx}");
                node(&mut nodes, &id, kx.clone(), "crypto", "key_exchange");
                links.insert((host_id.clone(), id, "negotiated_kx"));
            }
            if let Some(cipher) = &negotiated.cipher {
                if let Some(sym) = crate::model::symmetric_name(cipher) {
                    let id = format!("cipher:{sym}");
                    node(&mut nodes, &id, sym.clone(), "crypto", "symmetric");
                    links.insert((host_id.clone(), id, "symmetric_cipher"));
                }
            }
        }

        if let Some((cert, cert_edge)) = host_cert(state, host) {
            node(
                &mut nodes,
                &cert.id,
                cert.label.clone(),
                "pki",
                "certificate",
            );
            if let Some(metadata) = cert.metadata {
                if let Some(existing) = nodes.get_mut(&cert.id) {
                    existing.metadata = Some(metadata);
                }
            }
            links.insert((host_id.clone(), cert.id.clone(), cert_edge));

            if let Some(sig) = cert.cert_signature {
                let id = format!("certsig:{sig}");
                node(
                    &mut nodes,
                    &id,
                    sig.clone(),
                    "crypto",
                    "certificate_signature",
                );
                links.insert((cert.id.clone(), id, "cert_signature"));
            }
            if let Some(key) = cert.cert_key {
                let id = format!("certkey:{key}");
                node(&mut nodes, &id, key.clone(), "crypto", "certificate_key");
                links.insert((cert.id.clone(), id, "cert_key"));
            }
            let mut prev_ca: Option<String> = cert
                .issuer
                .as_deref()
                .map(|dn| format!("ca:{}", ca_slug(&ca_cn(dn))));
            if let Some(issuer) = cert.issuer {
                let (ca_id, ca_label) = ca_id(&issuer);
                node(&mut nodes, &ca_id, ca_label, "pki", "issuer");
                links.insert((cert.id.clone(), ca_id, "issued_by"));
            }
            for entry in cert.chain.iter().filter(|e| e.depth >= 1) {
                let Some(cn) = entry.common_name.as_deref().filter(|c| !c.is_empty()) else {
                    continue;
                };
                let ca_id = format!("ca:{}", ca_slug(cn));
                node(&mut nodes, &ca_id, cn.to_string(), "pki", "issuer");
                if let Some(existing) = nodes.get_mut(&ca_id) {
                    existing.metadata = Some(CertMetadata {
                        ca_role: if is_self_issued(entry) {
                            "root"
                        } else {
                            "intermediate"
                        },
                        sans: None,
                        not_before: entry.not_before,
                        not_after: entry.not_after,
                    });
                }
                if let Some(sig) = cert_signature_from_db(
                    entry.key_algorithm.as_deref(),
                    entry.key_size,
                    entry.signature_key_algorithm.as_deref(),
                    entry.signature_hash_algorithm.as_deref(),
                ) {
                    let id = format!("certsig:{sig}");
                    node(
                        &mut nodes,
                        &id,
                        sig.clone(),
                        "crypto",
                        "certificate_signature",
                    );
                    links.insert((ca_id.clone(), id, "cert_signature"));
                }
                if let Some(key) =
                    cert_key_name(entry.key_algorithm.as_deref(), entry.key_size, None)
                {
                    let id = format!("certkey:{key}");
                    node(&mut nodes, &id, key.clone(), "crypto", "certificate_key");
                    links.insert((ca_id.clone(), id, "cert_key"));
                }
                if let Some(prev) = prev_ca {
                    if prev != ca_id {
                        links.insert((prev, ca_id.clone(), "issued_by"));
                    }
                }
                prev_ca = Some(ca_id);
            }
        }
    }

    let graph = Graph {
        nodes: nodes.into_values().collect(),
        links: links
            .into_iter()
            .map(|(source, target, label)| Link {
                source,
                target,
                label,
            })
            .collect(),
    };
    serde_json::to_string_pretty(&graph)
        .unwrap_or_else(|_| "{\"nodes\":[],\"links\":[]}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixture;

    type Edge = (String, String, String);

    fn edges(json: &str) -> Vec<Edge> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                (
                    l["source"].as_str().unwrap().to_string(),
                    l["label"].as_str().unwrap().to_string(),
                    l["target"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn exposed_host_has_full_edge_set() {
        let state = fixture();
        let json = graph(&state);
        let e = edges(&json);
        assert!(e.contains(&(
            "host:www.nbp.pl".to_string(),
            "negotiated_kx".to_string(),
            "kx:X25519MLKEM768".to_string()
        )));
        assert!(e.contains(&(
            "host:www.nbp.pl".to_string(),
            "symmetric_cipher".to_string(),
            "cipher:AES256-GCM".to_string()
        )));
        assert!(e.contains(&(
            "host:www.nbp.pl".to_string(),
            "exposes".to_string(),
            "service:tcp/443".to_string()
        )));
        assert!(e.contains(&(
            "host:www.nbp.pl".to_string(),
            "presents_certificate".to_string(),
            "cert:www.nbp.pl:9612296601".to_string()
        )));
        assert!(e.contains(&(
            "cert:www.nbp.pl:9612296601".to_string(),
            "cert_signature".to_string(),
            "certsig:RSA-SHA256".to_string()
        )));
        assert!(e.contains(&(
            "cert:www.nbp.pl:9612296601".to_string(),
            "cert_key".to_string(),
            "certkey:RSA-2048".to_string()
        )));
        assert!(e.contains(&(
            "cert:www.nbp.pl:9612296601".to_string(),
            "issued_by".to_string(),
            "ca:digicert-tls-rsa-sha256-2020-ca-1".to_string()
        )));
        assert!(e.contains(&(
            "ca:digicert-tls-rsa-sha256-2020-ca-1".to_string(),
            "issued_by".to_string(),
            "ca:digicert-global-root-ca".to_string()
        )));
        assert!(e.contains(&(
            "ca:digicert-tls-rsa-sha256-2020-ca-1".to_string(),
            "cert_signature".to_string(),
            "certsig:RSA-SHA256".to_string()
        )));
        assert!(e.contains(&(
            "ca:digicert-tls-rsa-sha256-2020-ca-1".to_string(),
            "cert_key".to_string(),
            "certkey:RSA-2048".to_string()
        )));
        assert!(e.contains(&(
            "ca:digicert-global-root-ca".to_string(),
            "cert_signature".to_string(),
            "certsig:RSA-SHA256".to_string()
        )));
        assert!(!e.iter().any(|(_, l, _)| l == "uses"));
    }

    #[test]
    fn unprobed_hosts_route_through_their_cert() {
        let state = fixture();
        let json = graph(&state);
        let e = edges(&json);
        assert!(e.contains(&(
            "host:vpn.nbp.pl".to_string(),
            "certificate_for".to_string(),
            "cert:*.nbp.pl:9612297416".to_string()
        )));
        assert!(e.contains(&(
            "cert:*.nbp.pl:9612297416".to_string(),
            "cert_signature".to_string(),
            "certsig:ECDSA-P256".to_string()
        )));
        assert!(e.contains(&(
            "cert:*.nbp.pl:9612297416".to_string(),
            "cert_key".to_string(),
            "certkey:EC-256".to_string()
        )));
        assert!(e.contains(&(
            "host:old.nbp.pl".to_string(),
            "certificate_for".to_string(),
            "cert:*.nbp.pl:9612297416".to_string()
        )));
        assert!(
            !e.iter()
                .any(|(s, l, _)| s == "host:vpn.nbp.pl" && *l != "certificate_for")
        );
    }

    #[test]
    fn exact_cert_match_outranks_the_wildcard() {
        let state = fixture();
        let e = edges(&graph(&state));
        assert!(e.contains(&(
            "host:eas.nbp.pl".to_string(),
            "certificate_for".to_string(),
            "cert:eas.nbp.pl:9612300001".to_string()
        )));
        assert!(!e.contains(&(
            "host:eas.nbp.pl".to_string(),
            "certificate_for".to_string(),
            "cert:*.nbp.pl:9612297416".to_string()
        )));
    }

    #[test]
    fn fact_nodes_are_deduplicated() {
        let state = fixture();
        let json = graph(&state);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ids: Vec<&str> = v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len(), "duplicate node ids in {ids:?}");
        assert_eq!(ids.iter().filter(|i| **i == "service:tcp/443").count(), 1);
        assert_eq!(
            ids.iter()
                .filter(|i| **i == "cert:www.nbp.pl:9612296601")
                .count(),
            1
        );
        assert_eq!(
            ids.iter()
                .filter(|i| **i == "ca:digicert-tls-rsa-sha256-2020-ca-1")
                .count(),
            1
        );
    }

    #[test]
    fn nodes_carry_semantic_metadata() {
        let state = fixture();
        let json = graph(&state);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let find = |id: &str| {
            v["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["id"] == id)
                .unwrap()
                .clone()
        };
        let host = find("host:www.nbp.pl");
        assert_eq!(host["type"], "host");
        assert!(host.get("group").is_none());
        assert!(host.get("axis").is_none());
        assert_eq!(host["label"], "www.nbp.pl");
        let kx = find("kx:X25519MLKEM768");
        assert_eq!(kx["type"], "crypto");
        assert_eq!(kx["group"], "key_exchange");
        let cipher = find("cipher:AES256-GCM");
        assert_eq!(cipher["type"], "crypto");
        assert_eq!(cipher["group"], "symmetric");
        let svc = find("service:tcp/465");
        assert_eq!(svc["type"], "service");
        assert_eq!(svc["group"], "tcp_service");
        assert_eq!(svc["label"], "SMTPS:465");
        let cert = find("cert:www.nbp.pl:9612296601");
        assert_eq!(cert["type"], "pki");
        assert_eq!(cert["group"], "certificate");
        assert_eq!(cert["label"], "www.nbp.pl +1 SAN");
        assert_eq!(cert["metadata"]["ca_role"], "leaf");
        assert_eq!(cert["metadata"]["sans"], serde_json::json!(["nbp.pl"]));
        assert!(cert["metadata"]["not_before"].is_string());
        assert!(cert["metadata"]["not_after"].is_string());
        let inter = find("ca:digicert-tls-rsa-sha256-2020-ca-1");
        assert_eq!(inter["metadata"]["ca_role"], "intermediate");
        assert!(inter["metadata"]["not_before"].is_string());
        let root = find("ca:digicert-global-root-ca");
        assert_eq!(root["metadata"]["ca_role"], "root");
        let sig = find("certsig:RSA-SHA256");
        assert_eq!(sig["type"], "crypto");
        assert_eq!(sig["group"], "certificate_signature");
        let key = find("certkey:RSA-2048");
        assert_eq!(key["type"], "crypto");
        assert_eq!(key["group"], "certificate_key");
        assert_eq!(key["label"], "RSA-2048");
        let ca = find("ca:digicert-tls-rsa-sha256-2020-ca-1");
        assert_eq!(ca["type"], "pki");
        assert_eq!(ca["group"], "issuer");
        assert_eq!(ca["label"], "DigiCert TLS RSA SHA256 2020 CA-1");
        let service = find("service:tcp/443");
        assert_eq!(service["type"], "service");
        assert_eq!(service["group"], "tcp_service");
        assert_eq!(service["label"], "TCP/443");
    }

    #[test]
    fn unprobed_hosts_route_through_their_cert_semantics() {
        let state = fixture();
        let json = graph(&state);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let vpn = v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == "host:vpn.nbp.pl")
            .unwrap()
            .clone();
        assert_eq!(vpn["type"], "host");
        assert!(vpn.get("group").is_none());
    }
}
