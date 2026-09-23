use hickory_proto::rr::Record;
use hickory_proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::system_conf::read_system_conf;

use crate::config::Config;
use crate::model::{HttpsRecord, MxRecord, SrvRecord};

pub const SRV_SERVICES: &[(&str, &str)] = &[
    ("_ldap._tcp", "LDAP"),
    ("_ldaps._tcp", "LDAPS"),
    ("_kerberos._tcp", "Kerberos/TCP"),
    ("_kerberos._udp", "Kerberos/UDP"),
    ("_sip._tcp", "SIP/TCP"),
    ("_sip._udp", "SIP/UDP"),
    ("_sip._tls", "SIP/TLS"),
    ("_xmpp-client._tcp", "XMPP client"),
    ("_xmpp-server._tcp", "XMPP server"),
    ("_matrix-fed._tcp", "Matrix federation"),
];

#[derive(Debug, Default)]
pub struct DnsDiscovery {
    pub srv: Vec<SrvRecord>,
    pub https: Vec<HttpsRecord>,
    pub mx: Vec<MxRecord>,
}

pub fn service_label(service: &str) -> &str {
    SRV_SERVICES
        .iter()
        .find(|(s, _)| *s == service)
        .map(|(_, label)| *label)
        .unwrap_or(service)
}

pub fn build_resolver(cfg: &Config) -> std::io::Result<TokioAsyncResolver> {
    let (config, mut opts) = read_system_conf()?;
    opts.timeout = cfg.dns_timeout;
    opts.attempts = cfg.dns_attempts;
    Ok(TokioAsyncResolver::tokio(config, opts))
}

/// SRV sweep over the well-known service prefixes plus SVCB/HTTPS on the apex.
/// Individual query failures are logged, never fatal (parity with dig-based sweep).
pub async fn discover(domain: &str, resolver: &TokioAsyncResolver) -> DnsDiscovery {
    let mut out = DnsDiscovery::default();

    let sweeps = futures::future::join_all(SRV_SERVICES.iter().map(|(service, _)| async move {
        let fqdn = format!("{service}.{domain}");
        let records = query(resolver, &fqdn, RecordType::SRV).await;
        (service, fqdn, records)
    }))
    .await;

    for (service, fqdn, records) in sweeps {
        for record in records {
            if let Some(rec) = srv_from_record(service, &fqdn, &record) {
                out.srv.push(rec);
            }
        }
    }
    out.srv
        .sort_by(|a, b| (&a.fqdn, a.priority).cmp(&(&b.fqdn, b.priority)));

    for rr in [RecordType::SVCB, RecordType::HTTPS] {
        let rr_name = rr_name(rr);
        for record in query(resolver, domain, rr).await {
            if let Some(rec) = rr_from_record(rr_name, &record) {
                out.https.push(rec);
            }
        }
    }

    for record in query(resolver, domain, RecordType::MX).await {
        if let Some(rec) = mx_from_record(&record) {
            out.mx.push(rec);
        }
    }
    out.mx
        .sort_by(|a, b| (a.priority, a.target.clone()).cmp(&(b.priority, b.target.clone())));

    out
}

fn rr_name(rr: RecordType) -> &'static str {
    match rr {
        RecordType::SVCB => "SVCB",
        RecordType::HTTPS => "HTTPS",
        _ => "SVCB",
    }
}

async fn query(resolver: &TokioAsyncResolver, name: &str, rr: RecordType) -> Vec<Record> {
    match resolver.lookup(name, rr).await {
        Ok(lookup) => lookup.records().to_vec(),
        Err(e) => {
            if !matches!(
                e.kind(),
                hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. }
            ) {
                eprintln!("DNS: {} {} query failed: {e}", rr_name(rr), name);
            }
            Vec::new()
        }
    }
}

pub fn strip_dot(target: &str) -> String {
    if target == "." {
        ".".to_string()
    } else {
        target.trim_end_matches('.').to_lowercase()
    }
}

pub fn srv_from_record(service: &str, fqdn: &str, record: &Record) -> Option<SrvRecord> {
    let hickory_proto::rr::RData::SRV(srv) = record.data()? else {
        return None;
    };
    Some(SrvRecord {
        service: service.to_string(),
        fqdn: fqdn.to_string(),
        priority: u32::from(srv.priority()),
        weight: u32::from(srv.weight()),
        port: srv.port(),
        target: strip_dot(&srv.target().to_string()),
    })
}

pub fn mx_from_record(record: &Record) -> Option<MxRecord> {
    let hickory_proto::rr::RData::MX(mx) = record.data()? else {
        return None;
    };
    Some(MxRecord {
        priority: u32::from(mx.preference()),
        target: strip_dot(&mx.exchange().to_string()),
    })
}

pub fn rr_from_record(rr_type: &str, record: &Record) -> Option<HttpsRecord> {
    let svcb = match record.data()? {
        hickory_proto::rr::RData::SVCB(s) => s,
        hickory_proto::rr::RData::HTTPS(s) => &s.0,
        _ => return None,
    };
    Some(HttpsRecord {
        rr_type: rr_type.to_string(),
        priority: svcb.svc_priority(),
        target: strip_dot(&svcb.target_name().to_string()),
        params: params_string(svcb.svc_params()),
    })
}

fn params_string(
    params: &[(
        hickory_proto::rr::rdata::svcb::SvcParamKey,
        hickory_proto::rr::rdata::svcb::SvcParamValue,
    )],
) -> String {
    use hickory_proto::rr::rdata::svcb::SvcParamValue;
    params
        .iter()
        .map(|(key, value)| match value {
            SvcParamValue::NoDefaultAlpn => key.to_string(),
            _ => format!("{key}={value}"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn in_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn alpn_param(params: &str) -> Option<String> {
    params
        .split_whitespace()
        .find_map(|token| token.strip_prefix("alpn="))
        .map(|v| v.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn strip_dot_variants() {
        assert_eq!(strip_dot("sip.nbp.pl."), "sip.nbp.pl");
        assert_eq!(strip_dot("."), ".");
        assert_eq!(strip_dot("CDN.Example.COM."), "cdn.example.com");
    }

    #[test]
    fn in_domain_boundaries() {
        assert!(in_domain("nbp.pl", "nbp.pl"));
        assert!(in_domain("www.nbp.pl", "nbp.pl"));
        assert!(in_domain("a.b.nbp.pl", "nbp.pl"));
        assert!(!in_domain("anbp.pl", "nbp.pl"));
        assert!(!in_domain("nbp.pl.evil.com", "nbp.pl"));
        assert!(!in_domain("other.pl", "nbp.pl"));
    }

    #[test]
    fn alpn_param_extraction() {
        assert_eq!(alpn_param("alpn=h2,h3").as_deref(), Some("h2,h3"));
        assert_eq!(
            alpn_param("ipv4hint=1.2.3.4 alpn=\"h2,http/1.1\"").as_deref(),
            Some("h2,http/1.1")
        );
        assert_eq!(alpn_param("ipv4hint=1.2.3.4"), None);
        assert_eq!(alpn_param(""), None);
    }

    #[test]
    fn service_labels_cover_table() {
        assert_eq!(service_label("_sip._tls"), "SIP/TLS");
        assert_eq!(service_label("_matrix-fed._tcp"), "Matrix federation");
        assert_eq!(service_label("_unknown._tcp"), "_unknown._tcp");
    }

    #[test]
    fn resolver_build_reads_system_conf() {
        let cfg = Config::from_env();
        let resolver = build_resolver(&cfg);
        assert!(resolver.is_ok());
    }

    #[test]
    fn timeout_is_bounded() {
        let cfg = Config::from_env();
        assert!(cfg.dns_timeout <= Duration::from_secs(30));
    }
}
