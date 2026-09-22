use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{Local, Utc};
use futures::StreamExt;

use crate::config::Config;
use crate::discover::{ct, dns, fetch, probe_cache, resolve};
use crate::model::{CtStats, DnsRef, DnsStatus, DomainState, Endpoint, Host, Origins, ProbeStatus};

const TLS_PORT: u16 = 443;

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub refresh: bool,
    pub probe: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Ct(#[from] fetch::Error),
    #[error("DNS resolver unavailable: {0}")]
    Resolver(String),
    #[error("task join failed")]
    Join,
}

pub async fn collect(domain: &str, cfg: &Config, opts: &Options) -> Result<DomainState, Error> {
    // 1. CT snapshot.
    let outcome = fetch::obtain(domain, cfg, opts.refresh).await?;
    let certs = outcome.certs;
    let ct_stats = ct_stats(&certs);

    // 2. DNS: SRV sweep + SVCB/HTTPS on the apex.
    let resolver = dns::build_resolver(cfg).map_err(|e| Error::Resolver(e.to_string()))?;
    let discovery = dns::discover(domain, &resolver).await;

    // 3. Host set: concrete CT names ∪ apex ∪ in-domain SRV targets.
    let mut hosts: BTreeMap<String, Host> = BTreeMap::new();
    for cert in certs.values().filter(|c| c.currently_valid) {
        for name in &cert.identities {
            if !ct::is_wildcard(name) {
                let host = hosts.entry(name.clone()).or_default();
                host.name = name.clone();
                host.origins.insert(Origins::CT);
            }
        }
    }
    let apex = hosts.entry(domain.to_string()).or_default();
    apex.name = domain.to_string();
    apex.origins.insert(Origins::APEX);
    for rec in &discovery.srv {
        if dns::in_domain(&rec.target, domain) {
            let host = hosts.entry(rec.target.clone()).or_default();
            host.name = rec.target.clone();
            host.origins.insert(Origins::DNS);
            host.dns_refs.push(DnsRef::Srv {
                service: rec.service.clone(),
            });
        }
    }

    // 4. CT coverage per host (exact / wildcard refs).
    for host in hosts.values_mut() {
        host.ct_refs = ct::cert_refs(&certs, &host.name);
    }

    // 5. Resolve every host concurrently, capturing the response status.
    let resolution: Vec<(String, Option<IpAddr>, DnsStatus)> =
        futures::stream::iter(hosts.keys().map(|name| {
            let resolver = resolver.clone();
            let name = name.clone();
            async move {
                let (ip, status) = resolve::resolve_status(&resolver, &name).await;
                (name, ip, status)
            }
        }))
        .buffer_unordered(cfg.dns_concurrency)
        .collect()
        .await;

    for (name, ip, status) in &resolution {
        let host = hosts.get_mut(name).expect("host from map");
        host.resolves = Some(ip.is_some());
        host.dns_status = Some(*status);
    }

    // 6. Probe resolving hosts.
    if opts.probe {
        let snapshot = if opts.refresh {
            None
        } else {
            probe_cache::load(domain)
        };
        let now = Utc::now();
        let cached: BTreeMap<String, Endpoint> = snapshot
            .map(|s| {
                s.probes
                    .into_iter()
                    .filter(|(_, ep)| probe_cache::is_fresh(ep, cfg.probe_cache_ttl, now))
                    .collect()
            })
            .unwrap_or_default();

        let endpoints: Vec<(String, Endpoint, bool)> =
            futures::stream::iter(resolution.iter().map(|(name, ip, _)| {
                let name = name.clone();
                let hit = if ip.is_some() {
                    cached.get(&name).filter(|ep| ep.ip.is_some()).cloned()
                } else {
                    None
                };
                async move {
                    match hit {
                        Some(endpoint) => (name, endpoint, true),
                        None => {
                            let endpoint = if ip.is_some() {
                                crate::probe::probe_one(&name, *ip, TLS_PORT, cfg).await
                            } else {
                                Endpoint::failed(ProbeStatus::DnsFailure)
                            };
                            (name, endpoint, false)
                        }
                    }
                }
            }))
            .buffer_unordered(cfg.probe_concurrency)
            .collect()
            .await;

        let (mut cached_n, mut fresh_n, mut oldest_cached_secs) = (0usize, 0usize, 0u64);
        for (name, endpoint, hit) in endpoints {
            if hit {
                cached_n += 1;
                if let Some(t) = endpoint.observed_at {
                    oldest_cached_secs =
                        oldest_cached_secs.max((now - t).num_seconds().max(0) as u64);
                }
            } else {
                fresh_n += 1;
            }
            if let Some(host) = hosts.get_mut(&name) {
                host.endpoint = Some(endpoint);
            }
        }

        let probes: BTreeMap<String, Endpoint> = hosts
            .values()
            .filter_map(|h| h.endpoint.clone().map(|ep| (h.name.clone(), ep)))
            .collect();
        probe_cache::store(domain, &probes);

        if cached_n > 0 {
            eprintln!(
                "probes: {cached_n} cached ({} min old), {fresh_n} probed fresh",
                oldest_cached_secs / 60
            );
        } else {
            eprintln!("probes: {fresh_n} probed fresh");
        }
    }

    // 7. Correlate served certificates with CT; propagate signature facts.
    let mut certs = certs;
    for host in hosts.values() {
        let Some(served) = host.endpoint.as_ref().and_then(|e| e.served.as_ref()) else {
            continue;
        };
        if let Some(cert) = certs.get_mut(&served.serial) {
            cert.served_live = true;
            if cert.cert_signature.is_none() {
                cert.cert_signature = served.cert_signature.clone();
            }
            if cert.pubkey_alg.is_none() {
                cert.pubkey_alg = served.pubkey_alg.clone();
            }
            if cert.sig_alg.is_none() {
                cert.sig_alg = served.sig_alg.clone();
            }
        }
    }
    for host in hosts.values_mut() {
        if let Some(endpoint) = &mut host.endpoint {
            if let Some(served) = &endpoint.served {
                endpoint.served_not_in_ct = !certs.contains_key(&served.serial);
            }
        }
    }

    Ok(DomainState {
        domain: domain.to_string(),
        checked_at: Local::now(),
        provenance: outcome.provenance,
        ct_stats,
        certs,
        hosts,
        srv: discovery.srv,
        https: discovery.https,
    })
}

fn ct_stats(certs: &BTreeMap<String, crate::model::Certificate>) -> CtStats {
    let now = Utc::now();
    let mut stats = CtStats {
        rows: certs.len(),
        valid: 0,
        future: 0,
    };
    for cert in certs.values() {
        if cert.currently_valid {
            stats.valid += 1;
        } else if ct::future_valid(cert.not_before, now) {
            stats.future += 1;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Certificate;

    fn cert(serial: &str, nb: &str, na: &str) -> Certificate {
        let parse = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&Utc)
        };
        let (nb, na) = (Some(parse(nb)), Some(parse(na)));
        Certificate {
            serial: serial.to_string(),
            in_ct: true,
            served_live: false,
            currently_valid: ct::currently_valid(nb, na, Utc::now()),
            ct_ids: vec![1],
            common_name: None,
            identities: vec![],
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
        }
    }

    #[test]
    fn ct_stats_counts_grouped_certs() {
        let mut certs = BTreeMap::new();
        certs.insert(
            "aa11".to_string(),
            cert("aa11", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
        );
        certs.insert(
            "bb22".to_string(),
            cert("bb22", "2027-06-01T00:00:00Z", "2028-01-01T00:00:00Z"),
        );
        certs.insert(
            "cc33".to_string(),
            cert("cc33", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
        );
        let stats = ct_stats(&certs);
        assert_eq!(stats.rows, 3);
        assert_eq!(stats.valid, 1);
        assert_eq!(stats.future, 1);
    }
}
