use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{Local, Utc};
use futures::StreamExt;

use crate::config::Config;
use crate::discover::{ct, dns, fetch, probe_cache, resolve};
use crate::model::{
    CtStats, DnsRef, DnsStatus, DomainState, Endpoint, Host, Origins, PortScan, ProbeStatus,
    ScanState,
};

const TLS_PORT: u16 = 443;

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub refresh: bool,
    pub probe: bool,
    pub ports: Option<Vec<u16>>,
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
    for rec in &discovery.mx {
        let host = hosts.entry(rec.target.clone()).or_default();
        host.name = rec.target.clone();
        host.origins.insert(Origins::DNS);
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
        let carried_ports: BTreeMap<String, BTreeMap<u16, PortScan>> = snapshot
            .as_ref()
            .map(|s| s.ports.clone())
            .unwrap_or_default();
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
        probe_cache::store(domain, &probes, &carried_ports);

        if cached_n > 0 {
            eprintln!(
                "probes: {cached_n} cached ({} min old), {fresh_n} probed fresh",
                oldest_cached_secs / 60
            );
        } else {
            eprintln!("probes: {fresh_n} probed fresh");
        }
    }

    if opts.probe
        && let Some(explicit_ports) = &opts.ports
    {
        let mx_names: Vec<String> = discovery.mx.iter().map(|rec| rec.target.clone()).collect();
        let snapshot = if opts.refresh {
            None
        } else {
            probe_cache::load(domain)
        };
        let now = Utc::now();
        let carried: BTreeMap<String, BTreeMap<u16, PortScan>> = snapshot
            .as_ref()
            .map(|s| s.ports.clone())
            .unwrap_or_default();
        let cached_ports: BTreeMap<String, BTreeMap<u16, PortScan>> = snapshot
            .map(|s| {
                s.ports
                    .into_iter()
                    .map(|(host, scans)| {
                        (
                            host,
                            scans
                                .into_iter()
                                .filter(|(_, scan)| {
                                    probe_cache::scan_fresh(scan, cfg.sweep_ttl, now)
                                })
                                .collect::<BTreeMap<u16, PortScan>>(),
                        )
                    })
                    .filter(|(_, scans)| !scans.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let mut targets: Vec<(String, IpAddr)> = resolution
            .iter()
            .filter(|(name, ip, _)| {
                ip.is_some()
                    && hosts
                        .get(name)
                        .and_then(|h| h.endpoint.as_ref())
                        .is_some_and(|e| {
                            matches!(
                                e.status,
                                ProbeStatus::TcpRefused
                                    | ProbeStatus::TcpUnreachable
                                    | ProbeStatus::Timeout { .. }
                            )
                        })
            })
            .filter_map(|(name, ip, _)| ip.map(|ip| (name.clone(), ip)))
            .collect();

        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos() as u64)
            .unwrap_or(1);
        for i in (1..targets.len()).rev() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (seed >> 33) as usize % (i + 1);
            targets.swap(i, j);
        }

        let mx_targets = std::sync::Arc::new(
            mx_names
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<String>>(),
        );
        let cached_ports_locked = std::sync::Arc::new(cached_ports);
        let sweep_results: Vec<(String, Vec<PortScan>, usize)> =
            futures::stream::iter(targets.into_iter().map(|(name, ip)| {
                let cached_ports_locked = std::sync::Arc::clone(&cached_ports_locked);
                let mx_targets = std::sync::Arc::clone(&mx_targets);
                async move {
                    let is_mx = mx_targets.contains(&name);
                    let ports = match explicit_ports {
                        list if list.is_empty() => {
                            crate::probe::sweep::ports_for_host(&name, &cfg.probe_ports, is_mx)
                        }
                        list => list
                            .iter()
                            .take(crate::probe::sweep::PORT_CAP)
                            .map(|p| (*p, crate::probe::sweep::PortKind::DirectTls))
                            .collect(),
                    };
                    let mut scans: Vec<PortScan> = Vec::new();
                    for (port, kind) in ports {
                        let cached_hit = cached_ports_locked
                            .get(&name)
                            .and_then(|m| m.get(&port))
                            .filter(|scan| probe_cache::scan_fresh(scan, cfg.sweep_ttl, now))
                            .cloned();
                        if let Some(scan) = cached_hit {
                            scans.push(scan);
                        } else {
                            scans.extend(
                                crate::probe::sweep::sweep_host(&name, ip, &[(port, kind)], cfg)
                                    .await,
                            );
                        }
                    }
                    let fresh = scans
                        .iter()
                        .filter(|s| {
                            cached_ports_locked
                                .get(&name)
                                .and_then(|m| m.get(&s.port))
                                .map(|c| c.observed_at != s.observed_at)
                                .unwrap_or(true)
                        })
                        .count();
                    (name, scans, fresh)
                }
            }))
            .buffer_unordered(cfg.sweep_concurrency)
            .collect()
            .await;

        let (mut fresh_sweeps, mut cached_sweeps, mut open_hosts) = (0usize, 0usize, 0usize);
        let mut ports_map: BTreeMap<String, BTreeMap<u16, PortScan>> = carried;
        for (name, scans, fresh) in sweep_results {
            fresh_sweeps += fresh;
            cached_sweeps += scans.len() - fresh;
            if scans.iter().any(|s| s.state == ScanState::Open) {
                open_hosts += 1;
            }
            if let Some(host) = hosts.get_mut(&name) {
                host.ports = scans.clone();
            }
            let entry = ports_map.entry(name).or_default();
            for scan in scans {
                entry.insert(scan.port, scan);
            }
        }

        let probes: BTreeMap<String, Endpoint> = hosts
            .values()
            .filter_map(|h| h.endpoint.clone().map(|ep| (h.name.clone(), ep)))
            .collect();
        probe_cache::store(domain, &probes, &ports_map);
        eprintln!(
            "ports: {cached_sweeps} cached, {fresh_sweeps} swept fresh, {open_hosts} with open ports"
        );
    }

    // 7. Correlate served certificates with CT; propagate signature facts.
    let mut certs = certs;
    for host in hosts.values() {
        let served_certs = host
            .endpoint
            .as_ref()
            .and_then(|e| e.served.as_ref())
            .into_iter()
            .chain(host.ports.iter().filter_map(|s| s.served.as_ref()));
        for served in served_certs {
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
        mx: discovery.mx,
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
