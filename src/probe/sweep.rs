use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use chrono::Utc;

use crate::config::Config;
use crate::model::{PortScan, ProbeStatus, ScanState};

use super::probe_one;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    DirectTls,
    StartTls,
}

const GENERIC_WEB: &[(u16, PortKind)] = &[
    (8443, PortKind::DirectTls),
    (9443, PortKind::DirectTls),
    (4443, PortKind::DirectTls),
    (8843, PortKind::DirectTls),
    (10000, PortKind::DirectTls),
];

pub const PORT_CAP: usize = 5;

pub fn ports_for_host(name: &str, generic_override: &[u16], is_mx: bool) -> Vec<(u16, PortKind)> {
    let label = name.split('.').next().unwrap_or("").to_ascii_lowercase();
    let table: &[(u16, PortKind)] =
        if is_mx || starts_any(&label, &["smtp", "mx", "mailrelay", "mailout", "post"]) {
            &[
                (465, PortKind::DirectTls),
                (587, PortKind::StartTls),
                (25, PortKind::StartTls),
            ]
        } else if starts_any(&label, &["imap", "webmail", "mail"]) {
            &[
                (993, PortKind::DirectTls),
                (995, PortKind::DirectTls),
                (465, PortKind::DirectTls),
                (587, PortKind::StartTls),
            ]
        } else if label.starts_with("pop") {
            &[(995, PortKind::DirectTls)]
        } else if starts_any(&label, &["sip", "sips"]) {
            &[(5061, PortKind::DirectTls)]
        } else if starts_any(&label, &["ldap", "ldaps", "directory"]) {
            &[(636, PortKind::DirectTls)]
        } else if starts_any(&label, &["mqtt", "broker"]) {
            &[(8883, PortKind::DirectTls)]
        } else if starts_any(&label, &["xmpp", "jabber", "conference", "chat"]) {
            &[(5222, PortKind::StartTls), (5223, PortKind::DirectTls)]
        } else if generic_override.is_empty() {
            GENERIC_WEB
        } else {
            return generic_override
                .iter()
                .take(PORT_CAP)
                .map(|p| (*p, PortKind::DirectTls))
                .collect();
        };
    table.iter().take(PORT_CAP).copied().collect()
}

fn starts_any(label: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| label.starts_with(p))
}

async fn tcp_connect(ip: IpAddr, port: u16, timeout: Duration) -> ScanState {
    let fut = async {
        match tokio::net::TcpStream::connect(SocketAddr::new(ip, port)).await {
            Ok(_) => ScanState::Open,
            Err(e) => match super::classify_io(&e) {
                super::Failure::TcpRefused => ScanState::Closed,
                _ => ScanState::Filtered,
            },
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Err(_) => ScanState::Filtered,
        Ok(state) => state,
    }
}

pub async fn sweep_host(
    host: &str,
    ip: IpAddr,
    ports: &[(u16, PortKind)],
    cfg: &Config,
) -> Vec<PortScan> {
    let mut out = Vec::new();
    for (port, kind) in ports {
        let port = *port;
        let mut scan = PortScan {
            port,
            state: tcp_connect(ip, port, cfg.sweep_connect_timeout).await,
            served: None,
            negotiated: None,
            observed_at: Some(Utc::now()),
        };
        if scan.state == ScanState::Open && *kind == PortKind::DirectTls {
            let ep = probe_one(host, Some(ip), port, cfg).await;
            if ep.status == ProbeStatus::Ok {
                scan.served = ep.served;
                scan.negotiated = ep.negotiated;
            }
        } else if scan.state == ScanState::Open
            && *kind == PortKind::StartTls
            && matches!(port, 25 | 587)
        {
            let owned = host.to_string();
            let timeout = cfg.probe_timeout;
            let attempt = tokio::time::timeout(
                timeout,
                tokio::task::spawn_blocking(move || {
                    super::tls::openssl_starttls_smtp(&owned, Some(ip), port, timeout)
                }),
            )
            .await;
            if let Ok(Ok(Ok((served, negotiated)))) = attempt {
                scan.served = Some(served);
                scan.negotiated = Some(negotiated);
            }
        }
        out.push(scan);
        tokio::time::sleep(pacing(cfg.sweep_delay_ms)).await;
    }
    out
}

fn pacing(base_ms: u64) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.subsec_nanos() as u64)
        .unwrap_or(0);
    let jitter = base_ms * 3 / 4 + (nanos % (base_ms / 2).max(1));
    Duration::from_millis(jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_matching_is_ordered() {
        let smtp = ports_for_host("mx1c.nbp.pl", &[], false);
        assert_eq!(smtp.len(), 3);
        assert_eq!(smtp[0].0, 465);
        assert!(matches!(smtp[1].1, PortKind::StartTls));

        let mail = ports_for_host("webmail.example.pl", &[], false);
        assert_eq!(mail[0].0, 993);
        assert_eq!(mail.len(), 4);

        let xmpp = ports_for_host("conference.mbank.pl", &[], false);
        assert_eq!(
            xmpp.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![5222, 5223]
        );

        let web = ports_for_host("vpn.example.pl", &[], false);
        assert_eq!(
            web.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![8443, 9443, 4443, 8843, 10000]
        );
        assert_eq!(web.len(), PORT_CAP);
    }

    #[test]
    fn generic_override_replaces_web_list() {
        let ports = ports_for_host("vpn.example.pl", &[7000, 7001, 7002], false);
        assert_eq!(
            ports.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![7000, 7001, 7002]
        );
        let smtp = ports_for_host("mx.example.pl", &[7000], false);
        assert_eq!(smtp[0].0, 465);
    }

    #[test]
    fn port_cap_holds_for_every_family() {
        for name in [
            "mx.a.pl",
            "mail.a.pl",
            "pop.a.pl",
            "sip.a.pl",
            "ldap.a.pl",
            "mqtt.a.pl",
            "xmpp.a.pl",
            "web.a.pl",
        ] {
            assert!(ports_for_host(name, &[], false).len() <= PORT_CAP, "{name}");
        }
    }
}
