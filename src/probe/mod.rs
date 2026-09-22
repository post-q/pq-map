pub mod tls;

use std::io::ErrorKind;
use std::net::IpAddr;

use crate::config::Config;
use crate::model::{Endpoint, ProbeStatus};

#[derive(Debug)]
pub enum Failure {
    TcpRefused,
    TcpUnreachable,
    Timeout,
    Handshake(String),
    ClosedNoCert(String),
    Unknown(String),
}

/// Probe one endpoint within PROBE_TIMEOUT: rustls first, OpenSSL fallback
/// only for handshake-class failures (parity with ct-inv2.sh --probe).
pub async fn probe_one(host: &str, ip: Option<IpAddr>, port: u16, cfg: &Config) -> Endpoint {
    let mut endpoint = match tokio::time::timeout(cfg.probe_timeout, tls::attempt(host, ip, port, cfg)).await {
        Err(_) => Endpoint::failed(ProbeStatus::Timeout { secs: cfg.probe_timeout.as_secs() }),
        Ok(Ok((served, negotiated))) => Endpoint {
            status: ProbeStatus::Ok,
            ip,
            served: Some(served),
            served_not_in_ct: false,
            negotiated: Some(negotiated),
            observed_at: None,
        },
        Ok(Err(failure)) => handle_failure(host, ip, port, cfg, failure).await,
    };
    endpoint.ip = ip;
    if endpoint.observed_at.is_none() {
        endpoint.observed_at = Some(chrono::Utc::now());
    }
    endpoint
}

async fn handle_failure(
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
    cfg: &Config,
    failure: Failure,
) -> Endpoint {
    match failure {
        Failure::TcpRefused => Endpoint::failed(ProbeStatus::TcpRefused),
        Failure::TcpUnreachable => Endpoint::failed(ProbeStatus::TcpUnreachable),
        Failure::Timeout => Endpoint::failed(ProbeStatus::Timeout { secs: cfg.probe_timeout.as_secs() }),
        Failure::ClosedNoCert(_) => Endpoint::failed(ProbeStatus::ConnectedNoCert),
        Failure::Unknown(reason) => Endpoint::failed(ProbeStatus::Unknown { reason }),
        Failure::Handshake(_) => openssl_fallback(host, ip, port, cfg).await,
    }
}

async fn openssl_fallback(host: &str, ip: Option<IpAddr>, port: u16, cfg: &Config) -> Endpoint {
    let owned = host.to_string();
    let timeout = cfg.probe_timeout;
    let outcome = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || tls::openssl_attempt(&owned, ip, port, timeout)),
    )
    .await;

    match outcome {
        Err(_) => Endpoint::failed(ProbeStatus::Timeout { secs: timeout.as_secs() }),
        Ok(Err(join)) => Endpoint::failed(ProbeStatus::Unknown { reason: join.to_string() }),
        Ok(Ok(Ok((served, negotiated)))) => Endpoint {
            status: ProbeStatus::Ok,
            ip,
            served: Some(served),
            served_not_in_ct: false,
            negotiated: Some(negotiated),
            observed_at: None,
        },
        Ok(Ok(Err(_reason))) => Endpoint::failed(ProbeStatus::TlsHandshakeFailed),
    }
}

pub(super) fn classify_io(e: &std::io::Error) -> Failure {
    match e.kind() {
        ErrorKind::ConnectionRefused => Failure::TcpRefused,
        ErrorKind::NetworkUnreachable
        | ErrorKind::HostUnreachable
        | ErrorKind::AddrNotAvailable
        | ErrorKind::NotConnected
        | ErrorKind::NetworkDown => Failure::TcpUnreachable,
        ErrorKind::TimedOut | ErrorKind::WouldBlock => Failure::Timeout,
        _ => Failure::Unknown(e.to_string()),
    }
}

/// Map a mid-handshake I/O failure to a probe classification:
/// clean close without certificate vs. broken TLS (alerts, garbage, EOF with data).
pub(super) fn classify_handshake(e: std::io::Error) -> Failure {
    let text = e.to_string();
    match e.kind() {
        // Clean close before the certificate arrived (e.g. plain-TCP service).
        ErrorKind::UnexpectedEof => Failure::ClosedNoCert(text),
        ErrorKind::TimedOut | ErrorKind::WouldBlock => Failure::Timeout,
        // Alerts, protocol garbage, record overflows: everything else.
        _ => Failure::Handshake(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_classification() {
        assert!(matches!(
            classify_io(&std::io::Error::from(ErrorKind::ConnectionRefused)),
            Failure::TcpRefused
        ));
        assert!(matches!(
            classify_io(&std::io::Error::from(ErrorKind::NetworkUnreachable)),
            Failure::TcpUnreachable
        ));
        assert!(matches!(
            classify_io(&std::io::Error::from(ErrorKind::AddrNotAvailable)),
            Failure::TcpUnreachable
        ));
        assert!(matches!(
            classify_io(&std::io::Error::from(ErrorKind::TimedOut)),
            Failure::Timeout
        ));
        assert!(matches!(
            classify_io(&std::io::Error::other("boom")),
            Failure::Unknown(_)
        ));
    }

    #[test]
    fn handshake_eof_is_closed_no_cert() {
        assert!(matches!(
            classify_handshake(std::io::Error::new(ErrorKind::UnexpectedEof, "eof")),
            Failure::ClosedNoCert(_)
        ));
        assert!(matches!(
            classify_handshake(std::io::Error::other("alert")),
            Failure::Handshake(_)
        ));
    }
}
