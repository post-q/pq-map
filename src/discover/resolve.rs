use std::net::IpAddr;

use hickory_proto::op::ResponseCode;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::error::ResolveErrorKind;

use crate::model::DnsStatus;

/// Resolve a hostname (A/AAAA) and classify the DNS response status.
pub async fn resolve_status(
    resolver: &TokioAsyncResolver,
    host: &str,
) -> (Option<IpAddr>, DnsStatus) {
    match resolver.lookup_ip(host).await {
        Ok(ips) => (ips.iter().next(), DnsStatus::Ok),
        Err(e) => {
            let status = match e.kind() {
                ResolveErrorKind::NoRecordsFound { response_code, .. } => match response_code {
                    ResponseCode::NXDomain => DnsStatus::NxDomain,
                    ResponseCode::NoError => DnsStatus::NoData,
                    ResponseCode::ServFail => DnsStatus::ServFail,
                    ResponseCode::Refused => DnsStatus::Refused,
                    _ => DnsStatus::Other,
                },
                ResolveErrorKind::Timeout => DnsStatus::Timeout,
                _ => DnsStatus::Other,
            };
            (None, status)
        }
    }
}

/// Resolve a hostname to its first address (A or AAAA).
pub async fn resolve_first(resolver: &TokioAsyncResolver, host: &str) -> Option<IpAddr> {
    resolve_status(resolver, host).await.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    fn resolver() -> TokioAsyncResolver {
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    }

    #[tokio::test]
    async fn localhost_resolves() {
        let (ip, status) = resolve_status(&resolver(), "localhost").await;
        assert_eq!(status, DnsStatus::Ok);
        assert!(ip.is_some());
    }

    #[tokio::test]
    async fn bogus_name_is_nxdomain() {
        let (ip, status) = resolve_status(&resolver(), "nonexistent.invalid").await;
        assert_eq!(status, DnsStatus::NxDomain);
        assert!(ip.is_none());
    }
}
