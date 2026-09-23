use std::env;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub cache_ttl: u64,
    pub retries: u32,
    pub retry_delay: u64,
    pub connect_timeout: u64,
    pub max_time: u64,
    pub db_host: String,
    pub db_port: u16,
    pub db_user: String,
    pub db_name: String,
    pub db_connect_timeout: u64,
    pub db_query_timeout: u64,
    pub probe_cache_ttl: u64,
    pub probe_timeout: Duration,
    pub probe_concurrency: usize,
    pub sweep_connect_timeout: Duration,
    pub sweep_concurrency: usize,
    pub sweep_delay_ms: u64,
    pub sweep_ttl: u64,
    pub probe_ports: Vec<u16>,
    pub dns_timeout: Duration,
    pub dns_attempts: usize,
    pub dns_concurrency: usize,
}

impl Config {
    pub fn from_env() -> Self {
        let var = |name: &str, default: u64| {
            env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        let var_str = |name: &str, default: &str| {
            env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        Self {
            cache_ttl: var("CT_CACHE_TTL", 604_800),
            retries: var("CT_RETRIES", 5).max(1) as u32,
            retry_delay: var("CT_RETRY_DELAY", 2),
            connect_timeout: var("CT_CONNECT_TIMEOUT", 10),
            max_time: var("CT_MAX_TIME", 60),
            db_host: var_str("CT_DB_HOST", "crt.sh"),
            db_port: var("CT_DB_PORT", 5432) as u16,
            db_user: var_str("CT_DB_USER", "guest"),
            db_name: var_str("CT_DB_DB", "certwatch"),
            db_connect_timeout: var("CT_DB_CONNECT_TIMEOUT", 30),
            db_query_timeout: var("CT_DB_QUERY_TIMEOUT", 120),
            probe_cache_ttl: var("PROBE_CACHE_TTL", 86_400),
            probe_timeout: Duration::from_secs(var("PROBE_TIMEOUT", 8)),
            probe_concurrency: var("PROBE_CONCURRENCY", 32).max(1) as usize,
            sweep_connect_timeout: Duration::from_secs(var("SWEEP_CONNECT_TIMEOUT", 1)),
            sweep_concurrency: var("SWEEP_CONCURRENCY", 4).max(1) as usize,
            sweep_delay_ms: var("SWEEP_DELAY_MS", 200),
            sweep_ttl: var("PROBE_SWEEP_TTL", 604_800),
            probe_ports: env::var("PROBE_PORTS")
                .ok()
                .map(|v| v.split(',').filter_map(|p| p.trim().parse().ok()).collect())
                .unwrap_or_default(),
            dns_timeout: Duration::from_secs(var("DNS_TIMEOUT", 5)),
            dns_attempts: var("DNS_ATTEMPTS", 2).max(1) as usize,
            dns_concurrency: var("DNS_CONCURRENCY", 32).max(1) as usize,
        }
    }
}
