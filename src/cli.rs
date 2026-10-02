use crate::collect::{self, Options};
use crate::config::Config;
use crate::render;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Combined,
    Summary,
    Hosts,
    Certs,
    Graph,
    Json,
}

const USAGE: &str = "\
Usage:
  pq-map DOMAIN [--refresh] [--no-probe] [--summary|--hosts|--certs|--graph|--json]

Modes:
  (default)   combined text view: names, hosts, services, DNS records
  --summary   certificate estate summary
  --hosts     concrete hostnames of currently valid certificates
  --certs     CT certificate records table
  --graph     host/crypto edges as JSON for 3d-force-graph
  --json      full state as JSON

Options:
  --refresh   force a fresh CT snapshot (bypasses the 30-day cache)
  --no-probe  skip live TLS probing
  --ports     discover services on alternative ports for hosts whose 443 is
              closed: family-driven port list (mx -> 465/587/25, mail -> 993/995/
              465/587, ...) or explicit comma LIST (--ports=80,8443)
  -h, --help  this help
";

pub fn normalize_domain(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let raw = raw.strip_prefix("*.").unwrap_or(raw);
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let url = url::Url::parse(&candidate).ok()?;
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let host = match host.strip_prefix("www.") {
        Some(rest) if rest.contains('.') => rest.to_string(),
        _ => host,
    };
    (!host.is_empty()).then_some(host)
}

pub fn run() -> i32 {
    let mut domain: Option<String> = None;
    let mut mode = Mode::Combined;
    let mut refresh = false;
    let mut probe = true;
    let mut ports: Option<Vec<u16>> = None;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--refresh" => refresh = true,
            "--no-probe" => probe = false,
            "--ports" => ports = Some(Vec::new()),
            other if other.starts_with("--ports=") => {
                let list = other
                    .trim_start_matches("--ports=")
                    .split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect::<Vec<u16>>();
                if list.is_empty() {
                    eprintln!("ERROR: --ports=LIST requires a comma-separated port list");
                    return 2;
                }
                ports = Some(list);
            }
            "--summary" => mode = Mode::Summary,
            "--hosts" => mode = Mode::Hosts,
            "--certs" => mode = Mode::Certs,
            "--graph" => mode = Mode::Graph,
            "--json" => mode = Mode::Json,
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            other if other.starts_with("--") => {
                eprintln!("ERROR: unknown option: {other}");
                eprint!("{USAGE}");
                return 2;
            }
            other => {
                if domain.is_none() {
                    domain = Some(other.to_string());
                } else {
                    eprintln!("ERROR: unexpected argument: {other}");
                    eprint!("{USAGE}");
                    return 2;
                }
            }
        }
    }

    let Some(raw) = domain else {
        eprint!("{USAGE}");
        return 2;
    };
    let Some(domain) = normalize_domain(&raw) else {
        eprintln!("ERROR: cannot derive a domain from: {raw}");
        return 2;
    };

    let cfg = Config::from_env();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ERROR: cannot start async runtime: {e}");
            return 1;
        }
    };

    match runtime.block_on(collect::collect(
        &domain,
        &cfg,
        &Options {
            refresh,
            probe,
            ports,
        },
    )) {
        Ok(state) => {
            match mode {
                Mode::Combined => print!("{}", render::text::combined(&state)),
                Mode::Summary => print!("{}", render::text::summary(&state)),
                Mode::Hosts => print!("{}", render::text::hosts(&state)),
                Mode::Certs => print!("{}", render::text::certs(&state)),
                Mode::Graph => println!("{}", render::graph::graph(&state)),
                Mode::Json => match serde_json::to_string_pretty(&state) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("ERROR: JSON serialization failed: {e}");
                        return 1;
                    }
                },
            }
            0
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_domain;

    #[test]
    fn strips_scheme_path_and_www() {
        assert_eq!(
            normalize_domain("https://www.example.com/").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn accepts_bare_hosts_and_ports() {
        assert_eq!(normalize_domain("nbp.pl").as_deref(), Some("nbp.pl"));
        assert_eq!(
            normalize_domain("WWW.Example.COM.:8443").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn strips_userinfo_query_and_wildcard() {
        assert_eq!(
            normalize_domain("https://user:pw@example.com:8443/a?b=1#c").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("*.sub.example.com").as_deref(),
            Some("sub.example.com")
        );
    }

    #[test]
    fn keeps_single_label_www_hosts() {
        assert_eq!(normalize_domain("www.com").as_deref(), Some("www.com"));
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(normalize_domain("   "), None);
    }
}
