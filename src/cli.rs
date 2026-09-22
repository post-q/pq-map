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
  --refresh   force a fresh CT snapshot (bypasses the 7-day cache)
  --no-probe  skip live TLS probing
  -h, --help  this help
";

pub fn run() -> i32 {
    let mut domain: Option<String> = None;
    let mut mode = Mode::Combined;
    let mut refresh = false;
    let mut probe = true;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--refresh" => refresh = true,
            "--no-probe" => probe = false,
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

    let Some(domain) = domain else {
        eprint!("{USAGE}");
        return 2;
    };
    let domain = domain.to_lowercase();
    let domain = domain.strip_suffix('.').unwrap_or(&domain).to_string();

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

    match runtime.block_on(collect::collect(&domain, &cfg, &Options { refresh, probe })) {
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
