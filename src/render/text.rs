use crate::model::{DomainState, Host, ProbeStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    /// Valid certificate + service observed.
    Exposed,
    /// Valid certificate + DNS exists, service not yet identified.
    Resolving,
    /// Valid certificate + no public DNS.
    PkiOnly,
    /// No valid certificate + no current service signal.
    Unresolved,
}

impl Category {
    const ALL: [Self; 4] = [
        Self::Exposed,
        Self::Resolving,
        Self::PkiOnly,
        Self::Unresolved,
    ];

    fn title(&self) -> &'static str {
        match self {
            Self::Exposed => "EXPOSED",
            Self::Resolving => "RESOLVING",
            Self::PkiOnly => "PKI-ONLY",
            Self::Unresolved => "UNRESOLVED",
        }
    }

    fn of(host: &Host) -> Self {
        if matches!(
            host.endpoint.as_ref().map(|e| &e.status),
            Some(ProbeStatus::Ok)
        ) {
            return Self::Exposed;
        }
        if matches!(
            host.dns_status,
            Some(crate::model::DnsStatus::Ok) | Some(crate::model::DnsStatus::NoData)
        ) {
            return Self::Resolving;
        }
        if !host.ct_refs.is_empty() {
            Self::PkiOnly
        } else {
            Self::Unresolved
        }
    }
}

/// Combined view (default output mode).
pub fn combined(state: &DomainState) -> String {
    let mut out = String::new();
    out.push_str(&format!("Discovered names: {}\n", state.hosts.len()));

    let all: Vec<&Host> = state.hosts.values().collect();
    let host_w = 39
        .max(all.iter().map(|h| h.name.len()).max().unwrap_or(0) + 2)
        .max("HOST / SERVICE".len());
    let service_w = 11;
    let kx_w = 16;

    for category in Category::ALL {
        let hosts = all
            .iter()
            .filter(|h| Category::of(h) == category)
            .copied()
            .collect::<Vec<_>>();
        if hosts.is_empty() {
            continue;
        }
        out.push_str(&format!("\n{} ({})\n", category.title(), hosts.len()));
        out.push_str(&format!(
            "{:<host_w$}{:<service_w$}{}\n",
            "HOST / SERVICE", "SERVICE", "OBSERVED KX"
        ));
        for host in ordered(&hosts) {
            let service = match host.endpoint.as_ref().map(|e| &e.status) {
                Some(ProbeStatus::Ok) => "TLS:443",
                _ => "-",
            };
            let kx = host
                .endpoint
                .as_ref()
                .and_then(|e| e.negotiated.as_ref())
                .and_then(|n| n.kx_group.as_deref())
                .unwrap_or("-");
            out.push_str(&format!(
                "{:<host_w$}{:<service_w$}{:<kx_w$}\n",
                host.name, service, kx
            ));
        }
    }

    if !state.srv.is_empty() {
        out.push('\n');
        let mut prev_fqdn: Option<&str> = None;
        for rec in &state.srv {
            let label_line = format!(
                "{} → {}:{}",
                crate::discover::dns::service_label(&rec.service),
                rec.target,
                rec.port
            );
            let fqdn = if prev_fqdn == Some(rec.fqdn.as_str()) {
                ""
            } else {
                rec.fqdn.as_str()
            };
            out.push_str(&format!("{:<host_w$}{:<service_w$}\n", fqdn, label_line));
            prev_fqdn = Some(rec.fqdn.as_str());
        }
    }

    // SVCB/HTTPS records on the apex, same row shape as SRV.
    for rec in &state.https {
        let params = if rec.params.is_empty() {
            String::new()
        } else {
            format!(" {}", rec.params)
        };
        let label_line = format!("{} → {}{}", rec.rr_type, rec.target, params);
        out.push_str(&format!(
            "{:<host_w$}{:<service_w$}\n",
            state.domain, label_line
        ));
    }

    out
}

/// Alphabetical, with `www.` variants adjacent to their bare host.
fn ordered<'a>(hosts: &[&'a Host]) -> Vec<&'a Host> {
    let mut hosts: Vec<&Host> = hosts.to_vec();
    hosts.sort_by_key(|h| {
        let (base, is_www) = www_key(&h.name);
        (base, is_www, h.name.clone())
    });
    hosts
}

/// "www.x" → ("x", 1), "x" → ("x", 0) — bare host sorts before its www variant.
fn www_key(name: &str) -> (String, u8) {
    match name.strip_prefix("www.") {
        Some(base) => (base.to_string(), 1),
        None => (name.to_string(), 0),
    }
}

/// ct-inv2.sh `summary` parity.
pub fn summary(state: &DomainState) -> String {
    let mut identities = std::collections::BTreeSet::new();
    let mut concrete = std::collections::BTreeSet::new();
    let mut wildcards = std::collections::BTreeSet::new();
    for cert in state.certs.values().filter(|c| c.currently_valid) {
        for name in &cert.identities {
            identities.insert(name.clone());
            if crate::discover::ct::is_wildcard(name) {
                wildcards.insert(name.clone());
            } else {
                concrete.insert(name.clone());
            }
        }
    }
    let row = |label: &str, value: usize| format!("  {label:<31}{value}\n");
    format!(
        "Certificate estate: '{}'\n\n{}{}{}\n{}{}{}",
        state.domain,
        row("CT certificates:", state.ct_stats.rows),
        row("Currently valid:", state.ct_stats.valid),
        row("Future-valid:", state.ct_stats.future),
        row("Unique identities:", identities.len()),
        row("Concrete hostnames:", concrete.len()),
        row("Wildcard identities:", wildcards.len()),
    )
}

/// ct-inv2.sh `--hosts` parity: concrete names of currently valid certificates.
pub fn hosts(state: &DomainState) -> String {
    let mut names = std::collections::BTreeSet::new();
    for cert in state.certs.values().filter(|c| c.currently_valid) {
        for name in &cert.identities {
            if !crate::discover::ct::is_wildcard(name) {
                names.insert(name.clone());
            }
        }
    }
    let mut out = names.iter().map(|n| format!("{n}\n")).collect::<String>();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// ct-inv2.sh `--certs` parity.
pub fn certs(state: &DomainState) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<12}  {:<30}  {:<30}  {:<20}  {}\n",
        "CT ID", "NOT BEFORE", "NOT AFTER", "COMMON NAME", "IDENTITIES"
    ));
    out.push_str(&format!(
        "{:<12}  {:<30}  {:<30}  {:<20}  {}\n",
        "------------",
        "------------------------------",
        "------------------------------",
        "--------------------",
        "----------"
    ));
    for cert in state.certs.values().filter(|c| c.currently_valid) {
        let id = cert
            .ct_ids
            .first()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "-".to_string());
        let nb = fmt_date(cert.not_before);
        let na = fmt_date(cert.not_after);
        let cn = cert.common_name.clone().unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{:<12}  {:<30}  {:<30}  {:<20}  {}\n",
            id,
            nb,
            na,
            cn,
            cert.identities.join(",")
        ));
    }
    out
}

fn fmt_date(dt: Option<chrono::DateTime<chrono::Utc>>) -> String {
    dt.map(|d| d.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MatchKind, fixture};

    /// Cells of the first table row whose host column starts with `name`.
    fn row_cells(text: &str, name: &str) -> String {
        text.lines()
            .find(|l| l.starts_with(&format!("{name} ")))
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_else(|| panic!("no row for {name}"))
    }

    /// Cells of the last table row for `name` (host row first, DNS record rows later).
    fn last_row_cells(text: &str, name: &str) -> String {
        text.lines()
            .filter(|l| l.starts_with(&format!("{name} ")))
            .next_back()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_else(|| panic!("no row for {name}"))
    }

    #[test]
    fn combined_matches_layout() {
        let state = fixture();
        let text = combined(&state);

        assert!(text.starts_with("Discovered names: 5\n"));
        for section in ["EXPOSED (2)", "RESOLVING (2)", "PKI-ONLY (1)"] {
            assert!(text.contains(section));
        }
        assert_eq!(
            row_cells(&text, "www.nbp.pl"),
            "www.nbp.pl TLS:443 X25519MLKEM768"
        );
        assert_eq!(row_cells(&text, "vpn.nbp.pl"), "vpn.nbp.pl - -");
        assert_eq!(row_cells(&text, "old.nbp.pl"), "old.nbp.pl - -");
        assert!(text.contains("_sip._tls.nbp.pl"));
        assert!(text.contains("SIP/TLS → sipdir.online.lync.com:443"));
        // HTTPS records render as table rows, not sections.
        assert_eq!(
            last_row_cells(&text, "nbp.pl"),
            "nbp.pl HTTPS → . alpn=h2,h3"
        );
        assert!(!text.contains("=== "));
    }

    #[test]
    fn www_variants_group_with_bare_host() {
        let state = fixture();
        let text = combined(&state);
        let lines: Vec<&str> = text.lines().collect();
        let apex = lines.iter().position(|l| l.starts_with("nbp.pl ")).unwrap();
        let www = lines
            .iter()
            .position(|l| l.starts_with("www.nbp.pl "))
            .unwrap();
        assert_eq!(www, apex + 1, "www.nbp.pl directly after nbp.pl");
    }

    #[test]
    fn summary_counts_fixture() {
        let state = fixture();
        let text = summary(&state);
        assert!(text.contains("Certificate estate: 'nbp.pl'"));
        let line = text
            .lines()
            .find(|l| l.contains("CT certificates:"))
            .expect("summary row");
        assert!(line.trim_end().ends_with('2'), "rows counted: {line}");
    }

    #[test]
    fn wildcard_refs_rendered_by_probe_views() {
        let state = fixture();
        let old = state.hosts.get("old.nbp.pl").unwrap();
        assert!(
            old.ct_refs
                .iter()
                .any(|r| r.kind == MatchKind::Wildcard && r.serial == "bb22")
        );
    }
}
