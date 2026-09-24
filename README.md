# pq-map

Discovery and mapping of externally visible cryptographic infrastructure using Certificate Transparency, DNS, and live TLS probing.

Certificate discovery (crt.sh certwatch DB → HTTP fallback → cache)
→ DNS discovery (SRV/SVCB/HTTPS, A/AAAA)
→ live TLS probing (PQ/hybrid-first via rustls, OpenSSL fallback)
→ correlated text, JSON, and graph output.

[features demo](https://github.com/user-attachments/assets/a91043ad-a4e1-4dc0-9821-9d504935889a)


`pq-map` correlates certificates, hostnames, DNS-visible services, live TLS
configuration, certificate chains, keys, signatures, key exchange, and
symmetric ciphers.

It describes the externally observable cryptographic estate.

## Usage

```
pq-map nbp.pl                # combined text view (default)
pq-map nbp.pl --summary      # certificate estate summary
pq-map nbp.pl --hosts        # hostnames of valid certificates
pq-map nbp.pl --certs        # CT certificate records
pq-map nbp.pl --json         # full state as JSON
pq-map nbp.pl --graph        # semantic graph JSON (see visualization below)
pq-map nbp.pl --refresh      # force fresh CT + full re-probe
pq-map nbp.pl --no-probe     # CT/DNS only, no TLS handshakes
pq-map nbp.pl --ports        # discover other services (smtp/imap/...) on hosts where 443 failed
```

Caches in `~/.cache/pq-map/`: CT 7 days, probes 24 hours. DNS resolves every run and invalidates cached probes; failed probes are cached too. `--refresh` bypasses both.

## Visualization

```
pq-map nbp.pl --graph --ports > graph.json
./pq-graph.sh                 # serves ./graph.json on :8000, opens browser
./pq-graph.sh graph.json 9000
```

Interactive 3D semantic graph with node search/filtering and focused
1-hop, 2-hop, and entity-details views.

#### Examples

```
./pq-graph.sh examples/mbank.json

./pq-graph.sh examples/allegro.json
```

## ENV vars

- `CT_DB_HOST=crt.sh`
- `CT_DB_PORT=5432`
- `CT_DB_USER=guest`
- `CT_DB_DB=certwatch`
- `CT_DB_CONNECT_TIMEOUT=30`
- `CT_DB_QUERY_TIMEOUT=120`
- `CT_CACHE_TTL=604800`
- `PROBE_CACHE_TTL=86400`
- `PROBE_TIMEOUT=8`
- `PROBE_CONCURRENCY=32`
- `DNS_TIMEOUT=5`
- `DNS_ATTEMPTS=2`
- `DNS_CONCURRENCY=32`

## Build

```
cargo build --release    # rust 1.85+, libssl-dev
cargo test
```

## License

EUPL-1.2
