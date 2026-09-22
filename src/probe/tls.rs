use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::discover::ct;
use crate::model::{Negotiated, ServedCert};

use super::Failure;

/// Verifier that accepts everything: the probe inspects certificates like
/// `openssl s_client` does, it does not authenticate the endpoint.
#[derive(Debug, Default)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
        ]
    }
}

fn connector() -> Arc<TlsConnector> {
    static CONNECTOR: OnceLock<Arc<TlsConnector>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("TLS 1.2/1.3 protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth();
            Arc::new(TlsConnector::from(Arc::new(config)))
        })
        .clone()
}

/// Primary probe: rustls (aws-lc-rs) with SNI against host:port.
/// MLKEM768 is offered first (browser parity, `prefer-post-quantum`).
pub async fn attempt(
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
    _cfg: &crate::config::Config,
) -> Result<(ServedCert, Negotiated), Failure> {
    let addr = match ip {
        Some(ip) => SocketAddr::from((ip, port)),
        None => return Err(Failure::Unknown("host unresolved".to_string())),
    };

    let sni = server_name(host, ip)?;
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| super::classify_io(&e))?;

    let tls = connector()
        .connect(sni, tcp)
        .await
        .map_err(super::classify_handshake)?;

    let (_, conn) = tls.get_ref();

    let negotiated = Negotiated {
        tls_version: conn.protocol_version().map(version_str),
        kx_group: conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name())),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite())),
    };

    let chain_sigs: Vec<String> = conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .filter_map(|cert| sig_alg_from_der(cert.as_ref()))
        .collect();

    let Some(leaf) = conn
        .peer_certificates()
        .and_then(|chain| chain.first().cloned())
    else {
        return Err(Failure::ClosedNoCert("no certificate served".to_string()));
    };
    let served = served_cert_from_der(leaf.as_ref())
        .ok_or_else(|| Failure::Unknown("certificate parse failed".to_string()))?;
    Ok((served_with_chain_sigs(served, chain_sigs), negotiated))
}

/// Legacy fallback for servers that rustls cannot reach (TLS 1.0/1.1, odd
/// ciphers): OpenSSL with SECLEVEL=0, verification off — the s_client bar.
/// No PQ key exchange exists below TLS 1.3, so kx_group stays empty here.
pub fn openssl_attempt(
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
    timeout: Duration,
) -> Result<(ServedCert, Negotiated), String> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

    let addr = match ip {
        Some(ip) => SocketAddr::from((ip, port)),
        None => return Err("host unresolved".to_string()),
    };

    let stream =
        std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("tcp: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("tcp: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("tcp: {e}"))?;

    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1))
        .map_err(|e| e.to_string())?;
    builder
        .set_cipher_list("DEFAULT@SECLEVEL=0")
        .map_err(|e| e.to_string())?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let mut config = connector.configure().map_err(|e| e.to_string())?;
    config.set_use_server_name_indication(true);
    config.set_verify_hostname(false);

    let tls = config
        .connect(host, stream)
        .map_err(|e| format!("tls: {e}"))?;
    let ssl = tls.ssl();

    let negotiated = Negotiated {
        tls_version: Some(ssl.version_str().to_string()),
        kx_group: None,
        cipher: ssl.current_cipher().map(|c| c.name().to_string()),
    };

    // Client-side peer chain includes the leaf.
    let chain_sigs: Vec<String> = ssl
        .peer_cert_chain()
        .map(|chain| {
            chain
                .iter()
                .filter_map(|cert| cert.to_der().ok())
                .filter_map(|der| sig_alg_from_der(&der))
                .collect()
        })
        .unwrap_or_default();

    let cert = ssl
        .peer_certificate()
        .ok_or_else(|| "connected, no certificate".to_string())?;
    let der = cert.to_der().map_err(|e| e.to_string())?;
    let served =
        served_cert_from_der(&der).ok_or_else(|| "certificate parse failed".to_string())?;
    Ok((served_with_chain_sigs(served, chain_sigs), negotiated))
}

fn server_name(host: &str, ip: Option<IpAddr>) -> Result<ServerName<'static>, Failure> {
    if let Ok(name) = ServerName::try_from(host.to_string()) {
        return Ok(name);
    }
    // Invalid DNS name (e.g. underscores in CT entries): connect without SNI.
    match ip {
        Some(ip) => Ok(ServerName::IpAddress(ip.into())),
        None => Err(Failure::Unknown(format!("invalid name {host}"))),
    }
}

/// Shared leaf-certificate extraction for both TLS stacks.
pub fn served_cert_from_der(der: &[u8]) -> Option<ServedCert> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;

    let serial = ct::serial_norm(&hex_lower(cert.raw_serial()));
    let pubkey_alg = Some(oid_name(&cert.subject_pki.algorithm.algorithm, PUBKEY_OIDS));
    let sig_alg = Some(oid_name(&cert.signature_algorithm.algorithm, SIG_OIDS));
    let pubkey_curve = curve_from_params(&cert.subject_pki.algorithm.parameters);
    let cert_signature = live_cert_signature(
        pubkey_alg.as_deref(),
        sig_alg.as_deref(),
        pubkey_curve.clone(),
    );
    let issuer = Some(issuer_rfc2253(&cert.issuer));

    let validity = cert.validity();
    let not_before = chrono::DateTime::from_timestamp(validity.not_before.timestamp(), 0)
        .map(|d| d.with_timezone(&chrono::Utc));
    let not_after = chrono::DateTime::from_timestamp(validity.not_after.timestamp(), 0)
        .map(|d| d.with_timezone(&chrono::Utc));

    let mut identities: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    identities.sort();
    identities.dedup();

    let common_name = cert
        .subject
        .iter_common_name()
        .next()
        .and_then(|atv| atv.as_str().ok())
        .map(str::to_string);

    Some(ServedCert {
        serial,
        common_name,
        identities,
        pubkey_alg,
        sig_alg,
        issuer,
        not_before,
        not_after,
        chain_sigs: Vec::new(),
        pubkey_curve,
        cert_signature,
    })
}

fn curve_from_params(params: &Option<x509_parser::der_parser::asn1_rs::Any>) -> Option<String> {
    let params = params.as_ref()?;
    let dotted = params.as_oid().ok()?.to_id_string();
    EC_CURVE_OIDS
        .iter()
        .find(|(k, _)| *k == dotted)
        .map(|(_, v)| v.to_string())
}

fn live_cert_signature(
    pubkey_alg: Option<&str>,
    sig_alg: Option<&str>,
    curve: Option<String>,
) -> Option<String> {
    let sig = sig_alg?;
    let lower = sig.to_ascii_lowercase();
    let (class, hash): (String, Option<&str>) = if lower.contains("ecdsa") {
        ("ECDSA".to_string(), hash_from_sig(&lower))
    } else if lower.contains("ed25519") {
        ("Ed25519".to_string(), None)
    } else if lower.contains("ed448") {
        ("Ed448".to_string(), None)
    } else if lower.contains("rsa") {
        ("RSA".to_string(), hash_from_sig(&lower))
    } else if let Some(pubkey) = pubkey_alg {
        (crate::model::alg_class_of(pubkey), hash_from_sig(&lower))
    } else {
        (sig.to_string(), None)
    };
    crate::model::cert_signature_name(&class, hash, curve.as_deref())
}

/// "sha256WithRSAEncryption" → "SHA256", "SHA-384" → "SHA384".
fn hash_from_sig(sig_lower: &str) -> Option<&'static str> {
    const HASHES: [(&str, &str); 5] = [
        ("sha512", "SHA512"),
        ("sha384", "SHA384"),
        ("sha256", "SHA256"),
        ("sha1", "SHA1"),
        ("md5", "MD5"),
    ];
    HASHES
        .iter()
        .find(|(needle, _)| sig_lower.contains(needle))
        .map(|(_, name)| *name)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Signature algorithm name of a DER certificate (shared: leaf + chain scan).
pub fn sig_alg_from_der(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(oid_name(&cert.signature_algorithm.algorithm, SIG_OIDS))
}

fn served_with_chain_sigs(mut served: ServedCert, chain_sigs: Vec<String>) -> ServedCert {
    served.chain_sigs = chain_sigs;
    served
}

/// rustls protocol version in the pq-pulse-compatible presentation.
fn version_str(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_2 => "TLS1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS1.3".to_string(),
        other => format!("{other:?}"),
    }
}

const PUBKEY_OIDS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.1", "rsaEncryption"),
    ("1.2.840.113549.1.1.10", "rsassaPss"),
    ("1.2.840.10045.2.1", "id-ecPublicKey"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
];

const SIG_OIDS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
    ("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "rsassaPss"),
    ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.114", "Ed448"),
    ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
    ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
    ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
];

const EC_CURVE_OIDS: &[(&str, &str)] = &[
    ("1.2.840.10045.3.1.7", "P256"),
    ("1.3.132.0.34", "P384"),
    ("1.3.132.0.35", "P521"),
];

fn oid_name(oid: &x509_parser::der_parser::oid::Oid, table: &[(&str, &str)]) -> String {
    let dotted = oid.to_id_string();
    table
        .iter()
        .find(|(k, _)| *k == dotted)
        .map(|(_, v)| v.to_string())
        .unwrap_or(dotted)
}

const RDN_SHORT_NAMES: &[(&str, &str)] = &[
    ("2.5.4.3", "CN"),
    ("2.5.4.6", "C"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.5", "serialNumber"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("1.2.840.113549.1.9.1", "emailAddress"),
];

/// RFC 2253 rendering (most specific RDN first), like `openssl -nameopt RFC2253`.
fn issuer_rfc2253(name: &x509_parser::x509::X509Name) -> String {
    let parts: Vec<String> = name
        .iter_rdn()
        .flat_map(|rdn| rdn.iter())
        .map(|atv| {
            let dotted = atv.attr_type().to_id_string();
            let key = RDN_SHORT_NAMES
                .iter()
                .find(|(k, _)| *k == dotted)
                .map(|(_, v)| v.to_string())
                .unwrap_or(dotted);
            let value = atv
                .as_str()
                .map(std::borrow::ToOwned::to_owned)
                .unwrap_or_else(|_| String::from_utf8_lossy(atv.as_slice()).into_owned());
            format!("{key}={value}")
        })
        .collect();
    parts.into_iter().rev().collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed RSA leaf generated with openssl for test purposes.
    const TEST_CERT_PEM: &str = include_str!("../../tests/data/test-leaf.pem");

    #[test]
    fn extracts_fields_from_der() {
        let pem = TEST_CERT_PEM.trim();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64_decode(&body);
        let served = served_cert_from_der(&der).expect("parse test certificate");

        assert!(!served.serial.is_empty());
        assert_eq!(served.common_name.as_deref(), Some("test.pq-map.invalid"));
        assert!(
            served
                .identities
                .contains(&"test.pq-map.invalid".to_string())
        );
        assert_eq!(served.pubkey_alg.as_deref(), Some("rsaEncryption"));
        assert!(
            served
                .sig_alg
                .as_deref()
                .is_some_and(|s| s.contains("sha256"))
        );
        assert_eq!(served.cert_signature.as_deref(), Some("RSA-SHA256"));
        assert!(served.not_before.is_some());
        assert!(served.not_after.is_some());
        assert!(served.pubkey_curve.is_none());
    }

    /// Self-signed EC P-256 leaf generated with openssl for test purposes.
    const TEST_EC_CERT_PEM: &str = include_str!("../../tests/data/test-ec-leaf.pem");

    #[test]
    fn extracts_ecdsa_curve_and_signature() {
        let pem = TEST_EC_CERT_PEM.trim();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64_decode(&body);
        let served = served_cert_from_der(&der).expect("parse test EC certificate");

        assert_eq!(served.pubkey_alg.as_deref(), Some("id-ecPublicKey"));
        assert_eq!(served.pubkey_curve.as_deref(), Some("P256"));
        assert_eq!(served.cert_signature.as_deref(), Some("ECDSA-P256"));
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for c in input.bytes() {
            let v = match TABLE.iter().position(|t| *t == c) {
                Some(v) => v as u32,
                None => continue,
            };
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xff) as u8);
            }
        }
        out
    }
}
