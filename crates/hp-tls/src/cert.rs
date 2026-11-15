//! Where the server certificate comes from: files (an internal-CA cert makes
//! the decoy far more convincing) or a self-signed one generated at startup.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{bail, Context};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, SanType, SerialNumber,
};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, PartialEq)]
pub enum CertSource {
    /// PEM files: a certificate chain (leaf first) and its private key.
    Files { cert: PathBuf, key: PathBuf },
    /// Generate a self-signed certificate. The first name is the subject CN;
    /// all names are subject alternative names.
    SelfSigned {
        names: Vec<String>,
        organization: Option<String>,
    },
}

pub(crate) type Material = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

pub(crate) fn load(source: &CertSource) -> anyhow::Result<Material> {
    match source {
        CertSource::Files { cert, key } => {
            let chain = CertificateDer::pem_file_iter(cert)
                .with_context(|| format!("reading {}", cert.display()))?
                .collect::<Result<Vec<_>, _>>()
                .with_context(|| format!("parsing {}", cert.display()))?;
            if chain.is_empty() {
                bail!("{} contains no certificates", cert.display());
            }
            let key = PrivateKeyDer::from_pem_file(key)
                .with_context(|| format!("reading private key {}", key.display()))?;
            Ok((chain, key))
        }
        CertSource::SelfSigned {
            names,
            organization,
        } => self_signed(names, organization.as_deref(), OffsetDateTime::now_utc()),
    }
}

/// A self-signed certificate that looks issued by an admin, not by a tool:
/// it was issued months ago (not seconds before the first connection) on a
/// whole day, and is valid for a common span. Its shape follows what
/// `openssl req -x509` produces with the stock `openssl.cnf`: issuer equals
/// subject (`O=..., CN=...`, in OpenSSL's order), a random 159-bit serial,
/// and the `v3_ca` extensions: subject and authority key identifiers (SHA-1
/// of the public key, as OpenSSL derives them) and critical `CA:TRUE`, then
/// the `-addext` subject alternative names, in that order.
fn self_signed(
    names: &[String],
    organization: Option<&str>,
    now: OffsetDateTime,
) -> anyhow::Result<Material> {
    let Some(cn) = names.first() else {
        bail!("a self-signed certificate needs at least one name");
    };
    let mut params = CertificateParams::new(names.to_vec()).context("certificate names")?;
    let mut dn = DistinguishedName::new();
    if let Some(org) = organization {
        dn.push(DnType::OrganizationName, org);
    }
    dn.push(DnType::CommonName, cn.as_str());
    params.distinguished_name = dn;
    let issued = (now - Duration::days(143)).date().midnight().assume_utc();
    params.not_before = issued;
    params.not_after = issued + Duration::days(825);
    params.serial_number = Some(random_serial()?);
    let key = KeyPair::generate().context("generating key")?;
    // rcgen writes its own extensions in a different order (AKI, SAN, SKI,
    // basic constraints), which is a fingerprint; write OpenSSL's instead.
    let key_id = digest(&SHA1_FOR_LEGACY_USE_ONLY, key.public_key_raw());
    let san = subject_alt_names(&params.subject_alt_names)?;
    params.subject_alt_names.clear();
    let mut basic_constraints =
        CustomExtension::from_oid_content(&[2, 5, 29, 19], der(0x30, &der(0x01, &[0xff])));
    basic_constraints.set_criticality(true);
    params.custom_extensions = vec![
        CustomExtension::from_oid_content(&[2, 5, 29, 14], der(0x04, key_id.as_ref())),
        CustomExtension::from_oid_content(&[2, 5, 29, 35], der(0x30, &der(0x80, key_id.as_ref()))),
        basic_constraints,
        CustomExtension::from_oid_content(&[2, 5, 29, 17], san),
    ];
    let cert = params.self_signed(&key).context("signing certificate")?;
    let key = PrivateKeyDer::try_from(key.serialize_der())
        .map_err(|e| anyhow::anyhow!("encoding key: {e}"))?;
    Ok((vec![cert.der().clone()], key))
}

/// 20 random bytes with the top bit clear, like OpenSSL's 159-bit serials.
fn random_serial() -> anyhow::Result<SerialNumber> {
    let mut bytes = [0u8; 20];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("generating serial number"))?;
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

/// DER `GeneralNames` for the names rcgen parsed (DNS names and addresses).
fn subject_alt_names(names: &[SanType]) -> anyhow::Result<Vec<u8>> {
    let mut seq = Vec::new();
    for name in names {
        match name {
            SanType::DnsName(dns) => seq.extend(der(0x82, dns.as_str().as_bytes())),
            SanType::IpAddress(IpAddr::V4(ip)) => seq.extend(der(0x87, &ip.octets())),
            SanType::IpAddress(IpAddr::V6(ip)) => seq.extend(der(0x87, &ip.octets())),
            other => bail!("unsupported certificate name {other:?}"),
        }
    }
    Ok(der(0x30, &seq))
}

/// One DER tag-length-value.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        n @ 0..=0x7f => out.push(n as u8),
        n @ 0x80..=0xff => out.extend([0x81, n as u8]),
        n => {
            let n = u16::try_from(n).expect("DER value under 64 KiB");
            out.push(0x82);
            out.extend(n.to_be_bytes());
        }
    }
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::{
        FromDer, GeneralName, ParsedExtension, X509Certificate, X509Version,
    };

    fn parse<'a>(chain: &'a [CertificateDer<'static>]) -> X509Certificate<'a> {
        assert_eq!(chain.len(), 1);
        X509Certificate::from_der(chain[0].as_ref()).unwrap().1
    }

    #[test]
    fn self_signed_needs_a_name_and_is_backdated() {
        assert!(self_signed(&[], None, OffsetDateTime::now_utc()).is_err());
        let now = OffsetDateTime::now_utc();
        let (chain, _) = self_signed(
            &["portal.corp.example".into(), "10.0.0.5".into()],
            Some("Example Corp"),
            now,
        )
        .unwrap();
        let cert = parse(&chain);
        let san = cert.subject_alternative_name().unwrap().unwrap().value;
        assert_eq!(
            san.general_names,
            [
                GeneralName::DNSName("portal.corp.example"),
                GeneralName::IPAddress(&[10, 0, 0, 5]),
            ]
        );
        let not_before = cert.validity().not_before.to_datetime();
        assert_eq!(
            not_before,
            (now - Duration::days(143)).date().midnight().assume_utc()
        );
        assert_eq!(
            cert.validity().not_after.to_datetime(),
            not_before + Duration::days(825)
        );
    }

    #[test]
    fn self_signed_looks_like_openssl_req_x509() {
        let names = [
            "plc-gw-03".to_string(),
            "plc-gw-03.ot.corp.local".to_string(),
        ];
        let (chain, _) =
            self_signed(&names, Some("Plant Operations"), OffsetDateTime::now_utc()).unwrap();
        let cert = parse(&chain);
        assert_eq!(cert.version(), X509Version::V3);
        assert_eq!(
            cert.subject().to_string(),
            "O=Plant Operations, CN=plc-gw-03"
        );
        assert_eq!(cert.issuer(), cert.subject());

        let san = cert.subject_alternative_name().unwrap().unwrap().value;
        let dns: Vec<_> = san
            .general_names
            .iter()
            .map(|n| match n {
                GeneralName::DNSName(d) => d.to_string(),
                other => panic!("unexpected SAN {other:?}"),
            })
            .collect();
        assert_eq!(dns, names);

        // OpenSSL's order: v3_ca's SKI, AKI, basic constraints, then -addext.
        let oids: Vec<_> = cert
            .extensions()
            .iter()
            .map(|e| e.oid.to_id_string())
            .collect();
        assert_eq!(oids, ["2.5.29.14", "2.5.29.35", "2.5.29.19", "2.5.29.17"]);

        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.critical && bc.value.ca && bc.value.path_len_constraint.is_none());

        // Key identifiers are the SHA-1 of the public key, and the AKI is
        // keyid only, as OpenSSL writes for a self-signed certificate.
        let spk = cert.public_key().subject_public_key.data.as_ref();
        let expected = digest(&SHA1_FOR_LEGACY_USE_ONLY, spk);
        let (mut ski, mut aki) = (None, None);
        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => ski = Some(id.0),
                ParsedExtension::AuthorityKeyIdentifier(a) => {
                    assert!(a.authority_cert_issuer.is_none());
                    aki = a.key_identifier.as_ref().map(|k| k.0);
                }
                _ => {}
            }
        }
        assert_eq!(ski, Some(expected.as_ref()));
        assert_eq!(aki, ski);
    }

    #[test]
    fn serials_are_random_and_positive() {
        let serial = || {
            let (chain, _) = self_signed(&["a".into()], None, OffsetDateTime::now_utc()).unwrap();
            parse(&chain).raw_serial().to_vec()
        };
        let (a, b) = (serial(), serial());
        assert_ne!(a, b);
        assert!((16..=20).contains(&a.len()) && a[0] & 0x80 == 0, "{a:02x?}");
    }

    #[test]
    fn many_names_need_long_form_lengths() {
        let names: Vec<String> = (0..40).map(|i| format!("host-{i}.corp.example")).collect();
        let (chain, _) = self_signed(&names, None, OffsetDateTime::now_utc()).unwrap();
        let cert = parse(&chain);
        let san = cert.subject_alternative_name().unwrap().unwrap().value;
        assert_eq!(san.general_names.len(), 40);
        assert_eq!(der(0x04, &[0; 200])[..3], [0x04, 0x81, 200]);
        assert_eq!(der(0x04, &[0; 300])[..4], [0x04, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn organization_is_optional() {
        let (chain, _) = self_signed(&["a".into()], None, OffsetDateTime::now_utc()).unwrap();
        let cert = parse(&chain);
        assert_eq!(cert.subject().to_string(), "CN=a");
        assert_eq!(cert.issuer(), cert.subject());
    }

    #[test]
    fn file_errors_name_the_file() {
        let err = load(&CertSource::Files {
            cert: "/nonexistent/c.pem".into(),
            key: "/nonexistent/k.pem".into(),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("/nonexistent/c.pem"));
    }
}
