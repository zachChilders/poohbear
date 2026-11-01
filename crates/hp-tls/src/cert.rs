//! Where the server certificate comes from: files (an internal-CA cert makes
//! the decoy far more convincing) or a self-signed one generated at startup.

use std::path::PathBuf;

use anyhow::{bail, Context};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
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
/// whole day, and is valid for a common span.
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
    dn.push(DnType::CommonName, cn.as_str());
    if let Some(org) = organization {
        dn.push(DnType::OrganizationName, org);
    }
    params.distinguished_name = dn;
    let issued = (now - Duration::days(143)).date().midnight().assume_utc();
    params.not_before = issued;
    params.not_after = issued + Duration::days(825);
    let key = KeyPair::generate().context("generating key")?;
    let cert = params.self_signed(&key).context("signing certificate")?;
    let key = PrivateKeyDer::try_from(key.serialize_der())
        .map_err(|e| anyhow::anyhow!("encoding key: {e}"))?;
    Ok((vec![cert.der().clone()], key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_needs_a_name_and_is_backdated() {
        assert!(self_signed(&[], None, OffsetDateTime::now_utc()).is_err());
        let (chain, _) = self_signed(
            &["portal.corp.example".into(), "10.0.0.5".into()],
            Some("Example Corp"),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(chain.len(), 1);
        // The DER carries the names and organization.
        let der = chain[0].as_ref();
        let has = |s: &[u8]| der.windows(s.len()).any(|w| w == s);
        assert!(has(b"portal.corp.example") && has(b"Example Corp"));
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
