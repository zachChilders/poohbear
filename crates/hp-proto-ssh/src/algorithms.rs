//! The algorithm lists and host keys the server advertises in its KEXINIT.
//!
//! The default banner claims Ubuntu 22.04's OpenSSH 8.9p1 (3ubuntu0.6), so a
//! scanner such as nmap's `ssh2-enum-algos` should see that build's lists, in
//! its order. russh's defaults give the game away (`mlkem768x25519-sha256`
//! only exists from OpenSSH 9.9, and the host key and MAC sets are wrong), so
//! the lists are spelled out here.
//!
//! Only algorithms russh actually implements are listed: anything advertised
//! can be picked by a client, and a pick we can't honor fails the handshake.
//! That leaves these gaps against the real server:
//! - kex: `sntrup761x25519-sha512@openssh.com` (not implemented by russh).
//! - macs: `umac-64-etm`, `umac-128-etm`, `umac-64`, `umac-128` (not
//!   implemented by russh).
//!
//! The server never sends `ext-info-s`: OpenSSH's sshd only started
//! advertising it in 9.6, and Ubuntu's Terrapin backport to 8.9p1 adds just
//! `kex-strict-s-v00@openssh.com`.

use anyhow::Context;
use russh::keys::ssh_key::private::{KeypairData, RsaKeypair};
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};
use russh::{cipher, compression, kex, mac, Preferred};

/// `ssh-keygen`'s default RSA size, which is what a stock install's
/// `/etc/ssh/ssh_host_rsa_key` has (and what nmap's `ssh-hostkey` reports).
const RSA_BITS: usize = 3072;

const KEX: &[kex::Name] = &[
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_GEX_SHA256,
    kex::DH_G16_SHA512,
    kex::DH_G18_SHA512,
    kex::DH_G14_SHA256,
    // Terrapin countermeasure (CVE-2023-48795), as in 3ubuntu0.6.
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

/// russh advertises only the entries we hold a key for; `host_keys` provides
/// one of each, so all of these go out.
const HOST_KEY: &[Algorithm] = &[
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ed25519,
];

const CIPHER: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_128_CTR,
    cipher::AES_192_CTR,
    cipher::AES_256_CTR,
    cipher::AES_128_GCM,
    cipher::AES_256_GCM,
];

const MAC: &[mac::Name] = &[
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA1_ETM,
    mac::HMAC_SHA256,
    mac::HMAC_SHA512,
    mac::HMAC_SHA1,
];

const COMPRESSION: &[compression::Name] = &[compression::NONE, compression::ZLIB_LEGACY];

/// The server's algorithm preferences, in OpenSSH 8.9p1's order.
pub(crate) fn preferred() -> Preferred {
    Preferred {
        kex: KEX.into(),
        key: HOST_KEY.into(),
        cipher: CIPHER.into(),
        mac: MAC.into(),
        compression: COMPRESSION.into(),
        ..Preferred::default()
    }
}

/// Fresh host keys of the three types a stock sshd generates (RSA, ECDSA
/// P-256, Ed25519). They change on every restart.
pub(crate) fn host_keys() -> anyhow::Result<Vec<PrivateKey>> {
    let rng = &mut rand::rng();
    let rsa = RsaKeypair::random(rng, RSA_BITS)
        .and_then(|k| PrivateKey::new(KeypairData::from(k), ""))
        .context("generating RSA host key")?;
    let ecdsa = PrivateKey::random(
        rng,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    )
    .context("generating ECDSA host key")?;
    let ed25519 =
        PrivateKey::random(rng, Algorithm::Ed25519).context("generating Ed25519 host key")?;
    Ok(vec![rsa, ecdsa, ed25519])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names<T: AsRef<str>>(list: &[T]) -> Vec<&str> {
        list.iter().map(AsRef::as_ref).collect()
    }

    #[test]
    fn lists_match_ubuntu_22_04_openssh_8_9() {
        let p = preferred();
        assert_eq!(
            names(&p.kex),
            [
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group-exchange-sha256",
                "diffie-hellman-group16-sha512",
                "diffie-hellman-group18-sha512",
                "diffie-hellman-group14-sha256",
                "kex-strict-s-v00@openssh.com",
            ]
        );
        assert!(!p.kex.iter().any(|k| k.as_ref().contains("mlkem")));
        assert_eq!(
            p.key.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "rsa-sha2-512",
                "rsa-sha2-256",
                "ecdsa-sha2-nistp256",
                "ssh-ed25519"
            ]
        );
        assert_eq!(
            names(&p.cipher),
            [
                "chacha20-poly1305@openssh.com",
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
            ]
        );
        assert_eq!(
            names(&p.mac),
            [
                "hmac-sha2-256-etm@openssh.com",
                "hmac-sha2-512-etm@openssh.com",
                "hmac-sha1-etm@openssh.com",
                "hmac-sha2-256",
                "hmac-sha2-512",
                "hmac-sha1",
            ]
        );
        assert_eq!(names(&p.compression), ["none", "zlib@openssh.com"]);
        assert!(p.host_key_certificates.is_empty());
    }

    #[test]
    fn every_advertised_host_key_algorithm_has_a_key() {
        let keys = host_keys().unwrap();
        for algo in HOST_KEY {
            assert!(
                keys.iter().any(|k| match algo {
                    Algorithm::Rsa { .. } => k.algorithm().is_rsa(),
                    a => k.algorithm() == *a,
                }),
                "no host key for {algo}"
            );
        }
        let rsa = keys.iter().find(|k| k.algorithm().is_rsa()).unwrap();
        let bits = rsa
            .key_data()
            .rsa()
            .unwrap()
            .public()
            .n()
            .as_positive_bytes()
            .unwrap()
            .len()
            * 8;
        assert_eq!(bits, RSA_BITS);
    }
}
