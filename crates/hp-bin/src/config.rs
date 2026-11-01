//! Configuration boundary. YAML text goes in; a validated, fully typed
//! [`Config`] comes out. Nothing downstream re-parses strings or re-checks
//! ranges: durations, sizes and addresses are already real types.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use hp_core::{Limits, Persona};
use hp_tls::CertSource;
use serde::Deserialize;

use crate::services;

/// Where the session's behavior (track) comes from.
#[derive(Debug, PartialEq)]
pub enum TrackSource {
    File(PathBuf),
    /// YAML compiled into the binary (see `services`).
    Builtin(&'static str),
}

/// Validated runtime configuration.
#[derive(Debug)]
pub struct Config {
    pub protocol: String,
    pub listen: Vec<SocketAddr>,
    pub persona: Persona,
    pub track: Option<TrackSource>,
    /// Per-session limits handed to plugins.
    pub limits: Limits,
    /// Concurrent session cap, enforced by the server.
    pub max_sessions: usize,
    /// JSONL session log path; stdout if unset.
    pub session_log: Option<PathBuf>,
    /// Socket of the broker that runs real shells in sandboxes, if enabled.
    pub shell_broker: Option<PathBuf>,
    /// Serve every listener over TLS with this certificate.
    pub tls: Option<CertSource>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Config::parse(&text)
    }

    /// Configuration inferred from the environment alone: `PORT` picks the
    /// protocol and its built-in track; `HONEYPOT_BROKER` (a socket path)
    /// turns on real shells; `HONEYPOT_LOG` sends session records to a file.
    /// TLS ports use `HONEYPOT_TLS_CERT` + `HONEYPOT_TLS_KEY` (PEM) if set,
    /// else a self-signed certificate for `HONEYPOT_TLS_NAMES` (comma
    /// separated; the default is the built-in persona's hostname).
    pub fn from_env(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
        let port: u16 = var("PORT")
            .context("set PORT (or pass --config)")?
            .trim()
            .parse()
            .context("PORT must be a port number")?;
        let service = services::for_port(port).with_context(|| {
            format!(
                "no protocol is known for port {port} (known: {})",
                services::known_ports()
            )
        })?;
        let shell_broker = var("HONEYPOT_BROKER").map(PathBuf::from);
        let track = match (&shell_broker, service.shell_track) {
            (None, _) => service.track,
            (Some(_), Some(track)) => track,
            (Some(_), None) => bail!(
                "{} cannot serve real shells (HONEYPOT_BROKER)",
                service.protocol
            ),
        };
        let mut cfg = Config::parse(&format!(
            "protocol: {}\nlisten: ['0.0.0.0:{port}']\n",
            service.protocol
        ))?;
        cfg.track = Some(TrackSource::Builtin(track));
        cfg.persona.banner = service.banner.map(String::from);
        if service.tls {
            cfg.tls = Some(match (var("HONEYPOT_TLS_CERT"), var("HONEYPOT_TLS_KEY")) {
                (Some(cert), Some(key)) => CertSource::Files {
                    cert: cert.into(),
                    key: key.into(),
                },
                (None, None) => CertSource::SelfSigned {
                    names: var("HONEYPOT_TLS_NAMES")
                        .unwrap_or_else(|| DEFAULT_TLS_NAME.into())
                        .split(',')
                        .map(|n| n.trim().to_string())
                        .filter(|n| !n.is_empty())
                        .collect(),
                    organization: None,
                },
                _ => bail!("set both HONEYPOT_TLS_CERT and HONEYPOT_TLS_KEY, or neither"),
            });
        }
        cfg.shell_broker = shell_broker;
        cfg.session_log = var("HONEYPOT_LOG").map(PathBuf::from);
        Ok(cfg)
    }

    pub fn parse(text: &str) -> anyhow::Result<Config> {
        let raw: RawConfig = serde_yaml::from_str(text).context("parsing config")?;
        if raw.listen.is_empty() {
            bail!("`listen` must contain at least one address");
        }
        if raw.limits.max_sessions == 0 {
            bail!("limits.max_sessions must be > 0");
        }
        Ok(Config {
            protocol: raw.protocol,
            listen: raw.listen,
            persona: Persona {
                hostname: raw.persona.hostname,
                banner: raw.persona.banner,
            },
            track: raw.track.map(TrackSource::File),
            limits: Limits {
                session_timeout: humantime::parse_duration(&raw.limits.session_timeout)
                    .context("limits.session_timeout")?,
                max_input_bytes: parse_size(&raw.limits.max_input_bytes)
                    .context("limits.max_input_bytes")?,
            },
            max_sessions: raw.limits.max_sessions,
            session_log: raw.logging.json,
            shell_broker: raw.shell.map(|s| s.broker),
            tls: raw.tls.map(RawTls::into_source).transpose()?,
        })
    }
}

/// Self-signed certificate name when nothing else is given.
const DEFAULT_TLS_NAME: &str = "plc-gw-03";

// ---- on-disk shape (private: only `Config::parse` sees it) ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    protocol: String,
    listen: Vec<SocketAddr>,
    #[serde(default)]
    persona: RawPersona,
    track: Option<PathBuf>,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    logging: RawLogging,
    shell: Option<RawShell>,
    tls: Option<RawTls>,
}

/// Either `cert` + `key`, or `self_signed`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    self_signed: Option<RawSelfSigned>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelfSigned {
    names: Vec<String>,
    organization: Option<String>,
}

impl RawTls {
    fn into_source(self) -> anyhow::Result<CertSource> {
        match (self.cert, self.key, self.self_signed) {
            (Some(cert), Some(key), None) => Ok(CertSource::Files { cert, key }),
            (None, None, Some(s)) if !s.names.is_empty() => Ok(CertSource::SelfSigned {
                names: s.names,
                organization: s.organization,
            }),
            (None, None, Some(_)) => bail!("tls.self_signed.names must not be empty"),
            _ => bail!("tls needs either `cert` and `key`, or `self_signed`"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShell {
    broker: PathBuf,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPersona {
    hostname: Option<String>,
    banner: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    #[serde(default = "default_sessions")]
    max_sessions: usize,
    #[serde(default = "default_timeout")]
    session_timeout: String,
    #[serde(default = "default_input")]
    max_input_bytes: String,
}

fn default_sessions() -> usize {
    256
}
fn default_timeout() -> String {
    "15m".into()
}
fn default_input() -> String {
    "1MiB".into()
}

impl Default for RawLimits {
    fn default() -> Self {
        RawLimits {
            max_sessions: default_sessions(),
            session_timeout: default_timeout(),
            max_input_bytes: default_input(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLogging {
    json: Option<PathBuf>,
}

fn parse_size(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().with_context(|| format!("bad size {s:?}"))?;
    let mult: u64 = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        other => bail!("unknown size unit {other:?}"),
    };
    n.checked_mul(mult).context("size overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const MIN: &str = "protocol: banner\nlisten: ['127.0.0.1:1']\n";

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1MiB").unwrap(), 1 << 20);
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size(" 2KiB ").unwrap(), 2048);
        assert!(parse_size("1XB").is_err());
        assert!(parse_size("MiB").is_err());
        assert!(parse_size("99999999999GiB").is_err());
    }

    #[test]
    fn defaults_are_applied_and_typed() {
        let c = Config::parse(MIN).unwrap();
        assert_eq!(c.max_sessions, 256);
        assert_eq!(c.limits.session_timeout, Duration::from_secs(900));
        assert_eq!(c.limits.max_input_bytes, 1 << 20);
        assert!(c.track.is_none() && c.session_log.is_none() && c.shell_broker.is_none());
        assert!(c.tls.is_none());
    }

    #[test]
    fn full_config_maps_every_field() {
        let c = Config::parse(&format!(
            "{MIN}persona: {{ hostname: h, banner: b }}\ntrack: t.yaml\n\
             limits: {{ max_sessions: 3, session_timeout: 30s, max_input_bytes: 2KiB }}\n\
             logging: {{ json: /tmp/x.jsonl }}\nshell: {{ broker: /run/hp.sock }}"
        ))
        .unwrap();
        assert_eq!(c.shell_broker.as_deref(), Some(Path::new("/run/hp.sock")));
        assert_eq!(
            (c.persona.hostname.as_deref(), c.persona.banner.as_deref()),
            (Some("h"), Some("b"))
        );
        assert_eq!(c.track, Some(TrackSource::File("t.yaml".into())));
        assert_eq!(c.max_sessions, 3);
        assert_eq!(c.limits.session_timeout, Duration::from_secs(30));
        assert_eq!(c.limits.max_input_bytes, 2048);
        assert_eq!(c.session_log.as_deref(), Some(Path::new("/tmp/x.jsonl")));
    }

    #[test]
    fn tls_takes_files_or_a_self_signed_spec() {
        let c = Config::parse(&format!("{MIN}tls: {{ cert: c.pem, key: k.pem }}")).unwrap();
        assert_eq!(
            c.tls,
            Some(CertSource::Files {
                cert: "c.pem".into(),
                key: "k.pem".into()
            })
        );
        let c = Config::parse(&format!(
            "{MIN}tls: {{ self_signed: {{ names: [portal.corp, 10.0.0.5], organization: Corp }} }}"
        ))
        .unwrap();
        assert_eq!(
            c.tls,
            Some(CertSource::SelfSigned {
                names: vec!["portal.corp".into(), "10.0.0.5".into()],
                organization: Some("Corp".into())
            })
        );
        let err =
            |extra: &str| format!("{:#}", Config::parse(&format!("{MIN}{extra}")).unwrap_err());
        assert!(err("tls: { cert: c.pem }").contains("either"));
        assert!(err("tls: { cert: c, key: k, self_signed: { names: [a] } }").contains("either"));
        assert!(err("tls: { self_signed: { names: [] } }").contains("names"));
        assert!(err("tls: { pfx: x }").contains("pfx"));
    }

    #[test]
    fn tls_ports_get_tls_from_the_environment() {
        let c = Config::from_env(env(&[("PORT", "443")])).unwrap();
        assert_eq!(c.protocol, "http");
        assert_eq!(c.persona.banner.as_deref(), Some("nginx/1.18.0 (Ubuntu)"));
        assert_eq!(
            c.tls,
            Some(CertSource::SelfSigned {
                names: vec!["plc-gw-03".into()],
                organization: None
            })
        );
        let c = Config::from_env(env(&[
            ("PORT", "8443"),
            ("HONEYPOT_TLS_NAMES", "a.corp, b"),
        ]))
        .unwrap();
        assert!(
            matches!(c.tls, Some(CertSource::SelfSigned { names, .. }) if names == ["a.corp", "b"])
        );
        let c = Config::from_env(env(&[
            ("PORT", "443"),
            ("HONEYPOT_TLS_CERT", "/c"),
            ("HONEYPOT_TLS_KEY", "/k"),
        ]))
        .unwrap();
        assert!(matches!(c.tls, Some(CertSource::Files { .. })));
        let err = format!(
            "{:#}",
            Config::from_env(env(&[("PORT", "443"), ("HONEYPOT_TLS_CERT", "/c")])).unwrap_err()
        );
        assert!(err.contains("both"), "{err}");
        assert!(Config::from_env(env(&[("PORT", "80")]))
            .unwrap()
            .tls
            .is_none());
    }

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn the_port_alone_picks_protocol_and_track() {
        let c = Config::from_env(env(&[("PORT", "22")])).unwrap();
        assert_eq!(c.protocol, "ssh");
        assert_eq!(c.listen, ["0.0.0.0:22".parse().unwrap()]);
        assert!(
            matches!(c.track, Some(TrackSource::Builtin(t)) if t.contains("ssh-linux-gateway"))
        );
        assert!(c.shell_broker.is_none() && c.session_log.is_none());
        assert_eq!(
            Config::from_env(env(&[("PORT", " 23 ")])).unwrap().protocol,
            "banner"
        );
    }

    #[test]
    fn a_broker_switches_to_the_real_shell_track() {
        let c = Config::from_env(env(&[
            ("PORT", "2222"),
            ("HONEYPOT_BROKER", "/run/b.sock"),
            ("HONEYPOT_LOG", "/tmp/s.jsonl"),
        ]))
        .unwrap();
        assert!(matches!(c.track, Some(TrackSource::Builtin(t)) if t.contains("ssh-real-shell")));
        assert_eq!(c.shell_broker.as_deref(), Some(Path::new("/run/b.sock")));
        assert_eq!(c.session_log.as_deref(), Some(Path::new("/tmp/s.jsonl")));
    }

    #[test]
    fn environment_mistakes_are_explained() {
        let err =
            |pairs: &[(&str, &str)]| format!("{:#}", Config::from_env(env(pairs)).unwrap_err());
        assert!(err(&[]).contains("PORT"));
        assert!(err(&[("PORT", "ssh")]).contains("port number"));
        assert!(err(&[("PORT", "9")]).contains("22 (ssh)"));
        assert!(err(&[("PORT", "23"), ("HONEYPOT_BROKER", "/x")]).contains("real shells"));
    }

    #[test]
    fn rejects_bad_values_with_the_offending_key_named() {
        let err =
            |extra: &str| format!("{:#}", Config::parse(&format!("{MIN}{extra}")).unwrap_err());
        assert!(err("limits: { max_sessions: 0 }").contains("max_sessions"));
        assert!(err("limits: { session_timeout: soon }").contains("session_timeout"));
        assert!(err("limits: { max_input_bytes: 1XB }").contains("max_input_bytes"));
        assert!(err("bogus: 1").contains("bogus"));
        assert!(err("logging: { pcap: x }").contains("pcap"));
        assert!(err("shell: {}").contains("broker"));
        assert!(Config::parse("protocol: banner\nlisten: []").is_err());
        assert!(Config::load(Path::new("/nonexistent/x.yaml")).is_err());
    }
}
