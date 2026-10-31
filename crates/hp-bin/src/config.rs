//! Configuration boundary. YAML text goes in; a validated, fully typed
//! [`Config`] comes out. Nothing downstream re-parses strings or re-checks
//! ranges: durations, sizes and addresses are already real types.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use hp_core::{Limits, Persona};
use serde::Deserialize;

/// Validated runtime configuration.
#[derive(Debug)]
pub struct Config {
    pub protocol: String,
    pub listen: Vec<SocketAddr>,
    pub persona: Persona,
    pub track: Option<PathBuf>,
    /// Per-session limits handed to plugins.
    pub limits: Limits,
    /// Concurrent session cap, enforced by the server.
    pub max_sessions: usize,
    /// JSONL session log path; stdout if unset.
    pub session_log: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Config::parse(&text)
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
            track: raw.track,
            limits: Limits {
                session_timeout: humantime::parse_duration(&raw.limits.session_timeout)
                    .context("limits.session_timeout")?,
                max_input_bytes: parse_size(&raw.limits.max_input_bytes)
                    .context("limits.max_input_bytes")?,
            },
            max_sessions: raw.limits.max_sessions,
            session_log: raw.logging.json,
        })
    }
}

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
        assert!(c.track.is_none() && c.session_log.is_none());
    }

    #[test]
    fn full_config_maps_every_field() {
        let c = Config::parse(&format!(
            "{MIN}persona: {{ hostname: h, banner: b }}\ntrack: t.yaml\n\
             limits: {{ max_sessions: 3, session_timeout: 30s, max_input_bytes: 2KiB }}\n\
             logging: {{ json: /tmp/x.jsonl }}"
        ))
        .unwrap();
        assert_eq!(
            (c.persona.hostname.as_deref(), c.persona.banner.as_deref()),
            (Some("h"), Some("b"))
        );
        assert_eq!(c.track.as_deref(), Some(Path::new("t.yaml")));
        assert_eq!(c.max_sessions, 3);
        assert_eq!(c.limits.session_timeout, Duration::from_secs(30));
        assert_eq!(c.limits.max_input_bytes, 2048);
        assert_eq!(c.session_log.as_deref(), Some(Path::new("/tmp/x.jsonl")));
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
        assert!(Config::parse("protocol: banner\nlisten: []").is_err());
        assert!(Config::load(Path::new("/nonexistent/x.yaml")).is_err());
    }
}
