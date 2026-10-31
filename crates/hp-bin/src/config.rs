use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub protocol: String,
    pub listen: Vec<SocketAddr>,
    #[serde(default)]
    pub persona: Persona,
    pub track: Option<PathBuf>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub logging: Logging,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persona {
    pub hostname: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "d_sessions")]
    pub max_sessions: usize,
    #[serde(default = "d_timeout")]
    pub session_timeout: String,
    #[serde(default = "d_input")]
    pub max_input_bytes: String,
}
fn d_sessions() -> usize { 256 }
fn d_timeout() -> String { "15m".into() }
fn d_input() -> String { "1MiB".into() }
impl Default for Limits {
    fn default() -> Self { Self { max_sessions: d_sessions(), session_timeout: d_timeout(), max_input_bytes: d_input() } }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Logging {
    /// JSONL session log path; stdout if unset.
    pub json: Option<PathBuf>,
    pub pcap: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = serde_yaml::from_str(&text).context("parsing config")?;
        if cfg.listen.is_empty() { bail!("`listen` must contain at least one address"); }
        if cfg.limits.max_sessions == 0 { bail!("limits.max_sessions must be > 0"); }
        cfg.session_timeout()?;
        cfg.max_input_bytes()?;
        Ok(cfg)
    }

    pub fn session_timeout(&self) -> anyhow::Result<Duration> {
        humantime::parse_duration(&self.limits.session_timeout).context("limits.session_timeout")
    }

    pub fn max_input_bytes(&self) -> anyhow::Result<u64> { parse_size(&self.limits.max_input_bytes) }
}

pub fn parse_size(s: &str) -> anyhow::Result<u64> {
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
    #[test]
    fn sizes() {
        assert_eq!(parse_size("1MiB").unwrap(), 1 << 20);
        assert_eq!(parse_size("512").unwrap(), 512);
        assert!(parse_size("1XB").is_err());
        assert!(parse_size("MiB").is_err());
    }
    #[test]
    fn rejects_unknown_fields() {
        assert!(serde_yaml::from_str::<Config>("protocol: banner\nlisten: ['127.0.0.1:1']\nbogus: 1").is_err());
    }
}
