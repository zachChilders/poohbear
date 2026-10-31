//! Input schema: the serde shape of a track YAML file, before validation.
//! Nothing here knows about the runtime model; `compile` turns it into one.

use serde::de::Error as _;
use serde::Deserialize;
use serde_yaml::Value as Yaml;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTrack {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) vars: BTreeMap<String, Yaml>,
    pub(crate) start: String,
    pub(crate) states: BTreeMap<String, RawState>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawState {
    #[serde(default)]
    pub(crate) on: Vec<RawRule>,
    pub(crate) fallback: Option<Yaml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRule {
    #[serde(default, rename = "match")]
    pub(crate) matcher: RawMatch,
    pub(crate) when: Option<String>,
    #[serde(default, rename = "do")]
    pub(crate) steps: Vec<RawStep>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMatch {
    pub(crate) event: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) user: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) op: Option<String>,
    pub(crate) raw: Option<String>,
}

/// One step: a single-key map such as `{ send: "..." }`.
pub(crate) struct RawStep(pub(crate) String, pub(crate) Yaml);

impl<'de> Deserialize<'de> for RawStep {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let m = serde_yaml::Mapping::deserialize(d)?;
        if m.len() != 1 {
            return Err(D::Error::custom(
                "each step must be a map with exactly one key",
            ));
        }
        let (k, v) = m.into_iter().next().unwrap();
        let k = k
            .as_str()
            .ok_or_else(|| D::Error::custom("step name must be a string"))?
            .to_string();
        Ok(RawStep(k, v))
    }
}

/// `fallback:` may be one step map, a multi-key map (steps in key order) or a list.
pub(crate) fn fallback_steps(v: Yaml) -> Result<Vec<RawStep>, String> {
    match v {
        Yaml::Sequence(seq) => seq
            .into_iter()
            .map(|s| serde_yaml::from_value(s).map_err(|e| e.to_string()))
            .collect(),
        Yaml::Mapping(m) => m
            .into_iter()
            .map(|(k, v)| match k {
                Yaml::String(k) => Ok(RawStep(k, v)),
                _ => Err("step name must be a string".to_string()),
            })
            .collect(),
        _ => Err("`fallback` must be a step or a list of steps".into()),
    }
}
