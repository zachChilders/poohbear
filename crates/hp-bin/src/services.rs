//! Which protocol, and which built-in behavior, serves a well-known port.
//! Adding a protocol to the honeypot means adding a row here (plus its plugin
//! in the registry in `main.rs`).

pub struct Service {
    pub protocol: &'static str,
    pub ports: &'static [u16],
    /// Track used when nothing else is configured; compiled into the binary.
    pub track: &'static str,
    /// Track used when real shells are enabled (`HONEYPOT_BROKER`), if the
    /// protocol can serve them.
    pub shell_track: Option<&'static str>,
}

pub const SERVICES: &[Service] = &[
    Service {
        protocol: "ssh",
        ports: &[22, 2222],
        track: include_str!("../../../tracks/ssh-linux-gateway.yaml"),
        shell_track: Some(include_str!("../../../tracks/ssh-real-shell.yaml")),
    },
    Service {
        protocol: "banner",
        ports: &[23, 2323],
        track: include_str!("../../../tracks/banner-demo.yaml"),
        shell_track: None,
    },
];

pub fn for_port(port: u16) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.ports.contains(&port))
}

/// "22 (ssh), 23 (banner)" for error messages.
pub fn known_ports() -> String {
    SERVICES
        .iter()
        .flat_map(|s| s.ports.iter().map(move |p| format!("{p} ({})", s.protocol)))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_track_is_valid_and_ports_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for s in SERVICES {
            hp_track::Track::from_yaml(s.track).unwrap();
            if let Some(t) = s.shell_track {
                hp_track::Track::from_yaml(t).unwrap();
            }
            for p in s.ports {
                assert!(seen.insert(p), "port {p} is claimed twice");
            }
        }
    }

    #[test]
    fn lookup() {
        assert_eq!(for_port(22).unwrap().protocol, "ssh");
        assert_eq!(for_port(2222).unwrap().protocol, "ssh");
        assert!(for_port(9).is_none());
        assert!(known_ports().contains("22 (ssh)"));
    }
}
