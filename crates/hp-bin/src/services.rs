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
    /// Serve these ports over TLS (see `Config::from_env` for the certificate).
    pub tls: bool,
    /// Persona banner (for HTTP, the `Server` header).
    pub banner: Option<&'static str>,
}

pub const SERVICES: &[Service] = &[
    Service {
        protocol: "ssh",
        ports: &[22, 2222],
        track: include_str!("../../../tracks/ssh-linux-gateway.yaml"),
        shell_track: Some(include_str!("../../../tracks/ssh-real-shell.yaml")),
        tls: false,
        banner: None,
    },
    Service {
        protocol: "ftp",
        ports: &[21, 2121],
        track: include_str!("../../../tracks/ftp-vsftpd.yaml"),
        shell_track: None,
        tls: false,
        banner: None,
    },
    Service {
        protocol: "http",
        ports: &[80, 8080],
        track: HTTP_TRACK,
        shell_track: None,
        tls: false,
        banner: Some(HTTP_SERVER),
    },
    Service {
        protocol: "http",
        ports: &[443, 8443],
        track: HTTP_TRACK,
        shell_track: None,
        tls: true,
        banner: Some(HTTP_SERVER),
    },
    Service {
        protocol: "banner",
        ports: &[23, 2323],
        track: include_str!("../../../tracks/banner-demo.yaml"),
        shell_track: None,
        tls: false,
        banner: None,
    },
];

const HTTP_TRACK: &str = include_str!("../../../tracks/http-ops-portal.yaml");
/// What Ubuntu 22.04's nginx package reports.
const HTTP_SERVER: &str = "nginx/1.18.0 (Ubuntu)";

pub fn for_port(port: u16) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.ports.contains(&port))
}

/// "22 (ssh), 23 (banner), 443 (https)" for error messages.
pub fn known_ports() -> String {
    SERVICES
        .iter()
        .flat_map(|s| {
            let name = if s.tls {
                format!("{}s", s.protocol)
            } else {
                s.protocol.to_string()
            };
            s.ports.iter().map(move |p| format!("{p} ({name})"))
        })
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
        assert_eq!(for_port(21).unwrap().protocol, "ftp");
        assert!(!for_port(80).unwrap().tls && for_port(443).unwrap().tls);
        assert!(known_ports().contains("443 (https)"));
        assert!(for_port(9).is_none());
        assert!(known_ports().contains("22 (ssh)"));
    }
}
