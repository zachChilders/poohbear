//! Credentials a request carries: HTTP Basic auth, or a login form posted
//! as urlencoded fields or JSON. Field names vary by application, so they
//! are recognised by shape (`j_username`, `login[password]`, `passwd`...).

use base64::Engine;
use hp_log::AuthMethod;
use serde_json::Value;

use crate::request::Request;

#[derive(Debug, PartialEq)]
pub(crate) struct Creds {
    pub user: String,
    pub password: String,
    pub method: AuthMethod,
}

pub(crate) fn extract(req: &Request) -> Option<Creds> {
    basic(req).or_else(|| form(req))
}

fn basic(req: &Request) -> Option<Creds> {
    let (scheme, token) = req.header("authorization")?.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .ok()?;
    let text = String::from_utf8_lossy(&raw);
    let (user, password) = text.split_once(':').unwrap_or((&text, ""));
    Some(Creds {
        user: user.into(),
        password: password.into(),
        method: AuthMethod::HttpBasic,
    })
}

fn form(req: &Request) -> Option<Creds> {
    let ctype = req.header("content-type")?.to_ascii_lowercase();
    let fields: Vec<(String, String)> = if ctype.starts_with("application/x-www-form-urlencoded") {
        String::from_utf8_lossy(&req.body)
            .split('&')
            .map(|pair| {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                (percent_decode(k), percent_decode(v))
            })
            .collect()
    } else if ctype.contains("json") {
        let mut out = vec![];
        if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
            flatten(&v, 0, &mut out);
        }
        out
    } else {
        return None;
    };
    let password = fields.iter().find(|(k, _)| is_password(k))?.1.clone();
    let user = fields
        .iter()
        .find(|(k, _)| !is_password(k) && is_user(k))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    Some(Creds {
        user,
        password,
        method: AuthMethod::HttpForm,
    })
}

/// String fields of a JSON object, and of objects nested one level down
/// (`{"auth": {"username": ...}}`).
fn flatten(v: &Value, depth: usize, out: &mut Vec<(String, String)>) {
    let Value::Object(map) = v else { return };
    for (k, v) in map {
        match v {
            Value::String(s) => out.push((k.clone(), s.clone())),
            Value::Object(_) if depth == 0 => flatten(v, 1, out),
            _ => {}
        }
    }
}

/// `j_password` -> `jpassword`, `login[Pass]` -> `loginpass`.
fn norm(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn is_password(key: &str) -> bool {
    let k = norm(key);
    k.contains("pass") || k.contains("pwd") || k == "secret"
}

fn is_user(key: &str) -> bool {
    let k = norm(key);
    ["user", "login", "email", "account", "uname", "uid"]
        .iter()
        .any(|w| k.contains(w))
}

/// `application/x-www-form-urlencoded` decoding: `+` is a space, `%XX` a
/// byte; malformed escapes are kept literally.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)], body: &str) -> Request {
        Request {
            method: "POST".into(),
            target: "/login".into(),
            minor: 1,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn creds(user: &str, password: &str, method: AuthMethod) -> Option<Creds> {
        Some(Creds {
            user: user.into(),
            password: password.into(),
            method,
        })
    }

    #[test]
    fn basic_auth() {
        // admin:pa:ss
        let r = req(&[("Authorization", "Basic YWRtaW46cGE6c3M=")], "");
        assert_eq!(extract(&r), creds("admin", "pa:ss", AuthMethod::HttpBasic));
        assert_eq!(extract(&req(&[("Authorization", "Bearer abc")], "")), None);
        assert_eq!(extract(&req(&[("Authorization", "Basic !!!")], "")), None);
    }

    #[test]
    fn urlencoded_forms_with_assorted_field_names() {
        let form = (
            "Content-Type",
            "application/x-www-form-urlencoded; charset=UTF-8",
        );
        assert_eq!(
            extract(&req(
                &[form],
                "j_username=ops%40corp&j_password=Winter2024%21&remember=1"
            )),
            creds("ops@corp", "Winter2024!", AuthMethod::HttpForm)
        );
        assert_eq!(
            extract(&req(&[form], "login%5Bpass%5D=a+b&login%5Buser%5D=bob")),
            creds("bob", "a b", AuthMethod::HttpForm)
        );
        assert_eq!(
            extract(&req(&[form], "q=search&page=2")),
            None,
            "no password field"
        );
        assert_eq!(
            extract(&req(&[form], "pwd=x")),
            creds("", "x", AuthMethod::HttpForm)
        );
    }

    #[test]
    fn json_bodies() {
        let json = ("Content-Type", "application/json");
        assert_eq!(
            extract(&req(&[json], r#"{"email":"a@b","password":"p"}"#)),
            creds("a@b", "p", AuthMethod::HttpForm)
        );
        assert_eq!(
            extract(&req(&[json], r#"{"auth":{"username":"u","passwd":"p"}}"#)),
            creds("u", "p", AuthMethod::HttpForm)
        );
        assert_eq!(extract(&req(&[json], "not json")), None);
        assert_eq!(extract(&req(&[], "password=p")), None, "no content type");
    }

    #[test]
    fn percent_decoding_is_lenient() {
        assert_eq!(percent_decode("a%20b+c%2"), "a b c%2");
        assert_eq!(percent_decode("%zz%"), "%zz%");
        assert_eq!(percent_decode("%e2%82%ac"), "€");
    }
}
