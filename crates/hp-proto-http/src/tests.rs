use super::*;
use hp_core::Action;
use hp_testkit::{conformance, send, session, CtxOptions, Observer, Script};
use tokio::io::AsyncReadExt;

async fn run(script: Script, input: &'static [u8]) -> (String, Vec<Value>, Observer) {
    let (ctx, mut obs) = session(CtxOptions {
        script,
        banner: Some("nginx/1.18.0 (Ubuntu)"),
        ..Default::default()
    });
    let (server, mut client) = tokio::io::duplex(1 << 16);
    let peer = tokio::spawn(async move {
        client.write_all(input).await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = vec![];
        client.read_to_end(&mut got).await.unwrap();
        got
    });
    Http.handle(Box::new(server), ctx).await.unwrap();
    let got = String::from_utf8(peer.await.unwrap()).unwrap();
    let records = obs.records();
    (got, records, obs)
}

fn of_kind<'a>(recs: &'a [Value], kind: &str) -> Vec<&'a Value> {
    recs.iter().filter(|r| r["kind"] == kind).collect()
}

/// Answers `GET /` (and `HEAD /`) with a page, echoes POST bodies, ignores the rest.
fn site(e: &Event) -> Vec<Action> {
    match e {
        Event::Request { op, .. } if op == "GET /" || op == "HEAD /" => {
            vec![send("<h1>Portal</h1>")]
        }
        Event::Request { args, .. } if args["method"] == "POST" => {
            let body = args["body"].as_str().unwrap().to_string();
            vec![Action::Send(body.into())]
        }
        _ => vec![],
    }
}

#[test]
fn metadata() {
    assert_eq!(Http.name(), "http");
    assert_eq!(Http.default_ports(), [80, 8080]);
}

#[tokio::test]
async fn pipelined_keep_alive_requests_are_answered_in_order() {
    let (got, recs, obs) = run(
        site,
        b"GET / HTTP/1.1\r\nHost: portal\r\n\r\nGET /nope HTTP/1.1\r\nHost: portal\r\n\r\n",
    )
    .await;
    let first = got.find("<h1>Portal</h1>").unwrap();
    let second = got.find("HTTP/1.1 404 Not Found").unwrap();
    assert!(first < second, "{got}");
    assert!(got.starts_with("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nDate: "));
    assert!(got.contains("Content-Length: 15\r\nConnection: keep-alive\r\n"));
    assert!(got.contains("<hr><center>nginx/1.18.0 (Ubuntu)</center>"));

    let reqs = of_kind(&recs, "http_request");
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1]["target"], "/nope");
    assert_eq!(
        reqs[0]["headers"][0],
        json!({"name": "Host", "value": "portal"})
    );
    conformance::envelope(&recs);
    conformance::lifecycle(&obs.seen);
}

#[tokio::test]
async fn bodies_reach_the_behavior_by_length_and_chunked() {
    let (got, _, _) = run(
        site,
        b"POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloPOST /b HTTP/1.1\r\n\
          Transfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-T: 1\r\n\r\n",
    )
    .await;
    assert!(
        got.contains("Content-Length: 5\r\nConnection: keep-alive\r\n\r\nhello"),
        "{got}"
    );
    assert!(got.ends_with("\r\n\r\nabcde"), "{got}");
}

#[tokio::test]
async fn request_fields_are_handed_to_the_behavior() {
    fn check(e: &Event) -> Vec<Action> {
        let Event::Request { op, args } = e else {
            return vec![];
        };
        assert_eq!(op, "GET /x/y?a=1");
        assert_eq!(args["path"], "/x/y");
        assert_eq!(args["query"], "a=1");
        assert_eq!(
            args["headers"],
            "host: h\nuser-agent: sqlmap/1.7\nconnection: close\n"
        );
        assert!(args.get("password").is_none());
        vec![send("ok")]
    }
    let (got, _, _) = run(
        check,
        b"GET /x/y?a=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: sqlmap/1.7\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(got.contains("Connection: close\r\n\r\nok"), "{got}");
}

#[tokio::test]
async fn login_forms_and_basic_auth_are_logged_with_the_verdict() {
    fn login(e: &Event) -> Vec<Action> {
        match e {
            Event::Request { args, .. } if args["password"] == "letmein" => vec![
                Action::AuthResult(true),
                send("HTTP/1.1 302 Found\nLocation: /dashboard\nSet-Cookie: sid=1\n\n"),
            ],
            Event::Request { args, .. } if args.get("password").is_some() => {
                vec![
                    Action::AuthResult(false),
                    send("HTTP/1.1 401 Unauthorized\n\nno"),
                ]
            }
            _ => vec![],
        }
    }
    let (got, recs, _) = run(
        login,
        b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\
          Content-Length: 27\r\n\r\nusername=ops&password=guess\
          GET / HTTP/1.1\r\nAuthorization: Basic b3BzOmxldG1laW4=\r\n\r\n",
    )
    .await;
    assert!(got.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{got}");
    assert!(got.contains("HTTP/1.1 302 Found\r\n") && got.contains("Location: /dashboard\r\n"));
    let auth = of_kind(&recs, "auth");
    assert_eq!(auth.len(), 2);
    assert_eq!(
        (
            &auth[0]["user"],
            &auth[0]["credential"],
            &auth[0]["method"],
            &auth[0]["accepted"]
        ),
        (
            &json!("ops"),
            &json!("guess"),
            &json!("http_form"),
            &json!(false)
        )
    );
    assert_eq!(
        (&auth[1]["user"], &auth[1]["method"], &auth[1]["accepted"]),
        (&json!("ops"), &json!("http_basic"), &json!(true))
    );
}

#[tokio::test]
async fn http_1_0_and_head_requests() {
    let (got, _, _) = run(site, b"HEAD / HTTP/1.0\r\n\r\nGET / HTTP/1.1\r\n\r\n").await;
    assert!(
        got.contains("Content-Length: 15\r\nConnection: close\r\n\r\n"),
        "{got}"
    );
    assert!(
        got.ends_with("\r\n\r\n"),
        "HEAD has no body and 1.0 closes: {got}"
    );
}

#[tokio::test]
async fn garbage_and_oversized_input_get_an_error_page_and_close() {
    let (got, recs, _) = run(site, b"\x16\x03\x01\x02\x00\x01\x00GET / HTTP/1.1\r\n\r\n").await;
    assert!(got.starts_with("HTTP/1.1 400 Bad Request\r\n") && got.contains("Connection: close"));
    assert_eq!(
        got.matches("HTTP/1.1").count(),
        1,
        "nothing after the error: {got}"
    );
    assert!(of_kind(&recs, "http_request").is_empty());

    let (got, _, _) = run(site, b"POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n").await;
    assert!(got.starts_with("HTTP/1.1 413 "), "{got}");
    let (got, _, _) = run(site, b"POST / HTTP/1.1\r\nContent-Length: x\r\n\r\n").await;
    assert!(got.starts_with("HTTP/1.1 400 "), "{got}");
    let (got, _, _) = run(
        site,
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
    )
    .await;
    assert!(got.starts_with("HTTP/1.1 400 "), "{got}");
}

#[tokio::test]
async fn a_huge_head_is_rejected() {
    let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
    big.extend(vec![b'a'; 20 * 1024]);
    let input: &'static [u8] = Box::leak(big.into_boxed_slice());
    let (got, _, _) = run(site, input).await;
    assert!(got.starts_with("HTTP/1.1 431 "), "{got}");
}

#[tokio::test]
async fn close_without_a_reply_drops_the_connection() {
    fn drop_it(e: &Event) -> Vec<Action> {
        match e {
            Event::Request { .. } => vec![Action::Close],
            _ => vec![],
        }
    }
    let (got, _, _) = run(drop_it, b"GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(got, "");
}

#[tokio::test]
async fn expect_100_continue_is_honoured() {
    let (ctx, _obs) = session(CtxOptions {
        script: site,
        ..Default::default()
    });
    let (server, mut client) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { Http.handle(Box::new(server), ctx).await });
    client
        .write_all(b"POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n")
        .await
        .unwrap();
    let mut cont = [0u8; 25];
    client.read_exact(&mut cont).await.unwrap();
    assert_eq!(&cont, b"HTTP/1.1 100 Continue\r\n\r\n");
    client.write_all(b"hi").await.unwrap();
    client.shutdown().await.unwrap();
    let mut rest = vec![];
    client.read_to_end(&mut rest).await.unwrap();
    assert!(String::from_utf8(rest).unwrap().ends_with("\r\n\r\nhi"));
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn input_cap_is_enforced() {
    let (ctx, mut obs) = session(CtxOptions {
        max_input_bytes: 8,
        ..Default::default()
    });
    let (server, mut client) = tokio::io::duplex(8192);
    tokio::spawn(async move {
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut v = vec![];
        let _ = client.read_to_end(&mut v).await;
    });
    Http.handle(Box::new(server), ctx).await.unwrap();
    conformance::input_cap_enforced(&obs.records(), 8);
}
