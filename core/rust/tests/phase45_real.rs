use clops_core::{cve, lfi, misconfig, payload, pcap, proxy, sqli, xss};
use std::sync::{Arc, Mutex};

// Real vuln dummy server on 127.0.0.1. Each endpoint mimics one vuln class safely.
async fn start_vuln_lab() -> String {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
          return;
        }
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let line = req.lines().next().unwrap_or("").to_string();
        let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
        // Parse query roughly
        let (route, query) = match path.split_once('?') {
          Some((r, q)) => (r.to_string(), q.to_string()),
          None => (path.clone(), String::new()),
        };
        let params: std::collections::HashMap<String, String> = query
          .split('&')
          .filter_map(|kv| kv.split_once('='))
          .map(|(k, v)| {
            let dk = url_decode(k);
            let dv = url_decode(v);
            (dk, dv)
          })
          .collect();
        let body: Vec<u8> = if route == "/sqli" {
          let id = params.get("id").cloned().unwrap_or_default();
          if id.contains("SLEEP(2)") {
            tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
            b"ok after sleep".to_vec()
          } else if id.contains('\'') && id.contains("AND") {
            // boolean: true contains base marker, false does not
            if id.contains("'1'='1") || id.contains("1'='1") {
              b"user list: alice bob".to_vec()
            } else {
              b"no users".to_vec()
            }
          } else if id.contains('\'') || id.contains('"') {
            b"You have an error in your SQL syntax near ''".to_vec()
          } else {
            b"user list: alice bob".to_vec()
          }
        } else if route == "/xss" {
          let q = params.get("q").cloned().unwrap_or_default();
          format!("<html><body>hello {q}</body></html>").into_bytes()
        } else if route == "/lfi" {
          let f = params.get("file").cloned().unwrap_or_default();
          if f.contains("etc/passwd") || f.contains("etc%2fpasswd") || f.contains("..") {
            b"root:x:0:0:root:/root:/bin/bash".to_vec()
          } else {
            b"file ok".to_vec()
          }
        } else if route == "/ssti" {
          let v = params.get("name").cloned().unwrap_or_default();
          if v.contains("{{7*7}}") {
            b"hello 49".to_vec()
          } else if v.contains("{{8*8}}") {
            b"hello 64".to_vec()
          } else {
            format!("hello {v}").into_bytes()
          }
        } else if route == "/clean" {
          b"static clean page".to_vec()
        } else if route == "/cors" {
          b"cors lab".to_vec()
        } else {
          b"not found".to_vec()
        };
        // Headers: /cors returns ACAO * plus verbose server plus weak cookie
        let extra = if route == "/cors" {
          "Access-Control-Allow-Origin: *\r\nServer: ClopsLab/9.9.9\r\nSet-Cookie: sess=abc; Path=/\r\n"
        } else {
          "Server: ClopsLab\r\n"
        };
        let head = format!(
          "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n{}Connection: close\r\n\r\n",
          body.len(),
          extra
        );
        let _ = s.write_all(head.as_bytes()).await;
        let _ = s.write_all(&body).await;
      });
    }
  });
  format!("http://127.0.0.1:{port}")
}

fn url_decode(s: &str) -> String {
  // Full percent decode for lab. Handles all %XX from reqwest encoding.
  let mut out = String::new();
  let b = s.as_bytes();
  let mut i = 0;
  while i < b.len() {
    if b[i] == b'%' && i + 2 < b.len() {
      if let (Some(h), Some(l)) = (hexv(b[i+1]), hexv(b[i+2])) {
        out.push((h * 16 + l) as char);
        i += 3;
        continue;
      }
    }
    if b[i] == b'+' {
      out.push(' ');
    } else {
      out.push(b[i] as char);
    }
    i += 1;
  }
  return out;
}

fn hexv(c: u8) -> Option<u8> {
  match c {
    b'0'..=b'9' => Some(c - b'0'),
    b'a'..=b'f' => Some(c - b'a' + 10),
    b'A'..=b'F' => Some(c - b'A' + 10),
    _ => None,
  }
}

fn url_decode_legacy(s: &str) -> String {
  // Minimal decode for lab: %2f %20 plus + to space. reqwest already encodes, we decode back.
  s.replace("%2F", "/")
    .replace("%2f", "/")
    .replace("%20", " ")
    .replace('+', " ")
    .replace("%27", "'")
    .replace("%22", "\"")
    .replace("%7B", "{")
    .replace("%7b", "{")
    .replace("%7D", "}")
    .replace("%7d", "}")
    .replace("%2A", "*")
    .replace("%2a", "*")
    .replace("%28", "(")
    .replace("%29", ")")
}

#[tokio::test]
async fn t10_sqli_positive_and_negative_real() {
  let base = start_vuln_lab().await;
  let url = format!("{base}/sqli?id=1");
  let found = sqli::check(&url, &["id".to_string()], 4000, false).await;
  assert!(found.iter().any(|f| f.kind.contains("error-based")), "must detect error SQLi, got {found:?}");
  assert!(found.iter().any(|f| f.kind.contains("boolean")), "must detect boolean, got {found:?}");
  // Negative: clean endpoint ignores quotes
  let clean = format!("{base}/clean?x=1");
  let neg = sqli::check(&clean, &["x".to_string()], 3000, false).await;
  assert!(neg.is_empty(), "clean lab must stay clean, got {neg:?}");
}

#[tokio::test]
async fn t10_sqli_time_gated_real() {
  let base = start_vuln_lab().await;
  let url = format!("{base}/sqli?id=1");
  let found = sqli::check(&url, &["id".to_string()], 6000, true).await;
  assert!(found.iter().any(|f| f.kind.contains("time")), "must detect time based with allow_time, got {found:?}");
}

#[tokio::test]
async fn t11_xss_double_send_real() {
  let base = start_vuln_lab().await;
  let url = format!("{base}/xss?q=hi");
  let found = xss::check(&url, &["q".to_string()], 4000).await;
  assert!(!found.is_empty(), "must detect reflected XSS");
  assert_eq!(found[0].context, "html-text");
  // Negative
  let clean = format!("{base}/clean?x=hi");
  let neg = xss::check(&clean, &["x".to_string()], 3000).await;
  assert!(neg.is_empty(), "clean must not flag XSS, got {neg:?}");
}

#[tokio::test]
async fn t12_lfi_ssti_real() {
  let base = start_vuln_lab().await;
  let lfi_url = format!("{base}/lfi?file=ok");
  let found = lfi::check(&lfi_url, &["file".to_string()], 4000).await;
  assert!(found.iter().any(|f| f.kind == "path-traversal"), "must detect traversal, got {found:?}");
  let ssti_url = format!("{base}/ssti?name=hi");
  let found2 = lfi::check(&ssti_url, &["name".to_string()], 4000).await;
  assert!(found2.iter().any(|f| f.kind == "ssti"), "must detect SSTI math, got {found2:?}");
  // Negative
  let clean = format!("{base}/clean?x=hi");
  let neg = lfi::check(&clean, &["x".to_string()], 3000).await;
  assert!(neg.is_empty());
}

#[tokio::test]
async fn t13_misconfig_real() {
  let base = start_vuln_lab().await;
  let url = format!("{base}/cors");
  let found = misconfig::check(&url, 4000).await;
  assert!(found.iter().any(|f| f.check.contains("CORS")), "must flag wildcard CORS, got {found:?}");
  assert!(found.iter().any(|f| f.check.contains("cookie") || f.check.contains("Cookie") || f.check.contains("Weak")), "must flag weak cookie, got {found:?}");
}

#[tokio::test]
async fn t15_proxy_forward_and_scope_real() {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  // Target
  let target_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let tport = target_ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = target_ln.accept().await else { break };
      tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let _ = s.read(&mut buf).await;
        let body = b"admin panel via proxy";
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = s.write_all(head.as_bytes()).await;
        let _ = s.write_all(body).await;
      });
    }
  });
  let scope = clops_core::scope::Scope::lab_only();
  let history = Arc::new(Mutex::new(Vec::new()));
  // Direct forward real
  let url = format!("http://127.0.0.1:{tport}/admin");
  let (status, body) = proxy::forward(&scope, &history, "GET", &url, 4000).await.expect("forward works");
  assert_eq!(status, 200);
  assert!(String::from_utf8_lossy(&body).contains("admin panel"));
  assert_eq!(history.lock().unwrap().len(), 1);
  // Scope reject real
  let evil = proxy::forward(&scope, &history, "GET", "http://evil.example.net/", 2000).await;
  assert!(evil.is_err(), "outside scope must be blocked");
  // Listener mode real: start proxy, send raw request through it
  let pln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let pport = pln.local_addr().unwrap().port();
  drop(pln);
  let h2 = history.clone();
  tokio::spawn(async move {
    let _ = proxy::run(&format!("127.0.0.1:{pport}"), scope, h2, 4000).await;
  });
  tokio::time::sleep(std::time::Duration::from_millis(200)).await;
  let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{pport}")).await.unwrap();
  let req = format!("GET {url} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  s.write_all(req.as_bytes()).await.unwrap();
  let mut out = Vec::new();
  s.read_to_end(&mut out).await.unwrap();
  assert!(String::from_utf8_lossy(&out).contains("admin panel"), "proxy listener must relay");
}

#[test]
fn t16_pcap_parse_real() {
  let data = pcap::build_test_pcap();
  let flows = pcap::parse_bytes(&data).expect("parse test pcap");
  assert_eq!(flows.len(), 1);
  assert_eq!(flows[0].proto, "TCP");
  assert_eq!(flows[0].dport, 80);
  assert_eq!(flows[0].sport, 1234);
}

#[test]
fn t17_cve_match_real() {
  let m = cve::match_service("nginx", "nginx/1.18.0", None);
  assert!(m.iter().any(|x| x.id == "CVE-2021-23017"), "must match nginx old, got {m:?}");
  let ok = cve::match_service("nginx", "nginx/1.25.0", None);
  assert!(ok.is_empty(), "new nginx must not match old CVE");
  let a = cve::match_service("apache", "Apache/2.4.41", None);
  assert!(a.iter().any(|x| x.id == "CVE-2021-41773"));
}

#[test]
fn t18_payload_real() {
  let b = payload::generate("bash", "10.0.0.5", 4444);
  assert!(b.code.contains("10.0.0.5") && b.code.contains("4444"));
  assert!(b.listener.contains("4444"));
  let p = payload::generate("python3", "127.0.0.1", 9001);
  assert!(p.code.contains("127.0.0.1"));
  let e = payload::encode_base64("hello");
  assert_eq!(e, "aGVsbG8=");
}
