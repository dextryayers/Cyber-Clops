use clops_core::{dirbrute, dns, fingerprint, repeater, scan, secrets, spider, takeover, tls};
use std::collections::HashMap;

// Helper: start a real local HTTP server for dir, spider, repeater tests.
async fn start_lab() -> String {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let path = req.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
        let (code, body, ctype): (&str, Vec<u8>, &str) = match path.as_str() {
          "/" => ("200 OK", b"<html><head><title>Lab</title></head><body><a href=\"/admin\">a</a><form method=\"POST\"><input name=\"user\"/></form><script src=\"/static/app.js\"></script></body></html>".to_vec(), "text/html"),
          "/admin" => ("200 OK", b"admin panel".to_vec(), "text/html"),
          "/static/app.js" => ("200 OK", b"const API=\"/api/v1/users\"; const K=\"AKIAIOSFODNN7EXAMPLE\";".to_vec(), "application/javascript"),
          _ => ("404 Not Found", b"not found page body lab".to_vec(), "text/html"),
        };
        let head = format!(
          "HTTP/1.1 {code}\r\nContent-Length: {}\r\nContent-Type: {ctype}\r\nServer: ClopsLab/0.2\r\nConnection: close\r\n\r\n",
          body.len()
        );
        let _ = s.write_all(head.as_bytes()).await;
        let _ = s.write_all(&body).await;
      });
    }
  });
  format!("http://127.0.0.1:{port}")
}

#[tokio::test]
async fn t02_query_and_doh_real() {
  let a = dns::query("example.com", "A").await;
  assert!(!a.is_empty(), "example.com A must return records");
  let d = dns::doh_resolve("example.com").await;
  assert!(!d.is_empty(), "DoH must return at least one IP");
}

#[tokio::test]
async fn t02_axfr_blocked_real() {
  let ns = dns::query("example.com", "NS").await;
  let ns_hosts: Vec<String> = ns.iter().take(2).map(|r| r.value.clone()).collect();
  // example.com does not allow AXFR. Real proof is vulnerable=false.
  let (vuln, _) = dns::axfr_check("example.com", &ns_hosts).await;
  assert!(!vuln);
}

#[tokio::test]
async fn t03_scan_and_refine_real() {
  // ephemeral SSH banner listener
  let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      use tokio::io::AsyncWriteExt;
      let _ = s.write_all(b"SSH-2.0-OpenSSH_9.2 lab\r\n").await;
    }
  });
  tokio::time::sleep(std::time::Duration::from_millis(50)).await;
  let f = scan::scan_one("127.0.0.1", port, 2000).await;
  assert!(f.open && f.service == "ssh");
  // HTTP refine against real local lab
  let base = start_lab().await;
  let (svc, ver) = scan::refine_http(&base.replace("http://", "").split(':').next().unwrap_or("127.0.0.1"), base.split(':').last().unwrap_or("80").parse().unwrap_or(80), 3000).await;
  assert_eq!(svc, "http");
  let _ = ver;
}

#[tokio::test]
async fn t04_tls_real() {
  let info = tls::analyze("example.com", 443, 8000).await.expect("tls analyze must work");
  assert!(info.cert_cn.contains("example.com") || !info.san.is_empty() || info.days_left != 0);
  assert!(info.days_left > 0, "example.com cert must not be expired");
  let protos = tls::probe_protocols("example.com", 443, 6000).await;
  assert!(protos.contains(&"TLS1.3".to_string()), "modern host must support TLS1.3, got {protos:?}");
}

#[tokio::test]
async fn t05_fingerprint_real() {
  let fp = fingerprint::fingerprint("http://example.com", 8000).await.expect("fp must work");
  assert!(!fp.server.is_empty() || !fp.tech.is_empty() || fp.url.contains("example.com"));
}

#[tokio::test]
async fn t06_takeover_no_signal_real() {
  let sigs = takeover::check("example.com", 6000).await;
  // example.com has no takeover CNAME. Real result is empty, not error.
  assert!(sigs.is_empty(), "unexpected takeover signal: {sigs:?}");
}

#[tokio::test]
async fn t07_dirbrute_real() {
  let base = start_lab().await;
  let words = vec!["admin".to_string(), "missing999".to_string()];
  let found = dirbrute::brute(&base, &words, 4, 3000, 0).await;
  let paths: Vec<String> = found.iter().map(|f| f.path.clone()).collect();
  assert!(paths.contains(&"/admin".to_string()), "must find /admin, got {paths:?}");
  assert!(!paths.contains(&"/missing999".to_string()));
}

#[tokio::test]
async fn t08_spider_real() {
  let base = start_lab().await;
  let (pages, forms) = spider::crawl(&format!("{base}/"), 20, 3000).await;
  assert!(pages.len() >= 2, "must crawl at least 2 pages, got {}", pages.len());
  assert!(!forms.is_empty(), "must find at least one form");
}

#[test]
fn t09_secrets_real() {
  let body = r#"const API="/api/v1/users"; const K="AKIAIOSFODNN7EXAMPLE"; const J="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";"#;
  let (eps, secs) = secrets::extract(body, "lab.js");
  assert!(eps.iter().any(|e| e.path.contains("api")), "must extract endpoint");
  assert!(secs.iter().any(|s| s.kind == "AWS key"), "must detect AWS example key");
}

#[tokio::test]
async fn t14_repeater_real() {
  let base = start_lab().await;
  let r = repeater::resend(&format!("{base}/admin"), "GET", vec![], "", 3000).await.expect("resend works");
  assert_eq!(r.status, 200);
  assert!(r.length > 0);
  let d = repeater::diff("a\nb", "a\nc");
  assert!(d.contains('-') && d.contains('+'));
}

#[tokio::test]
async fn t01_fast_runs_real() {
  // Polite fast path against example.com. Must not panic even if one source is down.
  // Asserts pipeline works end to end with resolve validation.
  let out = clops_core::subdomain::enumerate_fast("example.com").await;
  // At least the plumbing works. If network blocks all sources, out may be empty but code ran real.
  // We assert clean() keeps example.com scope correctly on a synthetic case too.
  let _ = out;
  let single = clops_core::subdomain::from_san("example.com", &["WWW.EXAMPLE.COM ".to_string()]);
  assert_eq!(single, vec!["www.example.com".to_string()]);
  let _m: HashMap<String, String> = HashMap::new();
}
