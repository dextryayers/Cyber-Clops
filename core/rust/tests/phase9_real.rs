use clops_core::{ai, chain, codec, cracker, cve, osint, payload, pcap, proxy, repeater, report, sqli, wordlist, xss};

// Raw lab helper: routes is a list of (prefix, body, extra_headers).
async fn start_raw(routes: Vec<(String, Vec<u8>, String)>) -> String {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      let routes = routes.clone();
      tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        let n = s.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
          return;
        }
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let line = req.lines().next().unwrap_or("").to_string();
        let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
        // Split body for POST form parsing
        let body_in = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        let path = target.split('?').next().unwrap_or("/").to_string();
        let mut out: Option<(Vec<u8>, String)> = None;
        // POST /sqli dynamic route first, before static prefix match
        if line.starts_with("POST") && path == "/sqli" {
          let form = form_decode(&body_in);
          let id = form.get("id").cloned().unwrap_or_default();
          let b = if id.contains("SLEEP") {
            b"ok".to_vec()
          } else if id.contains('\'') {
            b"You have an error in your SQL syntax".to_vec()
          } else {
            b"rows".to_vec()
          };
          out = Some((b, "Server: T\r\n".to_string()));
        } else {
          // Exact match pass first so "/" never shadows deeper routes
          for (prefix, body, extra) in &routes {
            if path == *prefix {
              out = Some((body.clone(), extra.clone()));
              break;
            }
          }
          if out.is_none() {
            for (prefix, body, extra) in &routes {
              if target.starts_with(prefix.as_str()) {
                out = Some((body.clone(), extra.clone()));
                break;
              }
            }
          }
        }
        let (body, extra) = out.unwrap_or((b"nf".to_vec(), "Server: T\r\n".to_string()));
        let head = format!(
          "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
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

fn form_decode(s: &str) -> std::collections::HashMap<String, String> {
  let mut m = std::collections::HashMap::new();
  for kv in s.split('&') {
    if let Some((k, v)) = kv.split_once('=') {
      m.insert(pct(k), pct(v));
    }
  }
  m
}

fn pct(s: &str) -> String {
  let mut out = String::new();
  let b = s.as_bytes();
  let mut i = 0;
  while i < b.len() {
    if b[i] == b'%' && i + 2 < b.len() {
      let h = hexv(b[i + 1]);
      let l = hexv(b[i + 2]);
      if let (Some(h), Some(l)) = (h, l) {
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
  out
}

fn hexv(c: u8) -> Option<u8> {
  match c {
    b'0'..=b'9' => Some(c - b'0'),
    b'a'..=b'f' => Some(c - b'a' + 10),
    b'A'..=b'F' => Some(c - b'A' + 10),
    _ => None,
  }
}

#[tokio::test]
async fn dns_ttl_real() {
  let recs = clops_core::dns::query("example.com", "A").await;
  assert!(!recs.is_empty());
  // Real TTL from authority must be positive
  assert!(recs.iter().any(|r| r.ttl > 0), "TTL must be real, got {recs:?}");
}

#[tokio::test]
async fn scan_stream_live_real() {
  use tokio::sync::mpsc;
  let (tx, mut rx) = mpsc::channel(64);
  let ports: Vec<u16> = (55100..55108).collect();
  clops_core::scan::scan_many_stream("127.0.0.1", &ports, 400, 8, tx).await;
  let mut got = 0;
  while rx.try_recv().is_ok() {
    got += 1;
  }
  assert_eq!(got, 8, "stream must deliver one finding per port");
}

#[tokio::test]
async fn scan_refined_version_real() {
  let base = start_raw(vec![("/".to_string(), b"<html><head><title>LabRef</title></head></html>".to_vec(), "Server: RefSrv/2.0\r\n".to_string())]).await;
  let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();
  // Ephemeral ports are outside the http-like refine policy by design,
  // so verify liveness via scan_many and version fill via refine_http.
  let out = clops_core::scan::scan_many("127.0.0.1", &[port], 3000, 2).await;
  assert!(out.iter().find(|f| f.port == port).unwrap().open);
  let (svc, ver) = clops_core::scan::refine_http("127.0.0.1", port, 3000).await;
  assert_eq!(svc, "http");
  assert!(ver.contains("RefSrv") || ver.contains("LabRef"), "refine must fill version, got {ver:?}");
}

#[tokio::test]
async fn tls_chain_len_real() {
  let info = clops_core::tls::analyze("example.com", 443, 8000).await.unwrap();
  assert!(info.chain_len >= 1, "chain must hold leaf at least");
  let _ = info.hsts.len();
}

#[tokio::test]
async fn dirbrute_extensions_real() {
  let base = start_raw(vec![("/admin.php".to_string(), b"admin php".to_vec(), "Server: T\r\n".to_string())]).await;
  let words = vec!["admin".to_string(), "nope999".to_string()];
  let opts = clops_core::dirbrute::BruteOptions { extensions: vec!["php".to_string()], status_allow: vec![200], start_offset: 0 };
  let found = clops_core::dirbrute::brute_advanced(&base, &words, 4, 3000, opts).await;
  assert!(found.iter().any(|f| f.path == "/admin.php"), "must find with extension, got {found:?}");
}

#[tokio::test]
async fn spider_depth_and_robots_real() {
  let base = start_raw(vec![
    ("/robots.txt".to_string(), b"User-agent: *\nDisallow: /secret\n".to_vec(), "Server: T\r\n".to_string()),
    ("/secret".to_string(), b"secret".to_vec(), "Server: T\r\n".to_string()),
    ("/public".to_string(), b"public".to_vec(), "Server: T\r\n".to_string()),
    ("/".to_string(), b"<html><a href=\"/secret\">s</a><a href=\"/public\">p</a><a href=\"/a\">a</a></html>".to_vec(), "Server: T\r\n".to_string()),
    ("/a".to_string(), b"<html><a href=\"/b\">b</a></html>".to_vec(), "Server: T\r\n".to_string()),
    ("/b".to_string(), b"<html><a href=\"/c\">c</a></html>".to_vec(), "Server: T\r\n".to_string()),
    ("/c".to_string(), b"deep".to_vec(), "Server: T\r\n".to_string()),
  ])
  .await;
  let (pages, _) = clops_core::spider::crawl_depth(&format!("{base}/"), 20, 1, 3000).await;
  let urls: Vec<String> = pages.iter().map(|p| p.url.clone()).collect();
  assert!(!urls.iter().any(|u| u.ends_with("/secret")), "robots must exclude secret, got {urls:?}");
  assert!(!urls.iter().any(|u| u.ends_with("/c")), "depth 1 must not reach /c, got {urls:?}");
  let (pages3, _) = clops_core::spider::crawl_depth(&format!("{base}/"), 20, 5, 3000).await;
  assert!(pages3.iter().any(|p| p.url.ends_with("/c")), "depth 5 must reach /c");
}

#[tokio::test]
async fn sqli_post_real() {
  let base = start_raw(vec![("/sqli".to_string(), b"rows".to_vec(), "Server: T\r\n".to_string())]).await;
  let url = format!("{base}/sqli");
  let found = sqli::check_post(&url, &["id".to_string()], 4000, false).await;
  assert!(found.iter().any(|f| f.kind.contains("error-based")), "POST error SQLi must flag, got {found:?}");
}

#[tokio::test]
async fn xss_encoded_flag_real() {
  let base = start_raw(vec![("/x".to_string(), b"".to_vec(), "Server: T\r\n".to_string())]).await;
  // Custom reflect server inline: reflect q raw
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await.unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let tgt = req.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
        let q = tgt.split("q=").nth(1).unwrap_or("").split('&').next().unwrap_or("").to_string();
        let body = format!("<html>{}</html>", pct(&q));
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = s.write_all(head.as_bytes()).await;
        let _ = s.write_all(body.as_bytes()).await;
      });
    }
  });
  let _ = base;
  let found = xss::check(&format!("http://127.0.0.1:{port}/x?q=h"), &["q".to_string()], 4000).await;
  assert!(!found.is_empty());
  assert!(!found[0].encoded, "raw reflect must report encoded=false");
}

#[tokio::test]
async fn lfi_win_marker_real() {
  let base = start_raw(vec![("/f".to_string(), b"".to_vec(), "Server: T\r\n".to_string())]).await;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await.unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let tgt = req.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
        let body = if tgt.contains("win.ini") {
          "[extensions]\nfor 16-bit app support".to_string()
        } else {
          "file ok".to_string()
        };
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = s.write_all(head.as_bytes()).await;
        let _ = s.write_all(body.as_bytes()).await;
      });
    }
  });
  let _ = base;
  let found = clops_core::lfi::check(&format!("http://127.0.0.1:{port}/f?file=x"), &["file".to_string()], 4000).await;
  assert!(found.iter().any(|f| f.evidence.contains("win.ini")), "must flag win.ini, got {found:?}");
}

#[tokio::test]
async fn misconfig_hsts_csp_listing_real() {
  let base = start_raw(vec![
    ("/uploads/".to_string(), b"<html>Index of /uploads/</html>".to_vec(), "Server: T\r\n".to_string()),
    ("/".to_string(), b"home".to_vec(), "Server: PlainSrv\r\n".to_string()),
  ])
  .await;
  let found = clops_core::misconfig::check(&base, 4000).await;
  assert!(found.iter().any(|f| f.check == "Missing HSTS"), "HSTS must flag, got {found:?}");
  assert!(found.iter().any(|f| f.check == "Missing CSP"), "CSP must flag, got {found:?}");
  assert!(found.iter().any(|f| f.check == "Directory listing"), "listing must flag, got {found:?}");
}

#[test]
fn repeater_history_cap_real() {
  let mut h = repeater::History::new();
  for i in 0..205 {
    h.push("GET", &format!("http://x/{i}"), repeater::ReplayResult { status: 200, time_ms: 1, length: 1, body_preview: "b".into() });
  }
  assert_eq!(h.len(), 200);
  assert!(h.last().unwrap().1.ends_with("/204"));
}

#[tokio::test]
async fn proxy_connect_relay_real() {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  // Echo target
  let eln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let eport = eln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = eln.accept().await else { break };
      tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
          let n = s.read(&mut buf).await.unwrap_or(0);
          if n == 0 {
            break;
          }
          if s.write_all(&buf[..n]).await.is_err() {
            break;
          }
        }
      });
    }
  });
  let scope = clops_core::scope::Scope::lab_only();
  let hist = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
  let pln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let pport = pln.local_addr().unwrap().port();
  drop(pln);
  let h2 = hist.clone();
  tokio::spawn(async move {
    let _ = proxy::run(&format!("127.0.0.1:{pport}"), scope, h2, 4000).await;
  });
  tokio::time::sleep(std::time::Duration::from_millis(200)).await;
  let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{pport}")).await.unwrap();
  s.write_all(format!("CONNECT 127.0.0.1:{eport} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes()).await.unwrap();
  let mut buf = vec![0u8; 4096];
  let n = tokio::time::timeout(std::time::Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap();
  assert!(String::from_utf8_lossy(&buf[..n]).contains("200"), "tunnel must establish");
  s.write_all(b"ping-tunnel").await.unwrap();
  let n2 = tokio::time::timeout(std::time::Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap();
  assert!(String::from_utf8_lossy(&buf[..n2]).contains("ping-tunnel"), "tunnel must relay bytes");
}

#[test]
fn pcap_dns_query_real() {
  // Ethernet + IPv4 + UDP dport 53 + DNS query for example.com
  let mut pkt = vec![0u8; 14];
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  let mut ip = vec![0u8; 20];
  ip[0] = 0x45;
  ip[9] = 17;
  ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
  ip[16..20].copy_from_slice(&[8, 8, 8, 8]);
  let mut udp = vec![0u8; 8];
  udp[0..2].copy_from_slice(&[0x14, 0x35]);
  udp[2..4].copy_from_slice(&[0x00, 0x35]);
  let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
  dns.push(7);
  dns.extend(b"example");
  dns.push(3);
  dns.extend(b"com");
  dns.push(0);
  dns.extend([0x00, 0x01, 0x00, 0x01]);
  let udp_len = (8 + dns.len()) as u16;
  udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
  let total = (20 + udp_len as usize) as u16;
  ip[2..4].copy_from_slice(&total.to_be_bytes());
  let mut frame: Vec<u8> = Vec::new();
  frame.extend(pkt);
  frame.extend(ip);
  frame.extend(udp);
  frame.extend(dns);
  let mut data = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
  let l = frame.len() as u32;
  data.extend([0, 0, 0, 0, 0, 0, 0, 0]);
  data.extend(l.to_le_bytes());
  data.extend(l.to_le_bytes());
  data.extend(frame);
  let flows = pcap::parse_bytes(&data).unwrap();
  assert_eq!(flows.len(), 1);
  assert!(flows[0].summary.contains("example.com"), "DNS name must decode, got {:?}", flows[0].summary);
}

#[test]
fn cve_new_entries_real() {
  let o = cve::match_service("openssl", "OpenSSL/1.0.1f", None);
  assert!(o.iter().any(|x| x.id == "CVE-2014-0160"));
  let l = cve::match_service("log4j", "2.14.0", None);
  assert!(l.iter().any(|x| x.id == "CVE-2021-44228"));
}

#[test]
fn payload_encode_real() {
  let b = payload::generate("bash", "10.0.0.1", 4444);
  let e = payload::encode_shell(&b.code, "base64");
  assert!(e.contains("base64 -d"));
  let u = payload::encode_shell("a b", "url");
  assert!(u.contains("%20"));
}

#[test]
fn codec_time_uuid_real() {
  assert!(codec::unix_to_utc(0).contains("1970"));
  let id = codec::new_uuid();
  assert_eq!(id.len(), 36);
  assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
}

#[test]
fn cracker_rules_hybrid_real() {
  let r = cracker::apply_rules("Test");
  assert!(r.contains(&"test".to_string()) && r.contains(&"TEST".to_string()));
  let target = clops_core::hash::md5_hex("hi07");
  let st = cracker::hybrid_attack("MD5", &target, &["hi".to_string()], 5);
  assert_eq!(st.password.unwrap(), "hi07");
}

#[test]
fn wordlist_regex_lua_real() {
  let w = vec!["admin".to_string(), " admi n".to_string(), "login123".to_string()];
  let f = wordlist::filter_regex(w, r"^[a-z]+$");
  assert_eq!(f, vec!["admin".to_string()]);
  let t = wordlist::transform_lua(&["ab".to_string()], "function t(w) return w:upper() end").unwrap();
  assert_eq!(t, vec!["AB".to_string()]);
}

#[test]
fn osint_dork_real() {
  let u = osint::github_dork_url("example.com", "secrets");
  assert!(u.starts_with("https://github.com/search?") && u.contains("example.com"));
}

#[tokio::test]
async fn chain_execute_recon_real() {
  let (lines, vars) = chain::execute_recon("127.0.0.1", 400).await;
  assert_eq!(lines.len(), 2);
  assert_eq!(vars.get("target").unwrap(), "127.0.0.1");
}

#[test]
fn ai_replay_real() {
  let plan = ai::plan("full chain", "example.com");
  let mut log = Vec::new();
  for s in plan.steps.iter().take(2) {
    ai::log_step(&mut log, s, true);
  }
  let r = ai::replay(&log);
  assert_eq!(r.len(), 2);
  assert!(r[0].contains("approved=true"));
}

#[test]
fn report_order_real() {
  let findings = vec![
    report::ReportFinding { tool: "T05".into(), severity: "Low".into(), title: "l".into(), evidence: "e".into() },
    report::ReportFinding { tool: "T10".into(), severity: "Critical".into(), title: "c".into(), evidence: "e".into() },
  ];
  let html = report::to_html("p", "s", &findings, &[]);
  let ci = html.find("Critical").unwrap();
  let li = html.find(">Low<").unwrap();
  assert!(ci < li, "critical must sort first");
  assert!(html.contains("Counts:"));
}

#[tokio::test]
async fn scan_many_refined_http_port_real() {
  // scan_many_refined only refines http-like ports by policy. Bind the
  // conventional lab port when free, else skip honestly.
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let ln = match tokio::net::TcpListener::bind("127.0.0.1:18080").await {
    Ok(l) => l,
    Err(_) => return,
  };
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let _ = s.read(&mut buf).await;
        let body = b"<html><head><title>Ref18080</title></head></html>";
        let head = format!(
          "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nServer: RefSrv/3.0\r\nConnection: close\r\n\r\n",
          body.len()
        );
        let _ = s.write_all(head.as_bytes()).await;
        let _ = s.write_all(body).await;
      });
    }
  });
  tokio::time::sleep(std::time::Duration::from_millis(100)).await;
  let out = clops_core::scan::scan_many_refined("127.0.0.1", &[18080], 3000, 2, 2).await;
  let f = out.iter().find(|f| f.port == 18080).unwrap();
  assert!(f.open);
  assert!(f.version.contains("RefSrv") || f.version.contains("Ref18080"), "got {:?}", f.version);
}

#[test]
fn pcap_fixture_file_real() {
  let flows = clops_core::pcap::parse_file(std::path::Path::new("../../tests/fixtures/generated.pcap")).unwrap();
  assert_eq!(flows.len(), 2);
  assert!(flows.iter().any(|f| f.proto == "TCP" && f.dport == 80));
  assert!(flows.iter().any(|f| f.summary.contains("lab.example.com")), "got {flows:?}");
}
