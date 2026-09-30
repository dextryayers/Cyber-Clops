use clops_core::{ai, chain, codec, cracker, cve, osint, payload, pcap, report, wordlist};
use std::collections::HashMap;

#[test]
fn t19_codec_real() {
  assert_eq!(codec::b64_encode("hello"), "aGVsbG8=");
  assert_eq!(codec::b64_decode("aGVsbG8=").unwrap(), "hello");
  assert_eq!(codec::hex_encode("hi"), "6869");
  assert_eq!(codec::hex_decode("6869").unwrap(), "hi");
  assert_eq!(codec::url_encode("a b"), "a%20b");
  assert_eq!(codec::url_decode("a%20b"), "a b");
  assert!(codec::html_escape("<b>").contains("&lt;"));
  // Real JWT: header eyJhbGciOiJIUzI1NiJ9 = {"alg":"HS256"}
  let tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  let j = codec::jwt_parse(tok).unwrap();
  assert_eq!(j.alg, "HS256");
  assert!(j.payload.contains('1'));
  // Bulk file real in tmp
  let dir = std::env::temp_dir();
  let inp = dir.join("clops_codec_in.txt");
  let out = dir.join("clops_codec_out.b64");
  std::fs::write(&inp, "hello\nworld\n").unwrap();
  let n = codec::bulk_base64_encode_file(&inp, &out).unwrap();
  assert!(n > 0 && out.exists());
  assert!(codec::b64_decode("!!!notbase64!!!").is_err());
}

#[test]
fn t20_cracker_real() {
  let hs = cracker::bench("MD5");
  assert!(hs > 1000, "bench must measure real speed, got {hs}");
  let words = vec!["world".to_string(), "hello".to_string()];
  let target = clops_core::hash::md5_hex("hello");
  let dir = std::env::temp_dir();
  let cp = dir.join("clops_crack_cp.txt");
  let _ = std::fs::remove_file(&cp);
  let st = cracker::dict_attack("MD5", &target, &words, Some(&cp));
  assert_eq!(st.password.unwrap(), "hello");
  assert!(st.hs > 0 && !st.backend.is_empty());
  // Mask ?d?d finds 07
  let t07 = clops_core::hash::md5_hex("07");
  let m = cracker::mask_attack("MD5", &t07, "?d?d", 500);
  assert_eq!(m.password.unwrap(), "07");
  assert!(m.tested > 0);
}

#[test]
fn t21_wordlist_real() {
  let w = vec!["Admin".to_string(), "admin".to_string(), "".to_string(), "Login".to_string()];
  let d = wordlist::dedupe(w);
  assert!(d.contains(&"Admin".to_string()));
  let m = wordlist::mutate_basic(&["Test".to_string()]);
  assert!(m.contains(&"test".to_string()) && m.contains(&"TEST".to_string()));
  let c = wordlist::combine(&["a".to_string()], &["1".to_string(), "2".to_string()], "", 10);
  assert_eq!(c.len(), 2);
  let s = wordlist::stats(&["ab".to_string(), "abcd".to_string()], 1000);
  assert_eq!(s.total, 2);
  assert!(s.est_seconds_md5 > 0.0);
  let dir = std::env::temp_dir();
  let inp = dir.join("clops_wl_in.txt");
  let out = dir.join("clops_wl_out.txt");
  std::fs::write(&inp, "Hello\n\nWORLD\n").unwrap();
  let n = wordlist::stream_file(&inp, &out).unwrap();
  assert_eq!(n, 2);
  let body = std::fs::read_to_string(&out).unwrap();
  assert!(body.contains("hello") && body.contains("world"));
}

#[test]
fn t22_breach_and_mx_real() {
  let dir = std::env::temp_dir();
  let f = dir.join("clops_breach.txt");
  std::fs::write(&f, "alice@example.com:hash1\nbob@test.com:hash2\n").unwrap();
  let hits = osint::breach_match("alice", &f);
  assert_eq!(hits.len(), 1);
  // MX real runs without panic. example.com may have no MX, so only assert it returns vec.
  let _ = tokio::runtime::Runtime::new().unwrap().block_on(osint::email_mx("example.com"));
}

#[tokio::test]
async fn t22_username_slow_real() {
  // Polite real check for a highly unlikely name. Must return 4 rows, mostly not found, no panic.
  let out = osint::username_check("clopsunlikelyname99999", 6000).await;
  assert_eq!(out.len(), 4);
}

#[test]
fn t23_chain_real() {
  let c = chain::recon_chain("example.com");
  assert_eq!(c.steps.len(), 5);
  let mut vars = HashMap::new();
  vars.insert("target".to_string(), "example.com".to_string());
  assert_eq!(chain::render("scan {{target}}", &vars), "scan example.com");
  let dry = chain::dry_run(&c, &vars);
  assert_eq!(dry.len(), 5);
  assert!(dry[0].contains("T01"));
  let dir = std::env::temp_dir();
  let p = dir.join("clops_chain.json");
  chain::save_json(&c, &p).unwrap();
  let back = chain::load_json(&p).unwrap();
  assert_eq!(back.name, c.name);
}

#[test]
fn t24_ai_gates_real() {
  let p = ai::plan("recon only", "example.com");
  assert!(p.steps.len() >= 3);
  let full = ai::plan("full chain", "example.com");
  assert!(full.steps.iter().any(|s| s.needs_approval));
  // Low auto passes, medium without approve fails
  let low = &p.steps[0];
  assert!(ai::gate(low, false).is_ok());
  let med = full.steps.iter().find(|s| s.needs_approval).unwrap();
  assert!(ai::gate(med, false).is_err());
  assert!(ai::gate(med, true).is_ok());
  // Redact real AWS example key
  let r = ai::redact("key AKIAIOSFODNN7EXAMPLE here");
  assert!(!r.contains("AKIA") && r.contains("[REDACTED]"));
}

#[tokio::test]
async fn t24_ollama_probe_real() {
  // Must not panic when Ollama is down. Returns vec either way.
  let m = ai::ollama_models(1500).await;
  let _ = m.len();
}

#[test]
fn t25_report_redact_real() {
  let findings = vec![
    report::ReportFinding {
      tool: "T09".into(),
      severity: "High".into(),
      title: "AWS key".into(),
      evidence: "found AKIAIOSFODNN7EXAMPLE in app.js cookie sess=abc".into(),
    },
  ];
  let html = report::to_html("demo", "lab-only", &findings, &["run T09".into()]);
  assert!(html.contains("demo") && html.contains("[REDACTED]"));
  assert!(!html.contains("AKIAIOSFODNN7EXAMPLE"));
  let j = report::to_json("demo", &findings, &[]);
  assert!(j.contains("demo"));
}

#[test]
fn hardening_no_panic_real() {
  assert!(pcap::parse_bytes(b"short").is_err());
  assert!(pcap::parse_bytes(&[0u8; 100]).is_err());
  assert!(codec::jwt_parse("bad.token").is_err());
  assert!(codec::b64_decode("!!!").is_err());
  assert!(cve::match_service("nosuchsvc", "1.0", None).is_empty());
  let _ = payload::generate("bash", "127.0.0.1", 1);
}

#[tokio::test]
async fn perf_scan_20_ports_fast_real() {
  use std::time::Instant;
  let t0 = Instant::now();
  let ports: Vec<u16> = (55000..55020).collect();
  let out = clops_core::scan::scan_many("127.0.0.1", &ports, 300, 10).await;
  assert_eq!(out.len(), 20);
  assert!(t0.elapsed().as_secs() < 20, "20 closed ports must finish well under 20s");
}
