use clops_core::{dns, hash, lua, scan, scope};
use tokio::io::AsyncWriteExt;

// Real case, no mocks. Local lab plus one polite public check.
#[tokio::test]
async fn lab_port_scan_finds_open() {
  let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = ln.local_addr().unwrap().port();
  tokio::spawn(async move {
    loop {
      let Ok((mut s, _)) = ln.accept().await else { break };
      let _ = s.write_all(b"SSH-2.0-OpenSSH_9.2 lab\r\n").await;
    }
  });
  tokio::time::sleep(std::time::Duration::from_millis(100)).await;
  let f = scan::scan_one("127.0.0.1", port, 2000).await;
  assert!(f.open, "lab port should be open");
  assert_eq!(f.service, "ssh");
  assert!(f.banner.contains("SSH-2.0"));
}

#[tokio::test]
async fn dns_resolves_example() {
  let ips = dns::resolve("example.com").await.unwrap();
  assert!(!ips.is_empty(), "example.com must resolve");
}

#[test]
fn hash_and_lua_real() {
  assert_eq!(hash::md5_hex("hello"), "5d41402abc4b2a76b9719d911017c592");
  let out = lua::run_snippet("return clops.sha256('hello')").unwrap();
  assert!(out.contains("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
}

#[test]
fn scope_rejects_outside() {
  let s = scope::Scope::lab_only();
  assert!(s.is_allowed("127.0.0.1"));
  assert!(!s.is_allowed("evil.example.net"));
}
