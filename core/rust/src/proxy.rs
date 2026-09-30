use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
  pub method: String,
  pub url: String,
  pub status: u16,
  pub length: u64,
}

// Scope check helper: allow only hosts in scope.
fn allowed(scope: &crate::scope::Scope, url: &str) -> bool {
  if let Ok(u) = reqwest::Url::parse(url) {
    if let Some(h) = u.host_str() {
      return scope.is_allowed(h);
    }
  }
  scope.is_allowed(url)
}

// Real forward with scope gate. Used by listener and by tests.
pub async fn forward(
  scope: &crate::scope::Scope,
  history: &Arc<Mutex<Vec<ProxyEntry>>>,
  method: &str,
  url: &str,
  timeout_ms: u64,
) -> anyhow::Result<(u16, Vec<u8>)> {
  if !allowed(scope, url) {
    anyhow::bail!("target outside scope");
  }
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::none())
    .user_agent("Cyber-Clops/2.0")
    .build()?;
  let m = match method.to_uppercase().as_str() {
    "POST" => reqwest::Method::POST,
    _ => reqwest::Method::GET,
  };
  let resp = client.request(m, url).send().await?;
  let status = resp.status().as_u16();
  let body = resp.bytes().await.unwrap_or_default().to_vec();
  let len = body.len() as u64;
  history.lock().unwrap().push(ProxyEntry {
    method: method.into(),
    url: url.into(),
    status,
    length: len,
  });
  Ok((status, body))
}

// Minimal HTTP forward proxy on 127.0.0.1. Supports absolute URI GET and POST.
// CONNECT is rejected in v1 with a clear message. History is shared.
pub async fn run(
  addr: &str,
  scope: crate::scope::Scope,
  history: Arc<Mutex<Vec<ProxyEntry>>>,
  timeout_ms: u64,
) -> anyhow::Result<()> {
  let ln = tokio::net::TcpListener::bind(addr).await?;
  loop {
    let Ok((mut s, _)) = ln.accept().await else { break };
    let h = history.clone();
    let sc = scope.clone();
    tokio::spawn(async move {
      use tokio::io::{AsyncReadExt, AsyncWriteExt};
      let mut buf = vec![0u8; 8192];
      let n = s.read(&mut buf).await.unwrap_or(0);
      if n == 0 {
        return;
      }
      let req = String::from_utf8_lossy(&buf[..n]).to_string();
      let line = req.lines().next().unwrap_or("");
      let mut parts = line.split_whitespace();
      let method = parts.next().unwrap_or("GET").to_string();
      let target = parts.next().unwrap_or("/").to_string();
      if method.to_uppercase() == "CONNECT" {
        // HTTPS tunnel. Scope gate on host, then blind TCP relay.
        // Encrypted bytes are never inspected. History records host and byte counts.
        let authority = target.clone();
        let host_only = authority.split(':').next().unwrap_or("").to_string();
        if !sc.is_allowed(&host_only) {
          let msg = "blocked: target outside scope";
          let head = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n", msg.len());
          let _ = s.write_all(head.as_bytes()).await;
          let _ = s.write_all(msg.as_bytes()).await;
          return;
        }
        let upstream = if authority.contains(':') { authority.clone() } else { format!("{authority}:443") };
        match tokio::net::TcpStream::connect(&upstream).await {
          Ok(mut up) => {
            let _ = s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
            let (mut ri, mut wi) = tokio::io::split(s);
            let (mut r_up, mut w_up) = up.split();
            let c1 = tokio::io::copy(&mut ri, &mut w_up);
            let c2 = tokio::io::copy(&mut r_up, &mut wi);
            let (n1, n2) = tokio::join!(c1, c2);
            h.lock().unwrap().push(ProxyEntry {
              method: "CONNECT".into(),
              url: format!("{upstream}"),
              status: 200,
              length: n1.unwrap_or(0) + n2.unwrap_or(0),
            });
          }
          Err(_) => {
            let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 7\r\n\r\nno route").await;
          }
        }
        return;
      }
      // Absolute URI expected in forward proxy mode. Fall back to Host header.
      let url = if target.starts_with("http") {
        target.clone()
      } else {
        let mut host = String::new();
        for l in req.lines() {
          if l.to_lowercase().starts_with("host:") {
            host = l[5..].trim().to_string();
            break;
          }
        }
        if host.is_empty() {
          let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nbad proxy").await;
          return;
        }
        format!("http://{host}{target}")
      };
      match forward(&sc, &h, &method, &url, timeout_ms).await {
        Ok((status, body)) => {
          let head = format!("HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
          let _ = s.write_all(head.as_bytes()).await;
          let _ = s.write_all(&body).await;
        }
        Err(e) => {
          let msg = format!("blocked: {e}");
          let head = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n", msg.len());
          let _ = s.write_all(head.as_bytes()).await;
          let _ = s.write_all(msg.as_bytes()).await;
        }
      }
    });
  }
  Ok(())
}
