use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortFinding {
  pub port: u16,
  pub open: bool,
  pub banner: String,
  pub service: String,
  pub version: String,
  pub latency_ms: u64,
}

// Real TCP connect scan with timeout plus banner grab.
// Polite by default. Caller controls concurrency and rate.
pub async fn scan_one(host: &str, port: u16, timeout_ms: u64) -> PortFinding {
  let start = Instant::now();
  let addr = format!("{host}:{port}");
  let conn = timeout(std::time::Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await;
  match conn {
    Ok(Ok(mut s)) => {
      let latency = start.elapsed().as_millis() as u64;
      let mut buf = vec![0u8; 4096];
      let banner = match timeout(
        std::time::Duration::from_millis(timeout_ms),
        s.read(&mut buf),
      )
      .await
      {
        Ok(Ok(n)) if n > 0 => sanitize(&buf[..n]),
        _ => String::new(),
      };
      let (service, version) = guess_service(port, &banner);
      PortFinding { port, open: true, banner, service, version, latency_ms: latency }
    }
    _ => PortFinding {
      port,
      open: false,
      banner: String::new(),
      service: String::new(),
      version: String::new(),
      latency_ms: start.elapsed().as_millis() as u64,
    },
  }
}

fn sanitize(b: &[u8]) -> String {
  String::from_utf8_lossy(b)
    .chars()
    .map(|c| if c.is_control() && c != '\r' && c != '\n' && c != '\t' { '.' } else { c })
    .take(512)
    .collect()
}

fn guess_service(port: u16, banner: &str) -> (String, String) {
  let b = banner.trim();
  if b.starts_with("SSH-") {
    let v = b.lines().next().unwrap_or("").to_string();
    return ("ssh".into(), v);
  }
  if b.starts_with("220") {
    return ("ftp-or-smtp".into(), b.lines().next().unwrap_or("").to_string());
  }
  if port == 80 || port == 8000 || port == 8080 || port == 18080 {
    return ("http".into(), String::new());
  }
  if port == 443 || port == 8443 || port == 18443 {
    return ("https".into(), String::new());
  }
  ("unknown".into(), String::new())
}

// Refine HTTP service version with real GET. Called only for http-like ports to stay polite.
pub async fn refine_http(host: &str, port: u16, timeout_ms: u64) -> (String, String) {
  let scheme = if port == 443 || port == 8443 || port == 18443 { "https" } else { "http" };
  let url = format!("{scheme}://{host}:{port}/");
  match crate::http::fetch(&url, timeout_ms).await {
    Ok(r) => {
      let ver = if r.server.is_empty() { r.title.clone() } else if r.title.is_empty() { r.server.clone() } else { format!("{} | {}", r.server, r.title) };
      ("http".to_string(), ver.chars().take(128).collect())
    }
    Err(_) => ("http".to_string(), String::new()),
  }
}

pub async fn scan_many(host: &str, ports: &[u16], timeout_ms: u64, concurrency: usize) -> Vec<PortFinding> {
  use tokio::sync::Semaphore;
  use std::sync::Arc;
  let sem = Arc::new(Semaphore::new(concurrency.max(1)));
  let mut handles = Vec::new();
  for &p in ports {
    let h = host.to_string();
    let s = sem.clone();
    handles.push(tokio::spawn(async move {
      let _permit = s.acquire_owned().await.unwrap();
      scan_one(&h, p, timeout_ms).await
    }));
  }
  let mut out = Vec::new();
  for h in handles {
    if let Ok(f) = h.await {
      out.push(f);
    }
  }
  out.sort_by_key(|f| f.port);
  out
}

// Live variant. Sends each finding the moment its probe completes.
// UI renders rows as they arrive instead of waiting for the full range.
pub async fn scan_many_stream(
  host: &str,
  ports: &[u16],
  timeout_ms: u64,
  concurrency: usize,
  tx: tokio::sync::mpsc::Sender<PortFinding>,
) {
  use tokio::sync::Semaphore;
  use std::sync::Arc;
  let sem = Arc::new(Semaphore::new(concurrency.max(1)));
  let mut handles = Vec::new();
  for &p in ports {
    let h = host.to_string();
    let s = sem.clone();
    let t = tx.clone();
    handles.push(tokio::spawn(async move {
      let _permit = s.acquire_owned().await.unwrap();
      let f = scan_one(&h, p, timeout_ms).await;
      let _ = t.send(f).await;
    }));
  }
  for h in handles {
    let _ = h.await;
  }
}

fn is_http_like(port: u16) -> bool {
  matches!(port, 80 | 8000 | 8080 | 18080 | 443 | 8443 | 18443 | 3000 | 5000 | 9000)
}

// Refined variant. Open http-like ports with empty version get one real
// GET each via refine_http. Non-HTTP ports are untouched. Bounded by
// refine_concurrency so a wide range of web servers cannot stampede the target.
pub async fn scan_many_refined(
  host: &str,
  ports: &[u16],
  timeout_ms: u64,
  concurrency: usize,
  refine_concurrency: usize,
) -> Vec<PortFinding> {
  let mut out = scan_many(host, ports, timeout_ms, concurrency).await;
  use tokio::sync::Semaphore;
  use std::sync::Arc;
  let sem = Arc::new(Semaphore::new(refine_concurrency.max(1).min(16)));
  let targets: Vec<u16> = out
    .iter()
    .filter(|f| f.open && f.version.is_empty() && is_http_like(f.port))
    .map(|f| f.port)
    .collect();
  let mut handles = Vec::new();
  for port in targets {
    let h = host.to_string();
    let s = sem.clone();
    handles.push(tokio::spawn(async move {
      let _permit = s.acquire_owned().await.unwrap();
      let (svc, ver) = refine_http(&h, port, timeout_ms / 2 + 1000).await;
      (port, svc, ver)
    }));
  }
  for h in handles {
    if let Ok((port, svc, ver)) = h.await {
      if let Some(f) = out.iter_mut().find(|f| f.port == port) {
        f.service = svc;
        f.version = ver;
      }
    }
  }
  out
}

// Rated variant. Same probes as scan_many, but dispatch gate spaces probe
// starts at 1000/rate_rps ms apart. Zero means unlimited and behaves
// exactly like scan_many.
pub async fn scan_many_rated(
  host: &str,
  ports: &[u16],
  timeout_ms: u64,
  concurrency: usize,
  rate_rps: u32,
) -> Vec<PortFinding> {
  use tokio::sync::Semaphore;
  use std::sync::Arc;
  let sem = Arc::new(Semaphore::new(concurrency.max(1)));
  let gate = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
  let interval_ms: u64 = if rate_rps == 0 { 0 } else { (1000u64 / rate_rps.max(1) as u64).max(1) };
  let mut handles = Vec::new();
  for &p in ports {
    let h = host.to_string();
    let s = sem.clone();
    let g = gate.clone();
    handles.push(tokio::spawn(async move {
      let _permit = s.acquire_owned().await.unwrap();
      if interval_ms > 0 {
        loop {
          let wait = {
            let mut last = g.lock().unwrap();
            let now = std::time::Instant::now();
            let next = *last + std::time::Duration::from_millis(interval_ms);
            if now >= next {
              *last = now;
              None
            } else {
              Some(next - now)
            }
          };
          match wait {
            None => break,
            Some(d) => tokio::time::sleep(d).await,
          }
        }
      }
      scan_one(&h, p, timeout_ms).await
    }));
  }
  let mut out = Vec::new();
  for h in handles {
    if let Ok(f) = h.await {
      out.push(f);
    }
  }
  out.sort_by_key(|f| f.port);
  out
}
