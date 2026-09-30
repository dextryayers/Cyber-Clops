use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirFinding {
  pub path: String,
  pub status: u16,
  pub length: u64,
  pub time_ms: u64,
}

async fn calibrate(base: &str, client: &reqwest::Client) -> (HashSet<u64>, HashSet<String>) {
  let mut lens = HashSet::new();
  let mut hashes = HashSet::new();
  for i in 0..3 {
    let token = format!("__clops{}_", i);
    let url = format!("{}{}", base.trim_end_matches('/'), format!("/{token}"));
    if let Ok(r) = client.get(&url).send().await {
      let body = r.text().await.unwrap_or_default();
      lens.insert(body.len() as u64);
      hashes.insert(crate::hash::md5_hex(&body));
    }
  }
  (lens, hashes)
}

// Real dir brute with smart 404 filter, 429 backoff, checkpoint offset.
// Checkpoint is the start index. Caller persists last index for resume.
#[derive(Debug, Clone)]
pub struct BruteOptions {
  pub extensions: Vec<String>,
  pub status_allow: Vec<u16>,
  pub start_offset: usize,
  pub rate_rps: u32,
}

impl Default for BruteOptions {
  fn default() -> Self {
    Self { extensions: Vec::new(), status_allow: Vec::new(), start_offset: 0, rate_rps: 0 }
  }
}

fn with_extensions(word: &str, exts: &[String]) -> Vec<String> {
  if exts.is_empty() {
    return vec![word.to_string()];
  }
  let mut out = vec![word.to_string()];
  for e in exts {
    let e = e.trim_start_matches('.');
    out.push(format!("{word}.{e}"));
  }
  out
}

pub async fn brute(
  base: &str,
  words: &[String],
  concurrency: usize,
  timeout_ms: u64,
  start_offset: usize,
) -> Vec<DirFinding> {
  brute_advanced(base, words, concurrency, timeout_ms, BruteOptions { start_offset, ..Default::default() }).await
}

// Full variant with extensions, status allowlist, jittered 429 backoff.
pub async fn brute_advanced(
  base: &str,
  words: &[String],
  concurrency: usize,
  timeout_ms: u64,
  opts: BruteOptions,
) -> Vec<DirFinding> {
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::none())
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  let (lens, hashes) = calibrate(base, &client).await;
  use tokio::sync::Semaphore;
  use std::sync::Arc;
  let sem = Arc::new(Semaphore::new(concurrency.max(1).min(500)));
  // Honest rate cap. A shared dispatch gate spaces request starts at
  // 1000/rate_rps ms apart. Zero means unlimited.
  let gate = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
  let interval_ms: u64 = if opts.rate_rps == 0 { 0 } else { (1000 / opts.rate_rps.max(1) as u64).max(1) };
  // Expand extensions before fanout so checkpoint math stays on words.
  let mut expanded: Vec<(usize, String)> = Vec::new();
  for (idx, w) in words.iter().enumerate() {
    if idx < opts.start_offset {
      continue;
    }
    let w = w.trim().to_string();
    if w.is_empty() || w.starts_with('#') {
      continue;
    }
    for cand in with_extensions(&w, &opts.extensions) {
      expanded.push((idx, cand));
    }
  }
  let mut handles = Vec::new();
  for (idx, w) in expanded {
    let b = base.to_string();
    let c = client.clone();
    let s = sem.clone();
    let g = gate.clone();
    let lens_c = lens.clone();
    let hashes_c = hashes.clone();
    let allow = opts.status_allow.clone();
    handles.push(tokio::spawn(async move {
      let _p = s.acquire_owned().await.unwrap();
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
      let url = format!("{}/{w}", b.trim_end_matches('/'));
      let t0 = std::time::Instant::now();
      let resp = c.get(&url).send().await;
      match resp {
        Ok(r) => {
          let status = r.status().as_u16();
          if status == 429 {
            // Jittered backoff 600 to 1200 ms so retries do not re-thunder.
            let jitter = (idx as u64 * 37) % 600;
            tokio::time::sleep(std::time::Duration::from_millis(600 + jitter)).await;
            return None;
          }
          if status == 404 {
            return None;
          }
          if !allow.is_empty() && !allow.contains(&status) {
            return None;
          }
          let body = r.text().await.unwrap_or_default();
          let len = body.len() as u64;
          let h = crate::hash::md5_hex(&body);
          if lens_c.contains(&len) && hashes_c.contains(&h) {
            return None;
          }
          Some(DirFinding { path: format!("/{w}"), status, length: len, time_ms: t0.elapsed().as_millis() as u64 })
        }
        Err(_) => None,
      }
    }));
  }
  let mut out = Vec::new();
  for h in handles {
    if let Ok(Some(f)) = h.await {
      out.push(f);
    }
  }
  out.sort_by(|a, b| a.path.cmp(&b.path));
  out
}

pub fn load_wordlist(path: &std::path::Path) -> Vec<String> {
  std::fs::read_to_string(path)
    .unwrap_or_default()
    .lines()
    .map(|s| s.to_string())
    .collect()
}

#[allow(dead_code)]
pub fn unused_map() -> HashMap<String, String> {
  HashMap::new()
}
