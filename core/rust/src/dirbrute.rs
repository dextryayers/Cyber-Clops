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
pub async fn brute(
  base: &str,
  words: &[String],
  concurrency: usize,
  timeout_ms: u64,
  start_offset: usize,
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
  let mut handles = Vec::new();
  for (idx, w) in words.iter().enumerate() {
    if idx < start_offset {
      continue;
    }
    let w = w.trim().to_string();
    if w.is_empty() || w.starts_with('#') {
      continue;
    }
    let b = base.to_string();
    let c = client.clone();
    let s = sem.clone();
    let lens_c = lens.clone();
    let hashes_c = hashes.clone();
    handles.push(tokio::spawn(async move {
      let _p = s.acquire_owned().await.unwrap();
      let url = format!("{}/{w}", b.trim_end_matches('/'));
      let t0 = std::time::Instant::now();
      let resp = c.get(&url).send().await;
      match resp {
        Ok(r) => {
          let status = r.status().as_u16();
          if status == 429 {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            return None;
          }
          if status == 404 {
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
