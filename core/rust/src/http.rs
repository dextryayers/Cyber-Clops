use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
  pub status: u16,
  pub server: String,
  pub title: String,
  pub headers: HashMap<String, String>,
  pub waf: String,
  pub time_ms: u64,
}

fn detect_waf(headers: &HashMap<String, String>, body: &str) -> String {
  let joined: String = headers.values().cloned().collect::<Vec<_>>().join(" ").to_lowercase();
  if joined.contains("cloudflare") || joined.contains("cf-ray") {
    return "Cloudflare".into();
  }
  if joined.contains("akamai") {
    return "Akamai".into();
  }
  if body.contains("Access denied") && joined.contains("imperva") {
    return "Imperva".into();
  }
  String::new()
}

fn parse_title(body: &str) -> String {
  let low = body.to_lowercase();
  if let Some(s) = low.find("<title>") {
    if let Some(e) = low[s..].find("</title>") {
      let raw = &body[s + 7..s + e];
      return raw.trim().chars().take(120).collect();
    }
  }
  String::new()
}

// Real HTTP fetch with rustls, no openssl link needed.
pub async fn fetch(url: &str, timeout_ms: u64) -> anyhow::Result<HttpResult> {
  let start = std::time::Instant::now();
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::limited(3))
    .user_agent("Cyber-Clops/2.0")
    .build()?;
  let resp = client.get(url).send().await?;
  let status = resp.status().as_u16();
  let mut headers = HashMap::new();
  for (k, v) in resp.headers().iter() {
    headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
  }
  let server = headers.get("server").cloned().unwrap_or_default();
  let body = resp.text().await.unwrap_or_default();
  let waf = detect_waf(&headers, &body);
  Ok(HttpResult {
    status,
    server,
    title: parse_title(&body),
    headers,
    waf,
    time_ms: start.elapsed().as_millis() as u64,
  })
}
