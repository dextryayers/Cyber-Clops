use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
  pub status: u16,
  pub server: String,
  pub title: String,
  pub headers: HashMap<String, String>,
  pub body: String,
  pub waf: String,
  pub time_ms: u64,
}

fn detect_waf(headers: &HashMap<String, String>, body: &str) -> String {
  let joined: String = headers.values().cloned().collect::<Vec<_>>().join(" ").to_lowercase();
  if joined.contains("cloudflare") || joined.contains("cf-ray") || joined.contains("__cf_bm") {
    return "Cloudflare".into();
  }
  if joined.contains("akamai") || joined.contains("ak_bmsc") {
    return "Akamai".into();
  }
  if joined.contains("imperva") || joined.contains("incap_ses") || joined.contains("visid_incap") {
    return "Imperva".into();
  }
  if joined.contains("sucuri") || joined.contains("x-sucuri") {
    return "Sucuri".into();
  }
  if joined.contains("bigip") || joined.contains("f5_") {
    return "F5 BIG-IP".into();
  }
  if body.contains("Access denied") && joined.contains("mod_security") {
    return "ModSecurity".into();
  }
  if joined.contains("x-amz-cf-id") || joined.contains("cloudfront") {
    return "CloudFront".into();
  }
  if joined.contains("fastly") || joined.contains("x-served-by") && joined.contains("cache-") {
    return "Fastly".into();
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
// Multi value headers such as set-cookie are joined with newline so no
// signal is lost. Body is capped at 200 KB for detector reuse.
pub async fn fetch(url: &str, timeout_ms: u64) -> anyhow::Result<HttpResult> {
  let start = std::time::Instant::now();
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::limited(3))
    .user_agent("Cyber-Clops/2.0")
    .build()?;
  let resp = client.get(url).send().await?;
  let status = resp.status().as_u16();
  let mut headers: HashMap<String, String> = HashMap::new();
  for (k, v) in resp.headers().iter() {
    let val = v.to_str().unwrap_or("").to_string();
    headers
      .entry(k.to_string())
      .and_modify(|e| {
        e.push('\n');
        e.push_str(&val);
      })
      .or_insert(val);
  }
  let server = headers.get("server").cloned().unwrap_or_default();
  let full = resp.text().await.unwrap_or_default();
  let body: String = full.chars().take(200_000).collect();
  let waf = detect_waf(&headers, &body);
  Ok(HttpResult {
    status,
    server,
    title: parse_title(&body),
    headers,
    body,
    waf,
    time_ms: start.elapsed().as_millis() as u64,
  })
}
