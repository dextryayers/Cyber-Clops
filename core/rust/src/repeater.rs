use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
  pub status: u16,
  pub time_ms: u64,
  pub length: u64,
  pub body_preview: String,
}

// Real resend of a raw HTTP request to an in scope URL.
// Method, path, headers, body are explicit. No proxy magic in v1.
pub async fn resend(
  url: &str,
  method: &str,
  headers: Vec<(String, String)>,
  body: &str,
  timeout_ms: u64,
) -> anyhow::Result<ReplayResult> {
  let t0 = std::time::Instant::now();
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::none())
    .user_agent("Cyber-Clops/2.0")
    .build()?;
  let m = match method.to_uppercase().as_str() {
    "POST" => reqwest::Method::POST,
    "PUT" => reqwest::Method::PUT,
    "DELETE" => reqwest::Method::DELETE,
    "HEAD" => reqwest::Method::HEAD,
    "PATCH" => reqwest::Method::PATCH,
    _ => reqwest::Method::GET,
  };
  let mut req = client.request(m, url);
  for (k, v) in headers {
    req = req.header(k, v);
  }
  if !body.is_empty() {
    req = req.body(body.to_string());
  }
  let resp = req.send().await?;
  let status = resp.status().as_u16();
  let text = resp.text().await.unwrap_or_default();
  Ok(ReplayResult {
    status,
    time_ms: t0.elapsed().as_millis() as u64,
    length: text.len() as u64,
    body_preview: text.chars().take(2000).collect(),
  })
}

// Simple line diff for side by side view. Returns unified style hunks.
pub fn diff(a: &str, b: &str) -> String {
  let al: Vec<&str> = a.lines().collect();
  let bl: Vec<&str> = b.lines().collect();
  let mut out = String::new();
  let n = al.len().max(bl.len()).min(200);
  for i in 0..n {
    let x = al.get(i).unwrap_or(&"");
    let y = bl.get(i).unwrap_or(&"");
    if x != y {
      out.push_str(&format!("- {x}\n+ {y}\n"));
    }
    if out.len() > 8000 {
      break;
    }
  }
  if out.is_empty() {
    out.push_str("identical");
  }
  out
}
