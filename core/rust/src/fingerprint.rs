use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
  pub url: String,
  pub server: String,
  pub tech: Vec<String>,
  pub waf: String,
  pub cookies: Vec<CookieFlag>,
  pub issues: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieFlag {
  pub name: String,
  pub secure: bool,
  pub httponly: bool,
  pub samesite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
  pub check: String,
  pub severity: String,
  pub advice: String,
}

fn detect_tech(headers: &HashMap<String, String>, body: &str) -> Vec<String> {
  let mut t = Vec::new();
  let h: String = headers.values().cloned().collect::<Vec<_>>().join(" ").to_lowercase();
  let b = body.to_lowercase();
  if h.contains("wordpress") || b.contains("wp-content") {
    t.push("WordPress".into());
  }
  if b.contains("react") || b.contains("_next/static") {
    t.push("React/Next".into());
  }
  if b.contains("jquery") {
    t.push("jQuery".into());
  }
  if h.contains("laravel") || b.contains("laravel") {
    t.push("Laravel".into());
  }
  if h.contains("django") || b.contains("csrfmiddlewaretoken") {
    t.push("Django".into());
  }
  if h.contains("nginx") {
    t.push("Nginx".into());
  }
  if h.contains("apache") {
    t.push("Apache".into());
  }
  if h.contains("php") || b.contains("<?php") || h.contains("x-powered-by") && h.contains("php") {
    t.push("PHP".into());
  }
  if b.contains("express") || h.contains("express") {
    t.push("Express".into());
  }
  if b.contains("__next") || b.contains("_next/static") {
    if !t.contains(&"React/Next".to_string()) {
      t.push("Next.js".into());
    }
  }
  if b.contains("wp-json") || b.contains("wp-includes") {
    if !t.contains(&"WordPress".to_string()) {
      t.push("WordPress".into());
    }
  }
  t.sort();
  t.dedup();
  t
}

// Real fingerprint via one live fetch. Body is reused for tech detect.
pub async fn fingerprint(url: &str, timeout_ms: u64) -> anyhow::Result<Fingerprint> {
  let r = crate::http::fetch(url, timeout_ms).await?;
  let tech = detect_tech(&r.headers, &r.body);
  let mut issues = Vec::new();
  let get = |k: &str| r.headers.iter().find(|(hk, _)| hk.to_lowercase() == k).map(|(_, v)| v.clone());
  if get("strict-transport-security").is_none() && url.starts_with("https") {
    issues.push(Finding { check: "Missing HSTS".into(), severity: "Low".into(), advice: "Add Strict-Transport-Security".into() });
  }
  if get("content-security-policy").is_none() {
    issues.push(Finding { check: "Missing CSP".into(), severity: "Low".into(), advice: "Add Content-Security-Policy".into() });
  }
  if get("x-frame-options").is_none() {
    issues.push(Finding { check: "Missing X-Frame-Options".into(), severity: "Low".into(), advice: "Add X-Frame-Options or frame-ancestors".into() });
  }
  // Cookie flags from set-cookie headers. Multi values arrive newline joined.
  let mut cookies = Vec::new();
  for (k, v) in r.headers.iter() {
    if k.to_lowercase() != "set-cookie" {
      continue;
    }
    for line in v.split('\n') {
      let line = line.trim();
      if line.is_empty() {
        continue;
      }
      let name = line.split(';').next().unwrap_or("").split('=').next().unwrap_or("").trim().to_string();
      let low = line.to_lowercase();
      cookies.push(CookieFlag {
        name,
        secure: low.contains("secure"),
        httponly: low.contains("httponly"),
        samesite: if low.contains("samesite=strict") {
          "Strict".into()
        } else if low.contains("samesite=lax") {
          "Lax".into()
        } else if low.contains("samesite=none") {
          "None".into()
        } else {
          "Missing".into()
        },
      });
    }
  }
  Ok(Fingerprint { url: url.into(), server: r.server, tech, waf: r.waf, cookies, issues })
}
