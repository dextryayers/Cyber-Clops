use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
  pub kind: String,
  pub value_preview: String,
  pub confidence: String,
  pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
  pub path: String,
  pub location: String,
}

// High precision only. Patterns tuned to avoid false alarms.
pub fn extract(body: &str, location: &str) -> (Vec<Endpoint>, Vec<SecretFinding>) {
  let mut endpoints = Vec::new();
  let ep_re = regex::Regex::new(r#"["'](/[A-Za-z0-9_\-./]{3,80})["']"#).unwrap();
  for cap in ep_re.captures_iter(body) {
    let p = cap[1].to_string();
    if p.contains('.') || p.contains('/') {
      endpoints.push(Endpoint { path: p, location: location.into() });
    }
  }
  endpoints.sort_by(|a, b| a.path.cmp(&b.path));
  endpoints.dedup_by(|a, b| a.path == b.path);

  let patterns: Vec<(&str, &str, &str)> = vec![
    ("AWS key", r"AKIA[0-9A-Z]{16}", "High"),
    ("GitHub token", r"ghp_[A-Za-z0-9]{20,}", "High"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", "High"),
    ("Stripe live", r"sk_live_[A-Za-z0-9]{16,}", "High"),
    ("Google API", r"AIza[0-9A-Za-z\-_]{30,}", "Medium"),
    ("Private key", r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "High"),
    ("JWT", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "Medium"),
    ("Twilio SID", r"AC[a-z0-9]{32}", "Medium"),
    ("Mailgun key", r"key-[a-z0-9]{32}", "Medium"),
    ("OpenAI key", r"sk-[A-Za-z0-9]{20,}", "Medium"),
  ];
  let mut secrets = Vec::new();
  for (kind, pat, conf) in patterns {
    let re = regex::Regex::new(pat).unwrap();
    for m in re.find_iter(body) {
      let v = m.as_str();
      let preview = if v.len() > 12 { format!("{}...", &v[..8]) } else { v.to_string() };
      secrets.push(SecretFinding {
        kind: kind.into(),
        value_preview: preview,
        confidence: conf.into(),
        location: location.into(),
      });
      if secrets.len() > 200 {
        break;
      }
    }
  }
  (endpoints, secrets)
}
