use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfiFinding {
  pub param: String,
  pub kind: String,
  pub confidence: String,
  pub evidence: String,
}

async fn fetch(client: &reqwest::Client, url: &str) -> String {
  match client.get(url).send().await {
    Ok(r) => r.text().await.unwrap_or_default(),
    Err(_) => String::new(),
  }
}

fn inject(base: &str, param: &str, payload: &str) -> String {
  if let Ok(mut u) = reqwest::Url::parse(base) {
    let mut q: Vec<(String, String)> = u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    let mut found = false;
    for (k, v) in q.iter_mut() {
      if k == param {
        *v = payload.to_string();
        found = true;
      }
    }
    if !found {
      q.push((param.to_string(), payload.to_string()));
    }
    u.query_pairs_mut().clear();
    for (k, v) in q {
      u.query_pairs_mut().append_pair(&k, &v);
    }
    return u.to_string();
  }
  format!("{base}?{param}={payload}")
}

// Safe traversal plus SSTI math probe. No RCE, no upload.
pub async fn check(base_url: &str, params: &[String], timeout_ms: u64) -> Vec<LfiFinding> {
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  let mut out = Vec::new();
  let traversals = ["../../etc/passwd", "..%2f..%2fetc%2fpasswd"];
  for param in params {
    for t in traversals {
      let u = inject(base_url, param, t);
      let b = fetch(&client, &u).await;
      if b.contains("root:x") || b.contains("root:*") {
        out.push(LfiFinding {
          param: param.clone(),
          kind: "path-traversal".into(),
          confidence: "High".into(),
          evidence: "marker root:x".into(),
        });
        break;
      }
    }
    // SSTI math: {{7*7}} should render 49 only if template evaluates
    let u = inject(base_url, param, "{{7*7}}");
    let b = fetch(&client, &u).await;
    // Baseline without payload must not already contain lone 49 in same spot.
    // Simple guard: body contains 49 and does not contain the raw probe.
    if b.contains('4') && b.contains('9') && b.contains("49") && !b.contains("{{7*7}}") {
      // Second probe with different math to confirm
      let u2 = inject(base_url, param, "{{8*8}}");
      let b2 = fetch(&client, &u2).await;
      if b2.contains("64") && !b2.contains("{{8*8}}") {
        out.push(LfiFinding {
          param: param.clone(),
          kind: "ssti".into(),
          confidence: "Medium".into(),
          evidence: "math 7*7=49 and 8*8=64".into(),
        });
      }
    }
  }
  out
}
