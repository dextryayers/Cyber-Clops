use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssFinding {
  pub param: String,
  pub context: String,
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
  if base.contains('?') {
    format!("{base}&{param}={payload}")
  } else {
    format!("{base}?{param}={payload}")
  }
}

fn context_of(body: &str, marker: &str) -> String {
  if let Some(pos) = body.find(marker) {
    let start = pos.saturating_sub(120);
    let end = (pos + marker.len() + 120).min(body.len());
    let win = &body[start..end];
    if win.contains(&format!("\"{marker}\"")) {
      return "attr-double".into();
    }
    if win.contains(&format!("'{marker}'")) {
      return "attr-single".into();
    }
    if win.contains("<script") && win.contains(marker) {
      return "js".into();
    }
    return "html-text".into();
  }
  "not-reflected".into()
}

// Reflected only in v1. Double send with different markers to cut false positives.
pub async fn check(base_url: &str, params: &[String], timeout_ms: u64) -> Vec<XssFinding> {
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  let mut out = Vec::new();
  for param in params {
    let m1 = "clopsXYZ111";
    let m2 = "clopsXYZ222";
    let u1 = inject(base_url, param, m1);
    let u2 = inject(base_url, param, m2);
    let b1 = fetch(&client, &u1).await;
    let b2 = fetch(&client, &u2).await;
    let c1 = context_of(&b1, m1);
    let c2 = context_of(&b2, m2);
    // Both markers must reflect in the same context. Single reflection is not enough.
    if c1 != "not-reflected" && c1 == c2 {
      // Encoding check: raw vs encoded
      let raw = b1.contains(m1);
      let conf = if raw { "Medium" } else { "Low" };
      out.push(XssFinding {
        param: param.clone(),
        context: c1,
        confidence: conf.into(),
        evidence: format!("double send {m1} and {m2}"),
      });
    }
  }
  out
}
