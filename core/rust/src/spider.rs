use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
  pub url: String,
  pub status: u16,
  pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Form {
  pub url: String,
  pub method: String,
  pub params: Vec<String>,
}

fn extract_links(base: &str, body: &str) -> Vec<String> {
  let re = regex::Regex::new(r#"href=["']([^"'#]+)["']|src=["']([^"'#]+)["']"#).unwrap();
  let mut out = Vec::new();
  for cap in re.captures_iter(body) {
    for i in [1, 2] {
      if let Some(m) = cap.get(i) {
        let link = m.as_str();
        if link.starts_with("http") {
          out.push(link.to_string());
        } else if link.starts_with('/') {
          // same host, preserve port via URL join
          if let Ok(b) = reqwest::Url::parse(base) {
            if let Ok(abs) = b.join(link) {
              out.push(abs.to_string());
            }
          }
        } else if !link.contains(':') && !link.starts_with('#') {
          if let Ok(b) = reqwest::Url::parse(base) {
            if let Ok(abs) = b.join(link) {
              out.push(abs.to_string());
            }
          }
        }
      }
    }
  }
  out.sort();
  out.dedup();
  out
}

fn extract_forms(url: &str, body: &str) -> Vec<Form> {
  let form_re = regex::Regex::new(r"(?is)<form[^>]*>.*?</form>").unwrap();
  let attr_re = regex::Regex::new(r#"name=["']([^"']+)["']"#).unwrap();
  let method_re = regex::Regex::new(r#"method=["']([^"']+)["']"#).unwrap();
  let mut out = Vec::new();
  for m in form_re.find_iter(body) {
    let html = m.as_str();
    let method = method_re
      .captures(html)
      .and_then(|c| c.get(1))
      .map(|x| x.as_str().to_uppercase())
      .unwrap_or("GET".into());
    let mut params = Vec::new();
    for c in attr_re.captures_iter(html) {
      params.push(c[1].to_string());
    }
    out.push(Form { url: url.into(), method, params });
  }
  out
}

// Real spider. Same host only unless host is in scope list.
// Depth max 3, pages max 2000 by default via args.
pub async fn crawl(seed: &str, max_pages: usize, timeout_ms: u64) -> (Vec<Page>, Vec<Form>) {
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::limited(3))
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  let seed_url = match reqwest::Url::parse(seed) {
    Ok(u) => u,
    Err(_) => return (vec![], vec![]),
  };
  let host = seed_url.host_str().unwrap_or("").to_string();
  let mut seen = HashSet::new();
  let mut queue = vec![seed.to_string()];
  let mut pages = Vec::new();
  let mut forms = Vec::new();
  while let Some(url) = queue.pop() {
    if pages.len() >= max_pages || !seen.insert(url.clone()) {
      continue;
    }
    let resp = match client.get(&url).send().await {
      Ok(r) => r,
      Err(_) => continue,
    };
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let title = {
      let low = body.to_lowercase();
      if let Some(s) = low.find("<title>") {
        if let Some(e) = low[s..].find("</title>") {
          body[s + 7..s + e].trim().chars().take(120).collect()
        } else {
          String::new()
        }
      } else {
        String::new()
      }
    };
    pages.push(Page { url: url.clone(), status, title });
    forms.extend(extract_forms(&url, &body));
    if pages.len() > max_pages {
      break;
    }
    for link in extract_links(&url, &body) {
      if let Ok(u) = reqwest::Url::parse(&link) {
        if u.host_str().unwrap_or("") == host && !seen.contains(&link) && queue.len() < max_pages {
          queue.push(link);
        }
      }
    }
    // sitemap and robots only on first page, preserve port
    if pages.len() == 1 {
      for extra in ["/sitemap.xml", "/robots.txt"] {
        if let Ok(abs) = seed_url.join(extra) {
          let s = abs.to_string();
          if !seen.contains(&s) {
            queue.push(s);
          }
        }
      }
    }
  }
  (pages, forms)
}
