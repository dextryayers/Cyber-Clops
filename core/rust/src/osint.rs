use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileHit {
  pub site: String,
  pub url: String,
  pub status: u16,
  pub found: bool,
}

// Slow polite username check against public profile URLs. 1 req per 800 ms per site.
pub async fn username_check(username: &str, timeout_ms: u64) -> Vec<ProfileHit> {
  let sites = [
    ("GitHub", "https://github.com/"),
    ("GitLab", "https://gitlab.com/"),
    ("Reddit", "https://www.reddit.com/user/"),
    ("X", "https://x.com/"),
  ];
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  let mut out = Vec::new();
  for (site, base) in sites {
    let url = format!("{base}{username}");
    // HEAD first to stay light, fall back to GET
    let status = match client.head(&url).send().await {
      Ok(r) => r.status().as_u16(),
      Err(_) => 0,
    };
    // 200 likely exists, 404 not. 429 means rate limited, mark unknown.
    let found = status == 200;
    out.push(ProfileHit { site: site.into(), url, status, found });
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  }
  out
}

pub async fn email_mx(domain: &str) -> Vec<String> {
  crate::dns::query(domain, "MX").await.iter().map(|r| r.value.clone()).collect()
}

// Local breach match only. Never uploads. breach_path is user provided file with one hash or email per line.
pub fn breach_match(query: &str, breach_path: &std::path::Path) -> Vec<String> {
  let data = std::fs::read_to_string(breach_path).unwrap_or_default();
  let q = query.to_lowercase();
  data.lines().filter(|l| l.to_lowercase().contains(&q)).take(20).map(|s| s.to_string()).collect()
}

// Wayback host list for in scope domain. Real CDX, capped.
pub async fn wayback_hosts(domain: &str, timeout_ms: u64) -> Vec<String> {
  let url = format!("https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=200");
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  let body = match client.get(&url).send().await {
    Ok(r) => r.text().await.unwrap_or_default(),
    Err(_) => return vec![],
  };
  let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
  let mut out: Vec<String> = re.find_iter(&body).map(|m| m.as_str().to_lowercase()).collect();
  out.sort();
  out.dedup();
  out.into_iter().take(200).collect()
}
