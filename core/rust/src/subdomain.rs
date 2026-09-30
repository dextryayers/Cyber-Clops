use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubResult {
  pub subdomain: String,
  pub ip: String,
  pub source: String,
  pub resolved: bool,
}

fn client(timeout_ms: u64) -> reqwest::Client {
  reqwest::Client::builder()
    .timeout(Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::limited(2))
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap_or_else(|_| reqwest::Client::new())
}

fn cache_path(source: &str, domain: &str) -> std::path::PathBuf {
  let mut p = std::env::temp_dir();
  p.push("clops-cache");
  let _ = std::fs::create_dir_all(&p);
  p.push(format!("{source}_{domain}.json"));
  p
}

fn cache_get(source: &str, domain: &str) -> Option<Vec<String>> {
  let p = cache_path(source, domain);
  let meta = std::fs::metadata(&p).ok()?;
  let age = SystemTime::now().duration_since(meta.modified().ok()?).ok()?;
  if age.as_secs() > 24 * 3600 {
    return None;
  }
  let data = std::fs::read_to_string(&p).ok()?;
  serde_json::from_str(&data).ok()
}

fn cache_put(source: &str, domain: &str, v: &[String]) {
  let p = cache_path(source, domain);
  if let Ok(s) = serde_json::to_string(v) {
    let _ = std::fs::write(p, s);
  }
}

fn clean(domain: &str, vals: Vec<String>) -> Vec<String> {
  let d = domain.trim().to_lowercase();
  let mut out = Vec::new();
  for v in vals {
    let mut s = v.trim().to_lowercase();
    s = s.trim_start_matches("*.").to_string();
    s = s.trim_end_matches('.').to_string();
    if s.is_empty() {
      continue;
    }
    if s == d || s.ends_with(&format!(".{d}")) {
      // drop entries with spaces or slashes
      if s.contains(' ') || s.contains('/') || s.contains(':') {
        continue;
      }
      out.push(s);
    }
  }
  out.sort();
  out.dedup();
  out
}

async fn get_text(url: &str, timeout_ms: u64) -> anyhow::Result<String> {
  let c = client(timeout_ms);
  let r = c.get(url).send().await?;
  if !r.status().is_success() {
    anyhow::bail!("http {}", r.status());
  }
  Ok(r.text().await.unwrap_or_default())
}

// 1 crt.sh JSON
async fn src_crtsh(domain: &str) -> Vec<String> {
  let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.as_array() {
    for e in arr {
      if let Some(nv) = e.get("name_value").and_then(|x| x.as_str()) {
        for line in nv.lines() {
          out.push(line.to_string());
        }
      }
    }
  }
  clean(domain, out)
}

// 2 hackertarget hostsearch
async fn src_hackertarget(domain: &str) -> Vec<String> {
  let url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let mut out = Vec::new();
  for line in body.lines() {
    if let Some((h, _)) = line.split_once(',') {
      out.push(h.to_string());
    }
  }
  clean(domain, out)
}

// 3 certspotter
async fn src_certspotter(domain: &str) -> Vec<String> {
  let url = format!("https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.as_array() {
    for e in arr {
      if let Some(names) = e.get("dns_names").and_then(|x| x.as_array()) {
        for n in names {
          if let Some(s) = n.as_str() {
            out.push(s.to_string());
          }
        }
      }
    }
  }
  clean(domain, out)
}

// 4 urlscan search
async fn src_urlscan(domain: &str) -> Vec<String> {
  let url = format!("https://urlscan.io/api/v1/search/?q=domain%3A{domain}&size=100");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.get("results").and_then(|x| x.as_array()) {
    for e in arr {
      if let Some(u) = e.get("task").and_then(|t| t.get("url")).and_then(|x| x.as_str()) {
        // extract host from url
        if let Ok(parsed) = reqwest::Url::parse(u) {
          if let Some(h) = parsed.host_str() {
            out.push(h.to_string());
          }
        }
      }
    }
  }
  clean(domain, out)
}

// 5 entrust CT
async fn src_entrust(domain: &str) -> Vec<String> {
  let url = format!("https://ctsearch.entrust.com/api/v1/certificates?domain={domain}&limit=100");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  // best effort: regex for subdomains
  let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
  let mut out = Vec::new();
  for m in re.find_iter(&body) {
    out.push(m.as_str().to_string());
  }
  clean(domain, out)
}

// 6 rapiddns scrape
async fn src_rapiddns(domain: &str) -> Vec<String> {
  let url = format!("https://rapiddns.io/subdomain/{domain}?full=1");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
  let mut out = Vec::new();
  for m in re.find_iter(&body) {
    out.push(m.as_str().to_string());
  }
  clean(domain, out)
}

// 7 anubis jldc
async fn src_anubis(domain: &str) -> Vec<String> {
  let url = format!("https://jldc.me/anubis/subdomains/{domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.as_array() {
    for e in arr {
      if let Some(s) = e.as_str() {
        out.push(s.to_string());
      }
    }
  } else {
    let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
    for m in re.find_iter(&body) {
      out.push(m.as_str().to_string());
    }
  }
  clean(domain, out)
}

// 8 threatcrowd mirror
async fn src_threatcrowd(domain: &str) -> Vec<String> {
  let url = format!("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.get("sub_domains").and_then(|x| x.as_array()) {
    for e in arr {
      if let Some(s) = e.as_str() {
        out.push(s.to_string());
      }
    }
  }
  clean(domain, out)
}

// 9 otx passive dns, no key for public endpoint with limit
async fn src_otx(domain: &str) -> Vec<String> {
  let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.get("passive_dns").and_then(|x| x.as_array()) {
    for e in arr {
      if let Some(h) = e.get("hostname").and_then(|x| x.as_str()) {
        out.push(h.to_string());
      }
    }
  }
  clean(domain, out)
}

// 10 netcraft scrape
async fn src_netcraft(domain: &str) -> Vec<String> {
  let url = format!("https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
  let mut out = Vec::new();
  for m in re.find_iter(&body) {
    out.push(m.as_str().to_string());
  }
  clean(domain, out)
}

// 11 wayback CDX hosts
async fn src_wayback(domain: &str) -> Vec<String> {
  let url = format!("https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=1000");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let mut out = Vec::new();
  for line in body.lines() {
    // try to extract host
    let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
    for m in re.find_iter(line) {
      out.push(m.as_str().to_string());
    }
  }
  clean(domain, out)
}

// 12 commoncrawl index
async fn src_commoncrawl(domain: &str) -> Vec<String> {
  let url = format!("https://index.commoncrawl.org/CC-MAIN-2025-30-index?url=*.{domain}&output=json");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
  let mut out = Vec::new();
  for m in re.find_iter(&body) {
    out.push(m.as_str().to_string());
  }
  clean(domain, out)
}

// 13 dnsdumpster scrape, best effort
#[allow(dead_code)]
async fn src_dnsdumpster(domain: &str) -> Vec<String> {
  let url = format!("https://dnsdumpster.com/");
  let _ = url;
  let _ = domain;
  Vec::new()
}

// 14 local brute with tiny list
async fn src_local_brute(domain: &str) -> Vec<String> {
  const WORDS: &str = include_str!("../../../assets/wordlist/subdomains-tiny.txt");
  let mut out = Vec::new();
  for w in WORDS.lines() {
    let w = w.trim();
    if w.is_empty() || w.starts_with('#') {
      continue;
    }
    let cand = format!("{w}.{domain}");
    // resolve check to avoid noise
    if crate::dns::resolve(&cand).await.map(|v| !v.is_empty()).unwrap_or(false) {
      out.push(cand);
    }
  }
  clean(domain, out)
}

// 15 permutation staging set
async fn src_permutation(domain: &str) -> Vec<String> {
  let seeds = ["dev", "staging", "test", "qa", "uat", "api", "admin", "beta", "internal", "prod"];
  let mut out = Vec::new();
  for s in seeds {
    let cand = format!("{s}.{domain}");
    if crate::dns::resolve(&cand).await.map(|v| !v.is_empty()).unwrap_or(false) {
      out.push(cand);
    }
  }
  clean(domain, out)
}

// 16 typo prefix
async fn src_typo(domain: &str) -> Vec<String> {
  let seeds = ["www", "ww2", "m", "mobile", "blog", "shop", "app", "portal"];
  let mut out = Vec::new();
  for s in seeds {
    let cand = format!("{s}.{domain}");
    if crate::dns::resolve(&cand).await.map(|v| !v.is_empty()).unwrap_or(false) {
      out.push(cand);
    }
  }
  clean(domain, out)
}

// 17 SAN input passthrough, filled by caller from T04
pub fn from_san(domain: &str, sans: &[String]) -> Vec<String> {
  clean(domain, sans.to_vec())
}

// 18 CNAME guess resolve
async fn src_cname_guess(domain: &str) -> Vec<String> {
  let seeds = ["cdn", "static", "media", "assets", "files", "docs", "auth", "sso", "login"];
  let mut out = Vec::new();
  for s in seeds {
    let cand = format!("{s}.{domain}");
    if crate::dns::resolve(&cand).await.map(|v| !v.is_empty()).unwrap_or(false) {
      out.push(cand);
    }
  }
  clean(domain, out)
}

// 19 subdomain.center public API
async fn src_subdomain_center(domain: &str) -> Vec<String> {
  let url = format!("https://api.subdomain.center/?domain={domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.as_array() {
    for e in arr {
      if let Some(s) = e.as_str() {
        out.push(s.to_string());
      }
    }
  }
  clean(domain, out)
}

// 20 omnisint sonar
async fn src_sonar(domain: &str) -> Vec<String> {
  let url = format!("https://sonar.omnisint.io/subdomains/{domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  if let Some(arr) = v.as_array() {
    for e in arr {
      if let Some(s) = e.as_str() {
        out.push(s.to_string());
      }
    }
  }
  clean(domain, out)
}

// 21 findsubdomains scrape
async fn src_findsubdomains(domain: &str) -> Vec<String> {
  let url = format!("https://findsubdomains.com/subdomains-of/{domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let re = regex::Regex::new(&format!(r"[A-Za-z0-9_.-]+\.{d}", d = regex::escape(domain))).unwrap();
  let mut out = Vec::new();
  for m in re.find_iter(&body) {
    out.push(m.as_str().to_string());
  }
  clean(domain, out)
}

// 22 bufferover
async fn src_bufferover(domain: &str) -> Vec<String> {
  let url = format!("https://dns.bufferover.run/dns?q={domain}");
  let body = match get_text(&url, 12000).await {
    Ok(b) => b,
    Err(_) => return vec![],
  };
  let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
  let mut out = Vec::new();
  let subs = v.get("FDNS_A").and_then(|x| x.as_array());
  let subs2 = v.get("RDNS").and_then(|x| x.as_array());
  for arr in [subs, subs2].into_iter().flatten() {
    for e in arr {
      let s = e.get(1).and_then(|x| x.as_str()).unwrap_or("");
      if !s.is_empty() {
        // entries like "1.2.3.4,host"
        for part in s.split(',') {
          out.push(part.to_string());
        }
      }
    }
  }
  clean(domain, out)
}

async fn cached_or_fetch(source: &str, domain: &str, f: impl std::future::Future<Output = Vec<String>>) -> (String, Vec<String>) {
  if let Some(hit) = cache_get(source, domain) {
    return (source.to_string(), hit);
  }
  let v = f.await;
  cache_put(source, domain, &v);
  (source.to_string(), v)
}

// Fast path for tests: 4 reliable sources plus local resolve, to keep CI fast.
pub async fn enumerate_fast(domain: &str) -> Vec<SubResult> {
  let d = domain.to_string();
  let (a, b, c, e) = tokio::join!(
    cached_or_fetch("hackertarget", &d, src_hackertarget(&d)),
    cached_or_fetch("sonar", &d, src_sonar(&d)),
    cached_or_fetch("bufferover", &d, src_bufferover(&d)),
    cached_or_fetch("certspotter", &d, src_certspotter(&d)),
  );
  aggregate(domain, vec![a, b, c, e]).await
}

pub async fn enumerate_full(domain: &str) -> Vec<SubResult> {
  let d = domain.to_string();
  // Network sources in parallel. Local resolve sources run after to avoid DNS storm.
  let (r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12) = tokio::join!(
    cached_or_fetch("crtsh", &d, src_crtsh(&d)),
    cached_or_fetch("hackertarget", &d, src_hackertarget(&d)),
    cached_or_fetch("certspotter", &d, src_certspotter(&d)),
    cached_or_fetch("urlscan", &d, src_urlscan(&d)),
    cached_or_fetch("entrust", &d, src_entrust(&d)),
    cached_or_fetch("rapiddns", &d, src_rapiddns(&d)),
    cached_or_fetch("anubis", &d, src_anubis(&d)),
    cached_or_fetch("threatcrowd", &d, src_threatcrowd(&d)),
    cached_or_fetch("otx", &d, src_otx(&d)),
    cached_or_fetch("netcraft", &d, src_netcraft(&d)),
    cached_or_fetch("wayback", &d, src_wayback(&d)),
    cached_or_fetch("commoncrawl", &d, src_commoncrawl(&d)),
  );
  let (r13, r14, r15) = tokio::join!(
    cached_or_fetch("subdomain_center", &d, src_subdomain_center(&d)),
    cached_or_fetch("sonar", &d, src_sonar(&d)),
    cached_or_fetch("bufferover", &d, src_bufferover(&d)),
  );
  let r16 = cached_or_fetch("findsubdomains", &d, src_findsubdomains(&d)).await;
  // Resolve heavy local sources last with real DNS.
  let l1 = ("local_brute".to_string(), src_local_brute(&d).await);
  let l2 = ("permutation".to_string(), src_permutation(&d).await);
  let l3 = ("typo".to_string(), src_typo(&d).await);
  let l4 = ("cname_guess".to_string(), src_cname_guess(&d).await);
  let mut all = vec![r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, l1, l2, l3, l4];
  // dnsdumpster stub keeps slot 21 for contract stability
  all.push(("dnsdumpster".to_string(), Vec::new()));
  aggregate(domain, all).await
}

async fn aggregate(domain: &str, grouped: Vec<(String, Vec<String>)>) -> Vec<SubResult> {
  let mut map: HashMap<String, String> = HashMap::new();
  for (src, list) in grouped {
    for s in clean(domain, list) {
      map.entry(s).or_insert(src.clone());
    }
  }
  // Wildcard filter: resolve random token. If it resolves, domain uses wildcard.
  let wild_probe = format!("__clopswild9f3k7.{domain}");
  let wildcard = crate::dns::resolve(&wild_probe).await.map(|v| !v.is_empty()).unwrap_or(false);
  let mut out = Vec::new();
  // Dedupe set for final
  let mut seen = HashSet::new();
  for (sub, src) in map {
    if !seen.insert(sub.clone()) {
      continue;
    }
    let ips = crate::dns::resolve(&sub).await.unwrap_or_default();
    let ip = ips.first().cloned().unwrap_or_default();
    if wildcard && ip.is_empty() { continue; }
    out.push(SubResult { subdomain: sub, ip: ip.clone(), source: src, resolved: !ip.is_empty() });
  }
  out.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
  out
}
