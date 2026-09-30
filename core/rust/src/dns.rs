use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
  pub name: String,
  pub rtype: String,
  pub value: String,
  pub ttl: u32,
}

// Real DNS resolve with system config plus std fallback.
// Returns sorted unique IP strings.
pub async fn resolve(host: &str) -> anyhow::Result<Vec<String>> {
  let resolver = TokioAsyncResolver::tokio(
    ResolverConfig::default(),
    ResolverOpts::default(),
  );
  let mut out: Vec<String> = Vec::new();
  if let Ok(ips) = resolver.lookup_ip(host).await {
    for ip in ips.iter() {
      out.push(ip.to_string());
    }
  }
  if out.is_empty() {
    let h = host.to_string();
    let addrs = tokio::task::spawn_blocking(move || {
      use std::net::ToSocketAddrs;
      let mut v = Vec::new();
      if let Ok(it) = (h.as_str(), 0).to_socket_addrs() {
        for a in it {
          v.push(a.ip().to_string());
        }
      }
      v
    })
    .await
    .unwrap_or_default();
    out.extend(addrs);
  }
  out.sort();
  out.dedup();
  Ok(out)
}

pub async fn reverse(ip: &str) -> Vec<String> {
  use std::net::IpAddr;
  use std::str::FromStr;
  let Ok(addr) = IpAddr::from_str(ip) else { return vec![] };
  let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
  match r.reverse_lookup(addr).await {
    Ok(names) => names.iter().map(|n| n.to_string()).collect(),
    Err(_) => vec![],
  }
}

// Real record query for A, AAAA, MX, TXT, NS via hickory.
pub async fn query(host: &str, rtype: &str) -> Vec<DnsRecord> {
  let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
  let mut out = Vec::new();
  use hickory_resolver::proto::rr::RecordType;
  let rt = match rtype.to_uppercase().as_str() {
    "A" => RecordType::A,
    "AAAA" => RecordType::AAAA,
    "MX" => RecordType::MX,
    "TXT" => RecordType::TXT,
    "NS" => RecordType::NS,
    "SOA" => RecordType::SOA,
    "CNAME" => RecordType::CNAME,
    "CAA" => RecordType::CAA,
    _ => RecordType::A,
  };
  if let Ok(lookup) = r.lookup(host, rt).await {
    for rec in lookup.iter() {
      out.push(DnsRecord {
        name: host.to_string(),
        rtype: rtype.to_uppercase(),
        value: format!("{rec}"),
        ttl: 0,
      });
    }
  }
  out
}

// DoH fallback via Cloudflare and Google JSON API. Real HTTPS, no key.
pub async fn doh_resolve(host: &str) -> Vec<String> {
  let urls = [
    format!("https://cloudflare-dns.com/dns-query?name={host}&type=A"),
    format!("https://dns.google/resolve?name={host}&type=A"),
  ];
  let c = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(6))
    .user_agent("Cyber-Clops/2.0")
    .build();
  let Ok(c) = c else { return vec![] };
  let mut out = Vec::new();
  for u in urls {
    if let Ok(r) = c.get(&u).header("accept", "application/dns-json").send().await {
      if let Ok(j) = r.json::<serde_json::Value>().await {
        if let Some(arr) = j.get("Answer").and_then(|x| x.as_array()) {
          for e in arr {
            if let Some(d) = e.get("data").and_then(|x| x.as_str()) {
              out.push(d.to_string());
            }
          }
        }
      }
    }
    if !out.is_empty() {
      break;
    }
  }
  out.sort();
  out.dedup();
  out
}

// AXFR check. Safe: tries TCP 53 to each NS with short timeout.
// Returns vulnerable=true only if server answers with zone data.
// Lab scope warning is enforced by caller via scope guard.
pub async fn axfr_check(domain: &str, nameservers: &[String]) -> (bool, String) {
  use tokio::net::TcpStream;
  use tokio::time::timeout;
  for ns in nameservers {
    let addr = format!("{ns}:53");
    // Short TCP open check first. Full AXFR frame parse is Phase 2.1.
    // If TCP 53 is closed, server is not vulnerable via this path.
    match timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
      Ok(Ok(_)) => {
        // TCP open does not prove AXFR. We report hardened unless full transfer proves otherwise.
        // Full transfer attempt uses dig if present for real evidence.
        let dig = tokio::process::Command::new("dig")
          .args(["AXFR", domain, &format!("@{ns}"), "+short", "+time=3", "+tries=1"])
          .output()
          .await;
        if let Ok(o) = dig {
          let body = String::from_utf8_lossy(&o.stdout).to_string();
          if o.status.success() && body.lines().count() > 2 && body.contains(domain) {
            return (true, format!("NS {ns} answered AXFR with {} lines", body.lines().count()));
          }
        }
      }
      _ => continue,
    }
  }
  (false, "no NS answered AXFR".to_string())
}

use std::time::Duration;
