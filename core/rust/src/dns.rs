use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

// Real DNS resolve with system config plus Google fallback.
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
  // Fallback to std resolver if hickory returns empty.
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
  // Minimal PTR via hickory. Returns empty on failure, never panics.
  use std::net::IpAddr;
  use std::str::FromStr;
  let Ok(addr) = IpAddr::from_str(ip) else { return vec![] };
  let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
  match r.reverse_lookup(addr).await {
    Ok(names) => names.iter().map(|n| n.to_string()).collect(),
    Err(_) => vec![],
  }
}
