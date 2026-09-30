use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
  pub domains: Vec<String>,
  pub ips: Vec<String>,
  pub cidrs: Vec<String>,
}

impl Scope {
  pub fn lab_only() -> Self {
    Self {
      domains: vec!["localhost".into(), "example.com".into()],
      ips: vec!["127.0.0.1".into()],
      cidrs: vec!["127.0.0.0/8".into()],
    }
  }

  pub fn is_allowed(&self, target: &str) -> bool {
    let t = target.trim().to_lowercase();
    // Strip scheme first so http://host:port keeps its host, not "http".
    let no_scheme = t
      .trim_start_matches("http://")
      .trim_start_matches("https://");
    let hostport = no_scheme.split('/').next().unwrap_or(no_scheme);
    // Split host from port on the last colon to survive odd inputs.
    let host = match hostport.rfind(':') {
      Some(i) => &hostport[..i],
      None => hostport,
    };
    // Bare IPv6 loopback without brackets.
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
      return false;
    }
    if self.domains.iter().any(|d| host == d || host.ends_with(&format!(".{d}"))) {
      return true;
    }
    if self.ips.iter().any(|ip| host == ip) {
      return true;
    }
    // Minimal CIDR check for 127.0.0.0/8 without extra deps.
    if host.starts_with("127.") && self.cidrs.iter().any(|c| c == "127.0.0.0/8") {
      return true;
    }
    false
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn scope_allows_lab() {
    let s = Scope::lab_only();
    assert!(s.is_allowed("127.0.0.1"));
    assert!(s.is_allowed("127.0.0.1:18080"));
    assert!(s.is_allowed("http://127.0.0.1:18080"));
    assert!(s.is_allowed("http://127.0.0.1:18080/admin"));
    assert!(s.is_allowed("https://example.com/x"));
    assert!(s.is_allowed("http://127.0.0.5:9/"));
    assert!(!s.is_allowed("evil.example.net"));
    assert!(!s.is_allowed("http://evil.example.net/"));
    assert!(!s.is_allowed(""));
    assert!(s.is_allowed("example.com"));
    assert!(!s.is_allowed("evil.com"));
  }
}
