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
    let host = t.split(':').next().unwrap_or(&t).to_string();
    let host = host.trim_start_matches("http://").trim_start_matches("https://");
    let host = host.split('/').next().unwrap_or(host);
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
    assert!(s.is_allowed("example.com"));
    assert!(!s.is_allowed("evil.com"));
  }
}
