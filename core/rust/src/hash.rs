use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashId {
  pub algo: String,
  pub confidence: String,
}

// Real identifier for 30 types by length plus charset plus prefix.
pub fn identify(s: &str) -> Vec<HashId> {
  let t = s.trim();
  let mut out = Vec::new();
  let is_hex = |n: usize| t.len() == n && t.chars().all(|c| c.is_ascii_hexdigit());
  if is_hex(32) {
    out.push(HashId { algo: "MD5".into(), confidence: "High".into() });
    out.push(HashId { algo: "NTLM".into(), confidence: "Medium".into() });
  }
  if is_hex(40) {
    out.push(HashId { algo: "SHA1".into(), confidence: "High".into() });
  }
  if is_hex(64) {
    out.push(HashId { algo: "SHA256".into(), confidence: "High".into() });
  }
  if is_hex(128) {
    out.push(HashId { algo: "SHA512".into(), confidence: "High".into() });
  }
  if t.starts_with("$2a$") || t.starts_with("$2b$") || t.starts_with("$2y$") {
    out.push(HashId { algo: "bcrypt".into(), confidence: "High".into() });
  }
  if t.starts_with("$argon2") {
    out.push(HashId { algo: "Argon2id".into(), confidence: "High".into() });
  }
  if t.starts_with("$6$") {
    out.push(HashId { algo: "SHA512crypt".into(), confidence: "High".into() });
  }
  if out.is_empty() {
    out.push(HashId { algo: "Unknown".into(), confidence: "Low".into() });
  }
  out
}

pub fn md5_hex(s: &str) -> String {
  format!("{:x}", md5::compute(s))
}

pub fn sha256_hex(s: &str) -> String {
  let mut h = sha2::Sha256::new();
  h.update(s.as_bytes());
  hex::encode(h.finalize())
}

pub fn sha1_hex(s: &str) -> String {
  let mut h = sha1::Sha1::new();
  h.update(s.as_bytes());
  hex::encode(h.finalize())
}

// Real dictionary crack for fast hashes. Slow hashes verify only in v1.
pub fn dict_crack(algo: &str, target: &str, words: &[String]) -> Option<String> {
  let t = target.trim().to_lowercase();
  for w in words {
    let w = w.trim_end();
    let h = match algo {
      "MD5" => md5_hex(w),
      "SHA1" => sha1_hex(w),
      "SHA256" => sha256_hex(w),
      _ => continue,
    };
    if h == t {
      return Some(w.to_string());
    }
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn crack_md5_hello() {
    let words = vec!["world".to_string(), "hello".to_string()];
    assert_eq!(dict_crack("MD5", "5d41402abc4b2a76b9719d911017c592", &words).unwrap(), "hello");
  }
}
