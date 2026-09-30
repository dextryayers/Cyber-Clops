use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtInfo {
  pub header: String,
  pub payload: String,
  pub alg: String,
}

pub fn b64_encode(s: &str) -> String {
  use base64::Engine as E;
  E::encode(&base64::engine::general_purpose::STANDARD, s.as_bytes())
}

pub fn b64_decode(s: &str) -> anyhow::Result<String> {
  use base64::Engine as E;
  let b = E::decode(&base64::engine::general_purpose::STANDARD, s.trim())?;
  Ok(String::from_utf8_lossy(&b).to_string())
}

pub fn hex_encode(s: &str) -> String {
  hex::encode(s.as_bytes())
}

pub fn hex_decode(s: &str) -> anyhow::Result<String> {
  let b = hex::decode(s.trim())?;
  Ok(String::from_utf8_lossy(&b).to_string())
}

pub fn url_encode(s: &str) -> String {
  let mut out = String::new();
  for b in s.bytes() {
    if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
      out.push(b as char);
    } else {
      out.push_str(&format!("%{b:02X}"));
    }
  }
  out
}

pub fn url_decode(s: &str) -> String {
  let mut out = Vec::new();
  let b = s.as_bytes();
  let mut i = 0;
  while i < b.len() {
    if b[i] == b'%' && i + 2 < b.len() {
      if let (Some(h), Some(l)) = (hexv(b[i + 1]), hexv(b[i + 2])) {
        out.push(h * 16 + l);
        i += 3;
        continue;
      }
    }
    if b[i] == b'+' {
      out.push(b' ');
    } else {
      out.push(b[i]);
    }
    i += 1;
  }
  String::from_utf8_lossy(&out).to_string()
}

fn hexv(c: u8) -> Option<u8> {
  match c {
    b'0'..=b'9' => Some(c - b'0'),
    b'a'..=b'f' => Some(c - b'a' + 10),
    b'A'..=b'F' => Some(c - b'A' + 10),
    _ => None,
  }
}

pub fn html_escape(s: &str) -> String {
  s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// JWT decode without verify. Returns header and payload JSON strings.
pub fn jwt_parse(token: &str) -> anyhow::Result<JwtInfo> {
  use base64::Engine as E;
  let parts: Vec<&str> = token.split('.').collect();
  if parts.len() != 3 {
    anyhow::bail!("jwt must have 3 parts");
  }
  let dec = |p: &str| -> anyhow::Result<String> {
    let mut s = p.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
      s.push('=');
    }
    let b = E::decode(&base64::engine::general_purpose::STANDARD, &s)?;
    Ok(String::from_utf8_lossy(&b).to_string())
  };
  let header = dec(parts[0])?;
  let payload = dec(parts[1])?;
  let alg = serde_json::from_str::<serde_json::Value>(&header)
    .ok()
    .and_then(|v| v.get("alg").and_then(|x| x.as_str()).map(|s| s.to_string()))
    .unwrap_or_default();
  Ok(JwtInfo { header, payload, alg })
}

// Bulk transform for files up to 200 MB via streaming. Returns output path.
pub fn bulk_base64_encode_file(input: &std::path::Path, output: &std::path::Path) -> anyhow::Result<u64> {
  use base64::Engine as E;
  use std::io::{BufReader, Read, Write};
  let f = std::fs::File::open(input)?;
  let mut r = BufReader::new(f);
  let mut w = std::fs::File::create(output)?;
  let mut buf = vec![0u8; 57 * 1000];
  let mut total: u64 = 0;
  loop {
    let n = r.read(&mut buf)?;
    if n == 0 {
      break;
    }
    let enc = E::encode(&base64::engine::general_purpose::STANDARD, &buf[..n]);
    w.write_all(enc.as_bytes())?;
    total += n as u64;
    if total > 200 * 1024 * 1024 {
      anyhow::bail!("file over 200 MB cap");
    }
  }
  Ok(total)
}
