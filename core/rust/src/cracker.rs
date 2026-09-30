use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackStats {
  pub password: Option<String>,
  pub tested: u64,
  pub hs: u64,
  pub backend: String,
  pub algo: String,
}

fn hash_one(algo: &str, word: &str) -> Option<String> {
  match algo {
    "MD5" => Some(crate::hash::md5_hex(word)),
    "SHA1" => Some(crate::hash::sha1_hex(word)),
    "SHA256" => Some(crate::hash::sha256_hex(word)),
    _ => None,
  }
}

fn backend_label() -> String {
  let info = crate::accel::detect();
  if info.cuda {
    "CUDA".into()
  } else if info.opencl_platforms > 0 {
    "OpenCL".into()
  } else if info.avx2 || info.avx512 {
    "ISPC CPU".into()
  } else {
    "CPU scalar".into()
  }
}

// Real benchmark per algo, 200 ms each. Honest H/s for ETA math.
pub fn bench(algo: &str) -> u64 {
  let start = Instant::now();
  let mut n: u64 = 0;
  while start.elapsed().as_millis() < 200 {
    let w = format!("bench{n}");
    let _ = hash_one(algo, &w);
    n += 1;
  }
  let ms = start.elapsed().as_millis().max(1) as u64;
  n * 1000 / ms
}

// Dictionary with checkpoint. checkpoint_path stores last index as text.
// Returns stats with password when found.
pub fn dict_attack(
  algo: &str,
  target: &str,
  words: &[String],
  checkpoint_path: Option<&std::path::Path>,
) -> CrackStats {
  let backend = backend_label();
  let t = target.trim().to_lowercase();
  let start_idx: usize = checkpoint_path
    .and_then(|p| std::fs::read_to_string(p).ok())
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(0);
  let start = Instant::now();
  let mut tested: u64 = 0;
  for (idx, w) in words.iter().enumerate() {
    if idx < start_idx {
      continue;
    }
    let w = w.trim_end();
    if let Some(h) = hash_one(algo, w) {
      tested += 1;
      if h == t {
        if let Some(p) = checkpoint_path {
          let _ = std::fs::write(p, idx.to_string());
        }
        let ms = start.elapsed().as_millis().max(1) as u64;
        return CrackStats {
          password: Some(w.to_string()),
          tested,
          hs: tested * 1000 / ms,
          backend,
          algo: algo.into(),
        };
      }
    }
    if idx % 1000 == 0 {
      if let Some(p) = checkpoint_path {
        let _ = std::fs::write(p, idx.to_string());
      }
    }
  }
  let ms = start.elapsed().as_millis().max(1) as u64;
  CrackStats { password: None, tested, hs: tested * 1000 / ms, backend, algo: algo.into() }
}

fn charset_for(token: char) -> Vec<char> {
  match token {
    'l' => ('a'..='z').collect(),
    'u' => ('A'..='Z').collect(),
    'd' => ('0'..='9').collect(),
    's' => vec!['!', '@', '#', '$'],
    'a' => {
      let mut v: Vec<char> = ('a'..='z').collect();
      v.extend('A'..='Z');
      v.extend('0'..='9');
      v
    }
    _ => vec!['a'],
  }
}

// Mask attack for small lengths in tests. Supports ?l ?u ?d ?s ?a.
// Length is mask token count, not chars. Test uses ?d ?d to find 2 digit PIN.
pub fn mask_attack(algo: &str, target: &str, mask: &str, max_keys: u64) -> CrackStats {
  let backend = backend_label();
  let t = target.trim().to_lowercase();
  // Parse mask like "?d?d" into charsets
  let mut sets: Vec<Vec<char>> = Vec::new();
  let mut chars = mask.chars().peekable();
  while let Some(c) = chars.next() {
    if c == '?' {
      if let Some(k) = chars.next() {
        sets.push(charset_for(k));
      }
    }
  }
  if sets.is_empty() || sets.len() > 6 {
    return CrackStats { password: None, tested: 0, hs: 0, backend, algo: algo.into() };
  }
  let start = Instant::now();
  let mut tested: u64 = 0;
  let mut idx: Vec<usize> = vec![0; sets.len()];
  loop {
    if tested >= max_keys {
      break;
    }
    let cand: String = sets.iter().enumerate().map(|(i, s)| s[idx[i]]).collect();
    tested += 1;
    if let Some(h) = hash_one(algo, &cand) {
      if h == t {
        let ms = start.elapsed().as_millis().max(1) as u64;
        return CrackStats {
          password: Some(cand),
          tested,
          hs: tested * 1000 / ms,
          backend,
          algo: algo.into(),
        };
      }
    }
    // odometer
    let mut pos = sets.len();
    loop {
      if pos == 0 {
        // exhausted
        let ms = start.elapsed().as_millis().max(1) as u64;
        return CrackStats { password: None, tested, hs: tested * 1000 / ms, backend, algo: algo.into() };
      }
      pos -= 1;
      idx[pos] += 1;
      if idx[pos] < sets[pos].len() {
        break;
      }
      idx[pos] = 0;
    }
  }
  let ms = start.elapsed().as_millis().max(1) as u64;
  CrackStats { password: None, tested, hs: tested * 1000 / ms, backend, algo: algo.into() }
}
