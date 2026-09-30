use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordStats {
  pub total: usize,
  pub unique: usize,
  pub avg_len: f64,
  pub est_seconds_md5: f64,
}

pub fn dedupe(words: Vec<String>) -> Vec<String> {
  let mut seen = HashSet::new();
  let mut out = Vec::new();
  for w in words {
    let w = w.trim().to_string();
    if w.is_empty() {
      continue;
    }
    if seen.insert(w.clone()) {
      out.push(w);
    }
  }
  out
}

pub fn filter_len(words: Vec<String>, min: usize, max: usize) -> Vec<String> {
  words.into_iter().filter(|w| w.len() >= min && w.len() <= max).collect()
}

pub fn mutate_basic(words: &[String]) -> Vec<String> {
  let mut out = Vec::with_capacity(words.len() * 4);
  for w in words {
    out.push(w.clone());
    out.push(w.to_lowercase());
    out.push(w.to_uppercase());
    // leet basic: a->4 e->3 o->0
    let leet = w.replace('a', "4").replace('e', "3").replace('o', "0");
    out.push(leet);
  }
  out.sort();
  out.dedup();
  out
}

pub fn combine(a: &[String], b: &[String], sep: &str, limit: usize) -> Vec<String> {
  let mut out = Vec::new();
  for x in a {
    for y in b {
      out.push(format!("{x}{sep}{y}"));
      if out.len() >= limit {
        return out;
      }
    }
  }
  out
}

pub fn stats(words: &[String], md5_hs: u64) -> WordStats {
  let total = words.len();
  let unique = {
    let mut s = HashSet::new();
    for w in words {
      s.insert(w);
    }
    s.len()
  };
  let avg_len = if total == 0 { 0.0 } else { words.iter().map(|w| w.len()).sum::<usize>() as f64 / total as f64 };
  let est = if md5_hs == 0 { 0.0 } else { total as f64 / md5_hs as f64 };
  WordStats { total, unique, avg_len, est_seconds_md5: est }
}

// Stream large file without full RAM load. Applies lowercase mutate on the fly.
// Returns count written. Go worker does the same for 1 GB plus files.
pub fn stream_file(input: &std::path::Path, output: &std::path::Path) -> anyhow::Result<usize> {
  use std::io::{BufRead, BufReader, Write};
  let f = std::fs::File::open(input)?;
  let r = BufReader::new(f);
  let mut w = std::fs::File::create(output)?;
  let mut n = 0;
  for line in r.lines() {
    let line = line?;
    let t = line.trim();
    if t.is_empty() {
      continue;
    }
    writeln!(w, "{}", t.to_lowercase())?;
    n += 1;
  }
  Ok(n)
}
