use std::collections::HashMap;

// clops-job: real engine runner for GUI spawning and terminal use.
// Verbs stream JSONL on stdout, human notes on stderr. Exit 2 on scope deny.
fn args_map() -> HashMap<String, String> {
  let mut m = HashMap::new();
  let raw: Vec<String> = std::env::args().skip(1).collect();
  let mut i = 0;
  while i < raw.len() {
    if raw[i] == "scan" || raw[i] == "resolve" || raw[i] == "fetch" || raw[i] == "tls" || raw[i] == "dirbrute" || raw[i] == "crack-dict" || raw[i] == "codec" {
      m.insert("verb".to_string(), raw[i].clone());
    } else if raw[i].starts_with("--") {
      let k = raw[i].trim_start_matches('-').to_string();
      if i + 1 < raw.len() && !raw[i + 1].starts_with("--") {
        m.insert(k, raw[i + 1].clone());
        i += 1;
      } else {
        m.insert(k, "1".to_string());
      }
    }
    i += 1;
  }
  m
}

fn parse_ports(spec: &str) -> Vec<u16> {
  let mut out = Vec::new();
  for part in spec.split(',') {
    let part = part.trim();
    if part.is_empty() {
      continue;
    }
    if let Some((a, b)) = part.split_once('-') {
      if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
        for p in lo..=hi {
          out.push(p);
        }
      }
    } else if let Ok(p) = part.parse::<u16>() {
      out.push(p);
    }
  }
  out.sort_unstable();
  out.dedup();
  out.truncate(65535);
  out
}

fn deny(target: &str) -> ! {
  eprintln!("denied: target outside scope: {target}");
  std::process::exit(2);
}

#[tokio::main]
async fn main() {
  let a = args_map();
  let verb = a.get("verb").cloned().unwrap_or_default();
  let scope = clops_core::scope::Scope::lab_only();
  match verb.as_str() {
    "resolve" => {
      let host = a.get("host").cloned().unwrap_or_default();
      if !scope.is_allowed(&host) {
        deny(&host);
      }
      let ips = clops_core::dns::resolve(&host).await.unwrap_or_default();
      println!("{}", serde_json::json!({"host": host, "ips": ips}));
    }
    "scan" => {
      let host = a.get("host").cloned().unwrap_or_default();
      if !scope.is_allowed(&host) {
        deny(&host);
      }
      let ports = parse_ports(a.get("ports").map(|s| s.as_str()).unwrap_or("80,443"));
      let timeout: u64 = a.get("timeout").and_then(|s| s.parse().ok()).unwrap_or(2000);
      let conc: usize = a.get("concurrency").and_then(|s| s.parse().ok()).unwrap_or(100);
      let refine = a.contains_key("refine");
      let out = if refine {
        clops_core::scan::scan_many_refined(&host, &ports, timeout, conc, 4).await
      } else {
        clops_core::scan::scan_many(&host, &ports, timeout, conc).await
      };
      for f in out {
        println!("{}", serde_json::to_string(&f).unwrap());
      }
      eprintln!("done: {} ports scanned", ports.len());
    }
    "fetch" => {
      let url = a.get("url").cloned().unwrap_or_default();
      if !scope.is_allowed(&url) {
        deny(&url);
      }
      let timeout: u64 = a.get("timeout").and_then(|s| s.parse().ok()).unwrap_or(8000);
      match clops_core::fingerprint::fingerprint(&url, timeout).await {
        Ok(fp) => println!("{}", serde_json::to_string(&fp).unwrap()),
        Err(e) => {
          eprintln!("fetch failed: {e}");
          std::process::exit(1);
        }
      }
    }
    "tls" => {
      let host = a.get("host").cloned().unwrap_or_default();
      let port: u16 = a.get("port").and_then(|s| s.parse().ok()).unwrap_or(443);
      if !scope.is_allowed(&host) {
        deny(&host);
      }
      let timeout: u64 = a.get("timeout").and_then(|s| s.parse().ok()).unwrap_or(8000);
      match clops_core::tls::analyze(&host, port, timeout).await {
        Ok(info) => println!("{}", serde_json::to_string(&info).unwrap()),
        Err(e) => {
          eprintln!("tls failed: {e}");
          std::process::exit(1);
        }
      }
    }
    "dirbrute" => {
      let base = a.get("base").cloned().unwrap_or_default();
      if !scope.is_allowed(&base) {
        deny(&base);
      }
      let wl_path = a.get("wordlist").cloned().unwrap_or_default();
      let words = if wl_path.is_empty() {
        vec!["admin".to_string(), "login".to_string()]
      } else {
        clops_core::dirbrute::load_wordlist(std::path::Path::new(&wl_path))
      };
      let conc: usize = a.get("concurrency").and_then(|s| s.parse().ok()).unwrap_or(20);
      let timeout: u64 = a.get("timeout").and_then(|s| s.parse().ok()).unwrap_or(5000);
      let out = clops_core::dirbrute::brute(&base, &words, conc, timeout, 0).await;
      for f in &out {
        println!("{}", serde_json::to_string(f).unwrap());
      }
      eprintln!("done: {} findings", out.len());
    }
    "crack-dict" => {
      let algo = a.get("algo").cloned().unwrap_or("MD5".to_string());
      let target = a.get("target").cloned().unwrap_or_default();
      let wl_path = a.get("wordlist").cloned().unwrap_or_default();
      let words = if wl_path.is_empty() {
        vec![]
      } else {
        clops_core::dirbrute::load_wordlist(std::path::Path::new(&wl_path))
      };
      let st = clops_core::cracker::dict_attack(&algo, &target, &words, None);
      println!("{}", serde_json::to_string(&st).unwrap());
    }
    "codec" => {
      let op = a.get("op").cloned().unwrap_or_default();
      let input = a.get("input").cloned().unwrap_or_default();
      let out = match op.as_str() {
        "b64encode" => clops_core::codec::b64_encode(&input),
        "b64decode" => clops_core::codec::b64_decode(&input).unwrap_or_else(|e| format!("error: {e}")),
        "hexencode" => clops_core::codec::hex_encode(&input),
        "hexdecode" => clops_core::codec::hex_decode(&input).unwrap_or_else(|e| format!("error: {e}")),
        "urlencode" => clops_core::codec::url_encode(&input),
        "urldecode" => clops_core::codec::url_decode(&input),
        "md5" => clops_core::hash::md5_hex(&input),
        "sha256" => clops_core::hash::sha256_hex(&input),
        _ => {
          eprintln!("unknown op: b64encode b64decode hexencode hexdecode urlencode urldecode md5 sha256");
          std::process::exit(2);
        }
      };
      println!("{}", serde_json::json!({"op": op, "output": out}));
    }
    _ => {
      eprintln!("usage: clops-job <resolve|scan|fetch|tls|dirbrute|crack-dict|codec> [options]");
      eprintln!("  resolve --host H");
      eprintln!("  scan --host H --ports 80,443,8000-8010 [--refine]");
      eprintln!("  fetch --url URL");
      eprintln!("  tls --host H [--port 443]");
      eprintln!("  dirbrute --base URL --wordlist FILE");
      eprintln!("  crack-dict --algo MD5 --target HASH --wordlist FILE");
      eprintln!("  codec --op b64encode --input TEXT");
      std::process::exit(2);
    }
  }
}
