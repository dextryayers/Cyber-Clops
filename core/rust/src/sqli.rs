use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliFinding {
  pub param: String,
  pub kind: String,
  pub confidence: String,
  pub evidence: String,
}

fn error_sigs() -> Vec<(&'static str, &'static str)> {
  vec![
    ("MySQL", "You have an error in your SQL syntax"),
    ("MySQL", "mysql_fetch_"),
    ("Postgres", "PG::SyntaxError"),
    ("Postgres", "unterminated quoted string"),
    ("MSSQL", "Unclosed quotation mark"),
    ("Oracle", "ORA-01756"),
    ("SQLite", "SQLite3::SQLException"),
    ("Generic", "SQL syntax"),
  ]
}

async fn get(client: &reqwest::Client, url: &str) -> (u16, String, u64) {
  let t0 = std::time::Instant::now();
  match client.get(url).send().await {
    Ok(r) => {
      let s = r.status().as_u16();
      let b = r.text().await.unwrap_or_default();
      (s, b, t0.elapsed().as_millis() as u64)
    }
    Err(_) => (0, String::new(), 0),
  }
}

fn inject(base: &str, param: &str, payload: &str) -> String {
  // Supports URLs like http://host/path?param=1&other=2 and raw query append.
  if let Ok(mut u) = reqwest::Url::parse(base) {
    let mut q: Vec<(String, String)> = u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    let mut found = false;
    for (k, v) in q.iter_mut() {
      if k == param {
        *v = format!("{v}{payload}");
        found = true;
      }
    }
    if !found {
      q.push((param.to_string(), payload.to_string()));
    }
    u.query_pairs_mut().clear();
    for (k, v) in q {
      u.query_pairs_mut().append_pair(&k, &v);
    }
    return u.to_string();
  }
  // Fallback: append query string
  if base.contains('?') {
    format!("{base}&{param}={payload}")
  } else {
    format!("{base}?{param}={payload}")
  }
}

// Safe detector. Error based plus boolean diff. Time based is gated behind allow_time flag.
// Default allow_time=false for internet. Lab tests pass true explicitly.
pub async fn check(
  base_url: &str,
  params: &[String],
  timeout_ms: u64,
  allow_time: bool,
) -> Vec<SqliFinding> {
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  let mut out = Vec::new();
  for param in params {
    // Baseline
    let (_, base_body, _) = get(&client, base_url).await;
    // 1. Error based with single quote
    let u1 = inject(base_url, param, "'");
    let (_, b1, _) = get(&client, &u1).await;
    for (db, sig) in error_sigs() {
      if b1.contains(sig) && !base_body.contains(sig) {
        out.push(SqliFinding {
          param: param.clone(),
          kind: format!("error-based {db}"),
          confidence: "Medium".into(),
          evidence: format!("sig {sig}"),
        });
        break;
      }
    }
    // 2. Boolean diff: true vs false
    let ut = inject(base_url, param, "1' AND '1'='1");
    let uf = inject(base_url, param, "1' AND '1'='2");
    let (_, bt, _) = get(&client, &ut).await;
    let (_, bf, _) = get(&client, &uf).await;
    if !bt.is_empty() && !bf.is_empty() {
      let ht = crate::hash::md5_hex(&bt);
      let hf = crate::hash::md5_hex(&bf);
      let hb = crate::hash::md5_hex(&base_body);
      // True matches base but false differs, or true and false differ strongly with length gap
      if (ht == hb && hf != hb) || (ht != hf && (bt.len() as i64 - bf.len() as i64).abs() > 8) {
        // Avoid flagging when both equal base (no injection effect)
        if ht != hf {
          out.push(SqliFinding {
            param: param.clone(),
            kind: "boolean-blind".into(),
            confidence: "Low".into(),
            evidence: format!("len true {} vs false {}", bt.len(), bf.len()),
          });
        }
      }
    }
    // 3. Time based, gated, single sleep 2s max once per param
    if allow_time {
      let utime = inject(base_url, param, "' OR SLEEP(2)-- -");
      let t0 = std::time::Instant::now();
      let _ = get(&client, &utime).await;
      let dt = t0.elapsed().as_millis();
      if dt >= 1800 && dt < 8000 {
        out.push(SqliFinding {
          param: param.clone(),
          kind: "time-based".into(),
          confidence: "Low".into(),
          evidence: format!("delay {dt}ms"),
        });
      }
    }
  }
  out
}
