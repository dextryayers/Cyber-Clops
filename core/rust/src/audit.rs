use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Serialize)]
struct AuditRow<'a> {
  ts: String,
  tool: &'a str,
  target: &'a str,
  action: &'a str,
  detail: &'a str,
}

// Append only JSONL. UI cannot disable this path.
pub fn append(tool: &str, target: &str, action: &str, detail: &str, path: &str) {
  let row = AuditRow { ts: Utc::now().to_rfc3339(), tool, target, action, detail };
  if let Ok(json) = serde_json::to_string(&row) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
      let _ = writeln!(f, "{json}");
    }
  }
}
