use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
  pub tool: String,
  pub severity: String,
  pub title: String,
  pub evidence: String,
}

fn redact_evidence(s: &str) -> String {
  // Auto redact cookies and tokens in evidence.
  let mut out = s.to_string();
  for pat in [
    r"(?i)cookie[^\\n]{0,80}",
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    r"sk_live_[A-Za-z0-9]{16,}",
  ] {
    if let Ok(re) = regex::Regex::new(pat) {
      out = re.replace_all(&out, "[REDACTED]").to_string();
    }
  }
  out
}

fn esc(s: &str) -> String {
  s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

// HTML report, print ready CSS, English only. PDF via browser print.
// Findings sort Critical first. Counts per severity head the table.
pub fn to_html(project: &str, scope: &str, findings: &[ReportFinding], timeline: &[String]) -> String {
  fn rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
      "critical" => 0,
      "high" => 1,
      "medium" => 2,
      "low" => 3,
      _ => 4,
    }
  }
  let mut sorted: Vec<&ReportFinding> = findings.iter().collect();
  sorted.sort_by_key(|f| rank(&f.severity));
  let mut counts = [0usize; 5];
  for f in &sorted {
    counts[rank(&f.severity).min(4) as usize] += 1;
  }
  let mut rows = String::new();
  for f in sorted {
    rows.push_str(&format!(
      "<tr><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>",
      esc(&f.severity),
      esc(&f.tool),
      esc(&f.title),
      esc(&redact_evidence(&f.evidence))
    ));
  }
  let mut tl = String::new();
  for t in timeline {
    tl.push_str(&format!("<li>{}</li>", esc(t)));
  }
  format!(
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>{project} report</title><style>body{{font-family:Inter,Arial,sans-serif;margin:40px;color:#111}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #999;padding:8px;font-size:13px}}pre{{white-space:pre-wrap}}</style></head><body><h1>{project}</h1><p>Scope: {scope}</p><p>Counts: Critical {c0} High {c1} Medium {c2} Low {c3} Info {c4}</p><h2>Findings ({})</h2><table><tr><th>Severity</th><th>Tool</th><th>Title</th><th>Evidence</th></tr>{rows}</table><h2>Timeline</h2><ul>{tl}</ul></body></html>",
    findings.len(),
    project = esc(project),
    scope = esc(scope),
    rows = rows,
    tl = tl,
    c0 = counts[0],
    c1 = counts[1],
    c2 = counts[2],
    c3 = counts[3],
    c4 = counts[4],
  )
}

pub fn to_json(project: &str, findings: &[ReportFinding], timeline: &[String]) -> String {
  serde_json::to_string_pretty(&serde_json::json!({
    "project": project,
    "findings": findings,
    "timeline": timeline,
  }))
  .unwrap_or_else(|_| "{}".into())
}
