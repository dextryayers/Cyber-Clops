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
pub fn to_html(project: &str, scope: &str, findings: &[ReportFinding], timeline: &[String]) -> String {
  let mut rows = String::new();
  for f in findings {
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
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>{project} report</title><style>body{{font-family:Inter,Arial,sans-serif;margin:40px;color:#111}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #999;padding:8px;font-size:13px}}pre{{white-space:pre-wrap}}</style></head><body><h1>{project}</h1><p>Scope: {scope}</p><h2>Findings ({})</h2><table><tr><th>Severity</th><th>Tool</th><th>Title</th><th>Evidence</th></tr>{rows}</table><h2>Timeline</h2><ul>{tl}</ul></body></html>",
    findings.len(),
    project = esc(project),
    scope = esc(scope),
    rows = rows,
    tl = tl
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
