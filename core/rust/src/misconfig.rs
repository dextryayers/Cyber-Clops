use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisFinding {
  pub check: String,
  pub severity: String,
  pub cwe: String,
  pub evidence: String,
  pub fix: String,
}

// Real misconfig checks with live requests. CWE mapped.
pub async fn check(base_url: &str, timeout_ms: u64) -> Vec<MisFinding> {
  let mut out = Vec::new();
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .redirect(reqwest::redirect::Policy::none())
    .user_agent("Cyber-Clops/2.0")
    .build()
    .unwrap();
  // 1. CORS: send Origin and inspect ACAO
  if let Ok(resp) = client.get(base_url).header("Origin", "https://evil.example").send().await {
    let h = resp.headers().clone();
    let acao = h.get("access-control-allow-origin").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let creds = h.get("access-control-allow-credentials").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if acao == "*" {
      out.push(MisFinding {
        check: "CORS wildcard".into(),
        severity: "Medium".into(),
        cwe: "CWE-942".into(),
        evidence: "ACAO: *".into(),
        fix: "Echo explicit Origin, avoid * with credentials".into(),
      });
    } else if acao == "https://evil.example" {
      let sev = if creds.to_lowercase() == "true" { "High" } else { "Medium" };
      out.push(MisFinding {
        check: "CORS origin reflection".into(),
        severity: sev.into(),
        cwe: "CWE-942".into(),
        evidence: format!("ACAO reflected plus creds {creds}"),
        fix: "Allowlist trusted origins".into(),
      });
    }
    // Clickjacking
    let xfo = h.get("x-frame-options").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let csp = h.get("content-security-policy").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if xfo.is_empty() && !csp.contains("frame-ancestors") {
      out.push(MisFinding {
        check: "Missing clickjacking defense".into(),
        severity: "Low".into(),
        cwe: "CWE-1021".into(),
        evidence: "no X-Frame-Options and no frame-ancestors".into(),
        fix: "Add X-Frame-Options DENY or CSP frame-ancestors".into(),
      });
    }
    // HSTS explicit: only meaningful on HTTPS, flag when absent
    let hsts = h.get("strict-transport-security").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if hsts.is_empty() {
      // Determine scheme from base_url. Plain http sites get Info, https get Low.
      let sev = if base_url.starts_with("https") { "Low" } else { "Info" };
      out.push(MisFinding {
        check: "Missing HSTS".into(),
        severity: sev.into(),
        cwe: "CWE-319".into(),
        evidence: "no Strict-Transport-Security".into(),
        fix: "Add Strict-Transport-Security with max-age".into(),
      });
    }
    // CSP explicit
    if csp.is_empty() {
      out.push(MisFinding {
        check: "Missing CSP".into(),
        severity: "Low".into(),
        cwe: "CWE-1021".into(),
        evidence: "no Content-Security-Policy".into(),
        fix: "Add Content-Security-Policy with default-src".into(),
      });
    }
    // Cookies
    for v in h.get_all("set-cookie").iter() {
      let s = v.to_str().unwrap_or("").to_lowercase();
      if !s.contains("secure") || !s.contains("httponly") || !s.contains("samesite") {
        out.push(MisFinding {
          check: "Weak cookie flags".into(),
          severity: "Low".into(),
          cwe: "CWE-614".into(),
          evidence: v.to_str().unwrap_or("").chars().take(80).collect(),
          fix: "Set Secure HttpOnly SameSite".into(),
        });
        break;
      }
    }
    // Info leak: verbose server
    if let Some(srv) = h.get("server").and_then(|v| v.to_str().ok()) {
      if srv.contains('/') && srv.len() > 12 {
        out.push(MisFinding {
          check: "Verbose server header".into(),
          severity: "Info".into(),
          cwe: "CWE-200".into(),
          evidence: srv.chars().take(80).collect(),
          fix: "Minimize Server header".into(),
        });
      }
    }
  }
  // 2. .git HEAD light check, same host
  if let Ok(base) = reqwest::Url::parse(base_url) {
    if let Some(host) = base.host_str() {
      let scheme = base.scheme();
      let port = base.port().map(|p| format!(":{p}")).unwrap_or_default();
      let git_url = format!("{scheme}://{host}{port}/.git/HEAD");
      if let Ok(r) = client.get(&git_url).send().await {
        if r.status().as_u16() == 200 {
          let b = r.text().await.unwrap_or_default();
          if b.contains("ref:") {
            out.push(MisFinding {
              check: "Exposed .git/HEAD".into(),
              severity: "High".into(),
              cwe: "CWE-538".into(),
              evidence: "ref: found".into(),
              fix: "Block .git from web root".into(),
            });
          }
        }
      }
    }
  }
  // 3. Directory listing probe on common asset paths, same host only
  if let Ok(base) = reqwest::Url::parse(base_url) {
    if let Some(host) = base.host_str() {
      let scheme = base.scheme();
      let port = base.port().map(|p| format!(":{p}")).unwrap_or_default();
      for probe in ["/uploads/", "/files/", "/assets/"] {
        let url = format!("{scheme}://{host}{port}{probe}");
        if let Ok(r) = client.get(&url).send().await {
          if r.status().as_u16() == 200 {
            let b = r.text().await.unwrap_or_default();
            if b.contains("Index of /") {
              out.push(MisFinding {
                check: "Directory listing".into(),
                severity: "Low".into(),
                cwe: "CWE-548".into(),
                evidence: format!("Index of at {probe}"),
                fix: "Disable autoindex".into(),
              });
              break;
            }
          }
        }
      }
    }
  }
  out
}
