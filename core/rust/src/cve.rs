use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
  pub id: String,
  pub service: String,
  pub version_max: String,
  pub cvss: f32,
  pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMatch {
  pub id: String,
  pub cvss: f32,
  pub severity: String,
  pub summary: String,
}

fn sample_db() -> Vec<CveEntry> {
  vec![
    CveEntry {
      id: "CVE-2021-23017".into(),
      service: "nginx".into(),
      version_max: "1.20.0".into(),
      cvss: 7.7,
      summary: "Nginx resolver off by one".into(),
    },
    CveEntry {
      id: "CVE-2021-41773".into(),
      service: "apache".into(),
      version_max: "2.4.49".into(),
      cvss: 7.5,
      summary: "Apache path traversal".into(),
    },
    CveEntry {
      id: "CVE-2017-7494".into(),
      service: "samba".into(),
      version_max: "4.5.9".into(),
      cvss: 7.5,
      summary: "Samba remote code exec".into(),
    },
    CveEntry {
      id: "CVE-2014-0160".into(),
      service: "openssl".into(),
      version_max: "1.0.1f".into(),
      cvss: 7.5,
      summary: "Heartbleed information leak".into(),
    },
    CveEntry {
      id: "CVE-2019-11043".into(),
      service: "php".into(),
      version_max: "7.3.11".into(),
      cvss: 9.8,
      summary: "PHP-FPM remote code exec".into(),
    },
    CveEntry {
      id: "CVE-2020-1472".into(),
      service: "netlogon".into(),
      version_max: "10.0".into(),
      cvss: 10.0,
      summary: "Zerologon privilege escalation".into(),
    },
    CveEntry {
      id: "CVE-2021-44228".into(),
      service: "log4j".into(),
      version_max: "2.14.1".into(),
      cvss: 10.0,
      summary: "Log4Shell remote code exec".into(),
    },
    CveEntry {
      id: "CVE-2017-0144".into(),
      service: "smb".into(),
      version_max: "1.0".into(),
      cvss: 8.1,
      summary: "EternalBlue SMB remote code exec".into(),
    },
    CveEntry {
      id: "CVE-2022-22965".into(),
      service: "spring".into(),
      version_max: "5.3.17".into(),
      cvss: 9.8,
      summary: "Spring4Shell remote code exec".into(),
    },
    CveEntry {
      id: "CVE-2023-38408".into(),
      service: "openssh".into(),
      version_max: "9.3p1".into(),
      cvss: 9.8,
      summary: "OpenSSH agent PKCS11 injection".into(),
    },
  ]
}

fn ver_le(a: &str, b: &str) -> bool {
  let pa: Vec<u64> = a.split('.').map(|x| x.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0)).collect();
  let pb: Vec<u64> = b.split('.').map(|x| x.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0)).collect();
  let n = pa.len().max(pb.len());
  for i in 0..n {
    let x = *pa.get(i).unwrap_or(&0);
    let y = *pb.get(i).unwrap_or(&0);
    if x < y {
      return true;
    }
    if x > y {
      return false;
    }
  }
  true
}

fn severity(cvss: f32) -> String {
  if cvss >= 9.0 {
    "Critical"
  } else if cvss >= 7.0 {
    "High"
  } else if cvss >= 4.0 {
    "Medium"
  } else {
    "Low"
  }
  .to_string()
}

// Offline match. Service name case insensitive, version prefix compare.
// Never fetches network. DB path optional JSON, else built in sample.
pub fn match_service(service: &str, version: &str, db_path: Option<&std::path::Path>) -> Vec<CveMatch> {
  let db: Vec<CveEntry> = if let Some(p) = db_path {
    std::fs::read_to_string(p)
      .ok()
      .and_then(|s| serde_json::from_str(&s).ok())
      .unwrap_or_else(sample_db)
  } else {
    sample_db()
  };
  let s = service.to_lowercase();
  // Extract version number from banner like "nginx/1.18.0" or "Apache/2.4.41"
  let ver = {
    let low = version.to_lowercase();
    if let Some(pos) = low.find('/') {
      low[pos + 1..].split_whitespace().next().unwrap_or("").to_string()
    } else {
      // first token that looks like x.y
      low.split_whitespace()
        .find(|t| t.contains('.') && t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
        .unwrap_or(&low)
        .to_string()
    }
  };
  let mut out = Vec::new();
  for e in db {
    if e.service.to_lowercase() == s || s.contains(&e.service.to_lowercase()) {
      if !ver.is_empty() && ver_le(&ver, &e.version_max) {
        out.push(CveMatch { id: e.id, cvss: e.cvss, severity: severity(e.cvss), summary: e.summary });
      }
    }
  }
  out
}
