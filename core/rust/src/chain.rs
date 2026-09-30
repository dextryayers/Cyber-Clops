use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
  pub tool: String,
  pub target: String,
  pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
  pub name: String,
  pub steps: Vec<ChainStep>,
}

// Substitute {{var}} from vars map. Used by T23 and T24.
pub fn render(template: &str, vars: &std::collections::HashMap<String, String>) -> String {
  let mut out = template.to_string();
  for (k, v) in vars {
    out = out.replace(&format!("{{{{{k}}}}}"), v);
  }
  out
}

// Dry run returns planned lines without packets. Real execution calls engines.
pub fn dry_run(chain: &Chain, vars: &std::collections::HashMap<String, String>) -> Vec<String> {
  chain
    .steps
    .iter()
    .enumerate()
    .map(|(i, s)| {
      let t = render(&s.target, vars);
      format!("{}. {} on {} [{}]", i + 1, s.tool, t, s.risk)
    })
    .collect()
}

pub fn save_json(chain: &Chain, path: &std::path::Path) -> anyhow::Result<()> {
  let s = serde_json::to_string_pretty(chain)?;
  std::fs::write(path, s)?;
  Ok(())
}

pub fn load_json(path: &std::path::Path) -> anyhow::Result<Chain> {
  let s = std::fs::read_to_string(path)?;
  Ok(serde_json::from_str(&s)?)
}

// Example recon chain used by tests and by AI planner default.
pub fn recon_chain(target: &str) -> Chain {
  Chain {
    name: "recon-to-report".into(),
    steps: vec![
      ChainStep { tool: "T01".into(), target: target.into(), risk: "Low".into() },
      ChainStep { tool: "T02".into(), target: target.into(), risk: "Low".into() },
      ChainStep { tool: "T03".into(), target: target.into(), risk: "Low".into() },
      ChainStep { tool: "T04".into(), target: target.into(), risk: "Low".into() },
      ChainStep { tool: "T05".into(), target: target.into(), risk: "Low".into() },
    ],
  }
}

// Branch helper for no code conditions. Example: continue only if found > N.
pub fn meets_threshold(found: usize, min: usize) -> bool {
  found >= min
}

// Real recon execution for a single target. Runs resolve plus top port scan
// and stores results into vars for later steps. Polite timeouts throughout.
pub async fn execute_recon(
  target: &str,
  timeout_ms: u64,
) -> (Vec<String>, std::collections::HashMap<String, String>) {
  let mut lines = Vec::new();
  let mut vars = std::collections::HashMap::new();
  vars.insert("target".to_string(), target.to_string());
  let ips = crate::dns::resolve(target).await.unwrap_or_default();
  lines.push(format!("resolved {} to {} ips", target, ips.len()));
  vars.insert("ips".to_string(), ips.join(","));
  let ports = [80u16, 443, 8080, 8443];
  let found = crate::scan::scan_many(target, &ports, timeout_ms, 4).await;
  let open: Vec<String> = found.iter().filter(|f| f.open).map(|f| f.port.to_string()).collect();
  lines.push(format!("open ports: {}", open.join(",")));
  vars.insert("open_ports".to_string(), open.join(","));
  (lines, vars)
}
