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
