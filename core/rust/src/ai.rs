use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiStep {
  pub tool: String,
  pub target: String,
  pub risk: String,
  pub needs_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPlan {
  pub goal: String,
  pub steps: Vec<AiStep>,
}

// Redact secrets from prompts and logs. High precision patterns only.
pub fn redact(s: &str) -> String {
  let mut out = s.to_string();
  let patterns = [
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    r"sk_live_[A-Za-z0-9]{16,}",
    r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
  ];
  for pat in patterns {
    if let Ok(re) = regex::Regex::new(pat) {
      out = re.replace_all(&out, "[REDACTED]").to_string();
    }
  }
  out
}

// Rule based planner. Deterministic, no network. LLM only refines wording when available.
pub fn plan(goal: &str, target: &str) -> AiPlan {
  let g = goal.to_lowercase();
  let mut steps = vec![
    AiStep { tool: "T01".into(), target: target.into(), risk: "Low".into(), needs_approval: false },
    AiStep { tool: "T02".into(), target: target.into(), risk: "Low".into(), needs_approval: false },
    AiStep { tool: "T03".into(), target: target.into(), risk: "Low".into(), needs_approval: false },
  ];
  if g.contains("vuln") || g.contains("full") {
    steps.push(AiStep { tool: "T04".into(), target: target.into(), risk: "Low".into(), needs_approval: false });
    steps.push(AiStep { tool: "T05".into(), target: target.into(), risk: "Low".into(), needs_approval: false });
    steps.push(AiStep { tool: "T13".into(), target: target.into(), risk: "Medium".into(), needs_approval: true });
  }
  if g.contains("full") {
    steps.push(AiStep { tool: "T10".into(), target: target.into(), risk: "Medium".into(), needs_approval: true });
    steps.push(AiStep { tool: "T25".into(), target: target.into(), risk: "Low".into(), needs_approval: false });
  }
  AiPlan { goal: goal.into(), steps }
}

// Gate: Low auto, Medium and High need approve. Destructive always blocked.
pub fn gate(step: &AiStep, approved: bool) -> Result<(), String> {
  if step.tool.contains("destroy") || step.risk == "Destructive" {
    return Err("destructive blocked".into());
  }
  if step.needs_approval && !approved {
    return Err("approval required".into());
  }
  Ok(())
}

// Ollama local probe. Returns model list or empty when Ollama is down.
// Never fails the plan when Ollama is missing. Rule planner is the fallback.
pub async fn ollama_models(timeout_ms: u64) -> Vec<String> {
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_millis(timeout_ms))
    .build();
  let Ok(c) = client else { return vec![] };
  if let Ok(r) = c.get("http://127.0.0.1:11434/api/tags").send().await {
    if let Ok(j) = r.json::<serde_json::Value>().await {
      if let Some(arr) = j.get("models").and_then(|x| x.as_array()) {
        return arr
          .iter()
          .filter_map(|m| m.get("name").and_then(|x| x.as_str()).map(|s| s.to_string()))
          .collect();
      }
    }
  }
  vec![]
}
