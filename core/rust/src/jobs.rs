use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobStatus {
  Queued,
  Running,
  Paused,
  Cancelled,
  Done,
  Failed(String),
}

impl JobStatus {
  pub fn as_str(&self) -> String {
    match self {
      Self::Queued => "Queued".into(),
      Self::Running => "Running".into(),
      Self::Paused => "Paused".into(),
      Self::Cancelled => "Cancelled".into(),
      Self::Done => "Done".into(),
      Self::Failed(e) => format!("Failed: {e}"),
    }
  }
}

#[derive(Debug, Clone)]
pub struct Job {
  pub id: String,
  pub tool: String,
  pub target: String,
  pub status: JobStatus,
  pub found: u64,
  pub errors: u64,
}

pub struct JobManager {
  inner: Arc<Mutex<HashMap<String, Job>>>,
  tx: broadcast::Sender<String>,
}

impl JobManager {
  pub fn new() -> Self {
    let (tx, _) = broadcast::channel(1024);
    Self { inner: Arc::new(Mutex::new(HashMap::new())), tx }
  }

  pub fn create(&self, tool: &str, target: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let job = Job {
      id: id.clone(),
      tool: tool.into(),
      target: target.into(),
      status: JobStatus::Queued,
      found: 0,
      errors: 0,
    };
    self.inner.lock().unwrap().insert(id.clone(), job);
    let _ = self.tx.send(format!("created {id}"));
    id
  }

  pub fn set_status(&self, id: &str, s: JobStatus) {
    if let Some(j) = self.inner.lock().unwrap().get_mut(id) {
      j.status = s.clone();
      let _ = self.tx.send(format!("status {id} {}", s.as_str()));
    }
  }

  pub fn cancel(&self, id: &str) {
    self.set_status(id, JobStatus::Cancelled);
  }

  pub fn get(&self, id: &str) -> Option<Job> {
    self.inner.lock().unwrap().get(id).cloned()
  }

  pub fn subscribe(&self) -> broadcast::Receiver<String> {
    self.tx.subscribe()
  }
}

impl Default for JobManager {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn cancel_under_policy() {
    let m = JobManager::new();
    let id = m.create("T03", "127.0.0.1");
    m.set_status(&id, JobStatus::Running);
    m.cancel(&id);
    assert_eq!(m.get(&id).unwrap().status, JobStatus::Cancelled);
  }
}
