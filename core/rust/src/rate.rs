use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use std::sync::Arc;

// Simple token bucket plus concurrency semaphore.
// Polite defaults: 50 rps per host for internet, lab profile raises it.
pub struct RateLimiter {
  sem: Arc<Semaphore>,
  min_interval: Duration,
  last: std::sync::Mutex<Instant>,
}

impl RateLimiter {
  pub fn new(concurrency: usize, rps: u32) -> Self {
    let rps = rps.max(1);
    Self {
      sem: Arc::new(Semaphore::new(concurrency.max(1))),
      min_interval: Duration::from_millis(1000 / rps as u64),
      last: std::sync::Mutex::new(Instant::now() - Duration::from_secs(1)),
    }
  }

  pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
    // Pacing sleep outside the permit to keep it simple and correct.
    loop {
      let wait = {
        let mut l = self.last.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*l) >= self.min_interval {
          *l = now;
          None
        } else {
          Some(self.min_interval - now.duration_since(*l))
        }
      };
      if let Some(d) = wait {
        tokio::time::sleep(d).await;
      } else {
        break;
      }
    }
    self.sem.clone().acquire_owned().await.unwrap()
  }
}
