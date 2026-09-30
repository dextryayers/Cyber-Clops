use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverSignal {
  pub host: String,
  pub cname: String,
  pub service: String,
  pub confidence: String,
  pub evidence: String,
}

fn fingerprints() -> Vec<(&'static str, &'static str, &'static str)> {
  vec![
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("azurewebsites.net", "Azure", "Error 404"),
    ("netlify.app", "Netlify", "Not Found"),
    ("vercel.app", "Vercel", "404"),
    ("s3-website", "AWS S3 website", "NoSuchBucket"),
  ]
}

// Real takeover signal check. DNS CNAME plus HTTP GET only. Never claims takeover.
pub async fn check(host: &str, timeout_ms: u64) -> Vec<TakeoverSignal> {
  // Resolve CNAME via hickory query
  let cnames = crate::dns::query(host, "CNAME").await;
  let cname = cnames.first().map(|r| r.value.clone()).unwrap_or_default();
  let mut out = Vec::new();
  for (suffix, service, hit) in fingerprints() {
    if cname.contains(suffix) {
      let url = format!("http://{host}/");
      let evidence = match crate::http::fetch(&url, timeout_ms).await {
        Ok(_r) => {
          // fetch does not return body. Do a light body check here.
          let c = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .user_agent("Cyber-Clops/2.0")
            .build();
          if let Ok(c) = c {
            if let Ok(resp) = c.get(&url).send().await {
              let body = resp.text().await.unwrap_or_default();
              if body.contains(hit) {
                format!("CNAME {cname} plus body match {hit}")
              } else {
                format!("CNAME {cname} without body match, needs review")
              }
            } else {
              format!("CNAME {cname}, HTTP failed")
            }
          } else {
            format!("CNAME {cname}")
          }
        }
        Err(_) => format!("CNAME {cname}, fetch failed"),
      };
      let confidence = if evidence.contains("plus body match") { "High" } else { "Medium" };
      out.push(TakeoverSignal {
        host: host.into(),
        cname: cname.clone(),
        service: service.into(),
        confidence: confidence.into(),
        evidence,
      });
    }
  }
  out
}
