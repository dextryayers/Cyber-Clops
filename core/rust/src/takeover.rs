use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverSignal {
  pub host: String,
  pub cname: String,
  pub service: String,
  pub confidence: String,
  pub evidence: String,
}

// 30 takeover fingerprints. CNAME suffix match plus HTTP body match.
// Source: public takeover fingerprint lists, GET only, never claims takeover.
fn fingerprints() -> Vec<(&'static str, &'static str, &'static str)> {
  vec![
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("herokudns.com", "Heroku", "No such app"),
    ("azurewebsites.net", "Azure", "Error 404"),
    ("cloudapp.azure.com", "Azure", "Error 404"),
    ("trafficmanager.net", "Azure", "Error 404"),
    ("s3-website", "AWS S3 website", "NoSuchBucket"),
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("cloudfront.net", "AWS CloudFront", "Bad request"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk", "404 Not Found"),
    ("netlify.app", "Netlify", "Not Found"),
    ("netlify.com", "Netlify", "Not Found"),
    ("vercel.app", "Vercel", "404"),
    ("now.sh", "Vercel", "404"),
    ("shopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("tumblr.com", "Tumblr", "Whatever you were looking for doesn't currently exist here"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("fastly.net", "Fastly", "Fastly error"),
    ("pantheonsite.io", "Pantheon", "404 error"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("uservoice.com", "Uservoice", "This UserVoice subdomain is currently available"),
    ("ghost.io", "Ghost", "The thing you were looking for is no longer here"),
    ("helpjuice.com", "Helpjuice", "We could not find what you're looking for"),
    ("helpscoutdocs.com", "HelpScout", "No settings were found for this company"),
    ("intercom.help", "Intercom", "This page is no longer available"),
    ("readme.io", "Readme", "Project doesnt exist"),
    ("statuspage.io", "Statuspage", "You are being redirected"),
    ("surge.sh", "Surge", "project not found"),
    ("webflow.io", "Webflow", "The page you are looking for doesn't exist"),
  ]
}

fn clean_cname(raw: &str) -> String {
  // hickory Record display for CNAME renders like "target." with trailing dot.
  // Trim dot and lowercase so suffix match is exact.
  raw.split_whitespace()
    .next()
    .unwrap_or(raw)
    .trim()
    .trim_end_matches('.')
    .to_lowercase()
}

// Real takeover signal check. DNS CNAME plus HTTP GET only. Never claims takeover.
pub async fn check(host: &str, timeout_ms: u64) -> Vec<TakeoverSignal> {
  let cnames = crate::dns::query(host, "CNAME").await;
  let cname = cnames.first().map(|r| clean_cname(&r.value)).unwrap_or_default();
  if cname.is_empty() {
    return vec![];
  }
  let mut out = Vec::new();
  for (suffix, service, hit) in fingerprints() {
    if cname == suffix || cname.ends_with(&format!(".{suffix}")) || cname.contains(suffix) {
      let url = format!("http://{host}/");
      let body = {
        let c = reqwest::Client::builder()
          .timeout(std::time::Duration::from_millis(timeout_ms))
          .user_agent("Cyber-Clops/2.0")
          .build();
        match c {
          Ok(c) => match c.get(&url).send().await {
            Ok(resp) => resp.text().await.unwrap_or_default(),
            Err(_) => String::new(),
          },
          Err(_) => String::new(),
        }
      };
      let (confidence, evidence) = if body.is_empty() {
        ("Low", format!("CNAME {cname}, HTTP failed"))
      } else if body.contains(hit) {
        ("High", format!("CNAME {cname} plus body match {hit}"))
      } else {
        ("Medium", format!("CNAME {cname} without body match, needs review"))
      };
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
