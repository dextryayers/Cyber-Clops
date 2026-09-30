use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
  pub host: String,
  pub port: u16,
  pub cert_cn: String,
  pub san: Vec<String>,
  pub issuer: String,
  pub days_left: i64,
  pub tls_version: String,
  pub chain_len: usize,
  pub hsts: String,
  pub grade: String,
}

// Real TLS info via direct handshake and x509 parse.
// Leaf is parsed fully. Intermediates are counted for chain length.
// Cipher offer enum stays out of scope for rustls client builds.
pub async fn analyze(host: &str, port: u16, timeout_ms: u64) -> anyhow::Result<TlsInfo> {
  let _ = rustls::crypto::ring::default_provider().install_default();
  use tokio::net::TcpStream;
  use tokio::time::timeout;
  use x509_parser::prelude::FromDer;

  let addr = format!("{host}:{port}");
  let stream = timeout(std::time::Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
    .await??;

  let mut root_store = rustls::RootCertStore::empty();
  root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
  let config = rustls::ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();
  let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
  let dns_name = rustls_pki_types::ServerName::try_from(host.to_string())?;
  let tls = timeout(
    std::time::Duration::from_millis(timeout_ms),
    connector.connect(dns_name, stream),
  )
  .await??;

  let certs: Vec<rustls_pki_types::CertificateDer<'static>> = tls
    .get_ref()
    .1
    .peer_certificates()
    .map(|c| c.to_vec())
    .unwrap_or_default();
  let first = certs.first().ok_or_else(|| anyhow::anyhow!("no peer cert"))?;
  let (_, cert) = x509_parser::certificate::X509Certificate::from_der(first.as_ref())?;

  let cn = cert
    .subject()
    .iter_common_name()
    .next()
    .and_then(|n| std::str::from_utf8(n.as_slice()).ok())
    .unwrap_or("")
    .to_string();
  let issuer = cert.issuer().to_string();
  let days_left = (cert.validity().not_after.timestamp() - chrono::Utc::now().timestamp()) / 86400;
  let san: Vec<String> = cert
    .subject_alternative_name()
    .ok()
    .flatten()
    .map(|ext| ext.value.general_names.iter().map(|n| format!("{n:?}")).collect())
    .unwrap_or_default();

  let grade = if days_left < 0 {
    "F"
  } else if days_left < 14 {
    "C"
  } else {
    "B"
  }
  .to_string();

  // HSTS is an HTTP header, not TLS. One best effort HTTPS fetch keeps
  // the analyzer honest about transport security instead of guessing.
  let hsts = if port == 443 || port == 8443 {
    crate::http::fetch(&format!("https://{host}:{port}/"), timeout_ms / 2 + 1000)
      .await
      .ok()
      .and_then(|r| {
        r.headers
          .iter()
          .find(|(k, _)| k.to_lowercase() == "strict-transport-security")
          .map(|(_, v)| v.clone())
      })
      .unwrap_or_default()
  } else {
    String::new()
  };

  Ok(TlsInfo {
    host: host.into(),
    port,
    cert_cn: cn,
    san,
    issuer,
    days_left,
    tls_version: format!("{:?}", tls.get_ref().1.protocol_version().unwrap_or(rustls::ProtocolVersion::TLSv1_2)),
    chain_len: certs.len(),
    hsts,
    grade,
  })
}

// Real protocol support probe. Tries each version with a short handshake.
// Returns list like ["TLS1.2", "TLS1.3"]. Polite single attempt per version.
pub async fn probe_protocols(host: &str, port: u16, timeout_ms: u64) -> Vec<String> {
  let _ = rustls::crypto::ring::default_provider().install_default();
  use tokio::net::TcpStream;
  use tokio::time::timeout;
  let mut out = Vec::new();
  static V12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
  static V13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
  let versions: Vec<(&str, &[&rustls::SupportedProtocolVersion])> = vec![
    ("TLS1.2", V12),
    ("TLS1.3", V13),
  ];
  for (label, vers) in versions {
    let addr = format!("{host}:{port}");
    let Ok(conn) = timeout(std::time::Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await else { continue };
    let Ok(stream) = conn else { continue };
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let builder = rustls::ClientConfig::builder_with_protocol_versions(vers);
    let cfg = builder.with_root_certificates(roots).with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg));
    let Ok(dns) = rustls_pki_types::ServerName::try_from(host.to_string()) else { continue };
    if timeout(std::time::Duration::from_millis(timeout_ms), connector.connect(dns, stream)).await.is_ok() {
      out.push(label.to_string());
    }
  }
  out
}

