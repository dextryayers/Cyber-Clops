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
  pub grade: String,
}

// Real TLS info via direct handshake and x509 parse.
// v1: leaf cert only. Chain and cipher enum land in Phase 2.
pub async fn analyze(host: &str, port: u16, timeout_ms: u64) -> anyhow::Result<TlsInfo> {
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

  Ok(TlsInfo {
    host: host.into(),
    port,
    cert_cn: cn,
    san,
    issuer,
    days_left,
    tls_version: format!("{:?}", tls.get_ref().1.protocol_version().unwrap_or(rustls::ProtocolVersion::TLSv1_2)),
    grade,
  })
}
