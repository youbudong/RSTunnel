//! QUIC 的 TLS 配置。开发/测试用 rcgen 自签名证书；生产从 ACME/配置加载（T-27）。

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// 自签名证书（证书 DER + PKCS#8 私钥 DER）。服务端/测试客户端共用同一份即可互信。
pub struct SelfSignedCert {
    pub cert_der: CertificateDer<'static>,
    key_der_bytes: Vec<u8>,
}

/// 生成自签名证书（SAN 为 `subject_names`）。
pub fn generate_self_signed(subject_names: &[String]) -> Result<SelfSignedCert> {
    let certified = rcgen::generate_simple_self_signed(subject_names.to_vec())
        .context("generate self-signed certificate")?;
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der_bytes = certified.key_pair.serialize_der();
    Ok(SelfSignedCert {
        cert_der,
        key_der_bytes,
    })
}

/// 用给定证书构建 quinn 服务端配置。
pub fn server_config(cert: &SelfSignedCert) -> Result<quinn::ServerConfig> {
    let key_der: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(cert.key_der_bytes.clone()).into();
    let rustls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der.clone()], key_der)
        .context("build rustls server config")?;
    let crypto = QuicServerConfig::try_from(rustls_cfg).context("build quic crypto config")?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// 生成证书并构建服务端配置（`main` 用）。
pub fn build_server_config(subject_names: &[String]) -> Result<quinn::ServerConfig> {
    let cert = generate_self_signed(subject_names)?;
    server_config(&cert)
}

impl SelfSignedCert {
    /// 由已加载的 DER 字节构造（服务端复用持久化证书时用）。
    pub fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        Self {
            cert_der: CertificateDer::from(cert_der),
            key_der_bytes: key_der,
        }
    }
}

/// 加载或生成服务端自签名证书：`cert_path`/`key_path` 均已存在则复用（跨重启稳定身份），
/// 否则生成并同时落盘；任一路径未配置则不持久化（每次启动新生成，仅供开发/测试）。
pub fn load_or_generate(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    subject_names: &[String],
) -> Result<SelfSignedCert> {
    match (cert_path, key_path) {
        (Some(c), Some(k)) if c.exists() && k.exists() => {
            let cert_der = std::fs::read(c).context("read persisted server cert DER")?;
            let key_der = std::fs::read(k).context("read persisted server key DER")?;
            tracing::info!(cert = %c.display(), "reused persisted server certificate");
            Ok(SelfSignedCert::from_der(cert_der, key_der))
        }
        (Some(c), Some(k)) => {
            let cert = generate_self_signed(subject_names)?;
            std::fs::write(c, cert.cert_der.as_ref()).context("write server cert DER")?;
            std::fs::write(k, &cert.key_der_bytes).context("write server key DER")?;
            tracing::info!(
                cert = %c.display(),
                key = %k.display(),
                "wrote self-signed server certificate (DER)"
            );
            Ok(cert)
        }
        _ => generate_self_signed(subject_names),
    }
}
