//! QUIC 的 TLS 配置。开发/测试用 rcgen 自签名证书；生产从 ACME/配置加载（T-27）。

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
