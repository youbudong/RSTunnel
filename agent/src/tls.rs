//! Agent 的 QUIC 客户端 TLS 配置。

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

/// 信任单个（自签名）证书 —— 开发/测试用。
pub fn client_config_with_cert(cert: &CertificateDer<'static>) -> Result<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(cert.clone())
        .context("add certificate to root store")?;
    build(roots)
}

/// 从 DER 字节构建信任该证书的客户端配置（`main` 从 `[server].ca` 文件加载）。
pub fn client_config_from_der(der: Vec<u8>) -> Result<quinn::ClientConfig> {
    let cert: CertificateDer<'static> = CertificateDer::from(der);
    client_config_with_cert(&cert)
}

/// 空信任锚：拒绝所有服务端证书（安全默认）。系统根在 T-30 接入。
pub fn client_config_without_roots() -> Result<quinn::ClientConfig> {
    build(RootCertStore::empty())
}

fn build(roots: RootCertStore) -> Result<quinn::ClientConfig> {
    let rustls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let crypto =
        QuicClientConfig::try_from(rustls_cfg).context("build quic client crypto config")?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}
