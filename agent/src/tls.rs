//! Agent 的 QUIC 客户端 TLS 配置。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring::default_provider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

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

fn build(roots: RootCertStore) -> Result<quinn::ClientConfig> {
    let rustls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let crypto =
        QuicClientConfig::try_from(rustls_cfg).context("build quic client crypto config")?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// 首次信任（TOFU）证书校验器：首次连接记录服务端证书 DER 到 `pin_dir/<sni>.der`，
/// 之后每次严格比对，证书变更则拒绝（防中间人）。签名校验用默认 ring provider 的算法
/// （仅验签、不验信任链），确保服务端确实持有对应私钥。
pub struct TofuVerifier {
    pin_dir: PathBuf,
    /// 默认 ring provider 的签名校验算法，仅用于验签（不验信任链）。
    supported: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for TofuVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TofuVerifier")
            .field("pin_dir", &self.pin_dir)
            .finish()
    }
}

impl TofuVerifier {
    pub fn new(pin_dir: PathBuf) -> Self {
        Self {
            pin_dir,
            supported: default_provider().signature_verification_algorithms,
        }
    }

    /// 由 SNI 生成 pin 文件名（非字母数字替换为 `_`，避免路径穿越）。
    fn pin_path(&self, server_name: &ServerName<'_>) -> PathBuf {
        let safe: String = server_name
            .to_str()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.pin_dir.join(format!("{safe}.der"))
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let path = self.pin_path(server_name);
        let der = end_entity.as_ref();
        match std::fs::read(&path) {
            Ok(existing) if existing == der => Ok(ServerCertVerified::assertion()),
            Ok(_) => Err(Error::General(
                "server certificate changed since first use (possible MITM); \
                 delete the pin file to re-trust"
                    .into(),
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&self.pin_dir)
                    .map_err(|e| Error::General(format!("create pin dir: {e}")))?;
                let mut tmp = path.clone();
                tmp.set_extension("der.tmp");
                std::fs::write(&tmp, der).map_err(|e| Error::General(format!("write pin: {e}")))?;
                std::fs::rename(&tmp, &path)
                    .map_err(|e| Error::General(format!("commit pin: {e}")))?;
                tracing::warn!(
                    sni = %server_name.to_str(),
                    path = %path.display(),
                    "trusted server certificate on first use (TOFU)"
                );
                Ok(ServerCertVerified::assertion())
            }
            Err(e) => Err(Error::General(format!("read pin: {e}"))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// 构建 TOFU 客户端配置：信任首次见到的服务端证书（固定到 `pin_dir`），之后严格比对。
pub fn client_config_tofu(pin_dir: PathBuf) -> Result<quinn::ClientConfig> {
    let verifier = TofuVerifier::new(pin_dir);
    let rustls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let crypto =
        QuicClientConfig::try_from(rustls_cfg).context("build quic client crypto config")?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::TofuVerifier;
    use rcgen::generate_simple_self_signed;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn cert_der(subjects: &[&str]) -> Vec<u8> {
        let certified =
            generate_simple_self_signed(subjects.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        certified.cert.der().as_ref().to_vec()
    }

    #[test]
    fn tofu_pins_then_verifies_then_rejects_change() {
        let dir = std::env::temp_dir().join(format!("rstunnel-tofu-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let verifier = TofuVerifier::new(dir.clone());
        let sn = ServerName::try_from("192.168.31.45").unwrap();

        let end = CertificateDer::from(cert_der(&["192.168.31.45"]));

        // 首次：接受并固定。
        assert!(verifier
            .verify_server_cert(&end, &[], &sn, &[], UnixTime::now())
            .is_ok());
        assert!(dir.join("192.168.31.45.der").exists());

        // 同证书：通过。
        assert!(verifier
            .verify_server_cert(&end, &[], &sn, &[], UnixTime::now())
            .is_ok());

        // 不同证书：拒绝。
        let other = CertificateDer::from(cert_der(&["192.168.31.46"]));
        assert!(verifier
            .verify_server_cert(&other, &[], &sn, &[], UnixTime::now())
            .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
