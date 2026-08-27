//! 证书管理 + SNI 解析（T-27）：加载手动证书（PEM 证书链 + PEM 私钥），按 hostname 索引，
//! 实现 rustls [`ResolvesServerCert`] 供 TLS 终止入口按 SNI 选证书；并在加载/扫描时做过期告警。
//!
//! v1 范围：手动证书（PEM）。私钥静态加密、ACME/Let's Encrypt 自动签发留待后续任务。

use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;
use tunnel_db::CertificateRow;

/// 一张已解析的证书：覆盖的 hostname 集合、rustls 可用的签名密钥链与过期时间。
pub struct CertEntry {
    hostnames: Vec<String>,
    expires_at: Option<OffsetDateTime>,
    certified_key: Arc<CertifiedKey>,
}

impl CertEntry {
    /// 从 PEM 证书链 + PEM 私钥构造；hostnames 归一化为小写。
    pub fn from_pem(hostnames: Vec<String>, cert_pem: &str, key_pem: &str) -> Result<Self> {
        let cert_chain = parse_cert_chain(cert_pem)?;
        if cert_chain.is_empty() {
            bail!("certificate PEM contains no certificates");
        }
        let key = parse_private_key(key_pem)?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| anyhow::anyhow!("unsupported private key: {e}"))?;
        let certified_key = Arc::new(CertifiedKey::new(cert_chain.clone(), signing_key));
        let expires_at = cert_not_after(&cert_chain[0])?;
        Ok(Self {
            hostnames: hostnames
                .into_iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            expires_at,
            certified_key,
        })
    }

    pub fn hostnames(&self) -> &[String] {
        &self.hostnames
    }

    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }
}

/// 解析 PEM 证书链（可含多张，叶证书在前）。
fn parse_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate PEM")
}

/// 解析 PEM 私钥（PKCS#8 / RSA / EC）。
fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .context("parse private key PEM")?
        .context("no private key found in PEM")
}

/// 提取叶证书的 NotAfter（证书过期时间）。
fn cert_not_after(cert: &CertificateDer<'_>) -> Result<Option<OffsetDateTime>> {
    let (_, x509) =
        x509_parser::parse_x509_certificate(cert.as_ref()).context("parse X.509 certificate")?;
    Ok(Some(x509.validity().not_after.to_datetime()))
}

/// hostname → 证书 的存储（大小写不敏感），供 SNI 解析与过期扫描共用。
#[derive(Default)]
pub struct CertStore {
    by_hostname: HashMap<String, Arc<CertEntry>>,
    /// 去重后的证书列表（每张证书可覆盖多个 hostname），供过期扫描。
    entries: Vec<Arc<CertEntry>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 从数据库证书行构建（解析 hostnames JSON + PEM 证书/私钥）。
    pub fn from_rows(rows: &[CertificateRow]) -> Result<Self> {
        let mut store = Self::new();
        for row in rows {
            let hostnames: Vec<String> = serde_json::from_str(&row.hostnames)
                .with_context(|| format!("parse hostnames for certificate {}", row.name))?;
            let key_pem = row.private_key_encrypted.as_deref().unwrap_or_default();
            if key_pem.is_empty() {
                bail!("certificate {} has no private key", row.name);
            }
            let entry = CertEntry::from_pem(hostnames, &row.certificate, key_pem)
                .with_context(|| format!("load certificate {}", row.name))?;
            store.insert(entry)?;
        }
        Ok(store)
    }

    /// 插入一张证书，按每个 hostname 建索引；重复 hostname 报错。
    pub fn insert(&mut self, entry: CertEntry) -> Result<()> {
        let hostnames = entry.hostnames.clone();
        for host in &hostnames {
            if self.by_hostname.contains_key(host) {
                bail!("duplicate certificate hostname {host}");
            }
        }
        let entry = Arc::new(entry);
        for host in hostnames {
            self.by_hostname.insert(host, Arc::clone(&entry));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// 按 SNI 查找证书（大小写不敏感）。
    pub fn lookup(&self, sni: &str) -> Option<Arc<CertEntry>> {
        self.by_hostname.get(&sni.to_ascii_lowercase()).cloned()
    }

    /// 已加载证书数（按 hostname 计）。
    pub fn len(&self) -> usize {
        self.by_hostname.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hostname.is_empty()
    }

    /// 已过期或将在 `warn_before` 内过期的证书，返回 `(hostnames, expires_at)`。
    pub fn expiring(
        &self,
        now: OffsetDateTime,
        warn_before: time::Duration,
    ) -> Vec<(String, OffsetDateTime)> {
        self.entries
            .iter()
            .filter_map(|e| {
                let exp = e.expires_at?;
                (exp <= now + warn_before).then(|| (e.hostnames.join(","), exp))
            })
            .collect()
    }
}

/// 按 SNI 选证书的 rustls 证书解析器（T-27 TLS 终止）。
#[derive(Clone)]
pub struct CertResolver {
    store: Arc<CertStore>,
}

impl CertResolver {
    pub fn new(store: Arc<CertStore>) -> Self {
        Self { store }
    }
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver")
            .field("hostnames", &self.store.len())
            .finish()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        self.store.lookup(sni).map(|e| Arc::clone(&e.certified_key))
    }
}

/// 用 SNI 证书解析器构建 rustls 服务端配置（供 TLS 终止入口的 tokio-rustls acceptor 使用）。
pub fn server_config(resolver: CertResolver) -> rustls::ServerConfig {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use rcgen::generate_simple_self_signed;

    /// 生成一张自签名证书的 PEM（cert + key），SAN 为给定 hostnames。
    fn gen_cert_pem(hostnames: &[&str]) -> (String, String) {
        let certified = generate_simple_self_signed(
            hostnames.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();
        (cert_pem, key_pem)
    }

    #[test]
    fn parse_and_lookup_by_sni_case_insensitive() {
        let (cert_pem, key_pem) = gen_cert_pem(&["app.example.com"]);
        let entry =
            CertEntry::from_pem(vec!["app.example.com".into()], &cert_pem, &key_pem).unwrap();
        assert!(entry.expires_at().is_some());

        let mut store = CertStore::new();
        store.insert(entry).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.lookup("app.example.com").is_some());
        assert!(store.lookup("APP.EXAMPLE.COM").is_some());
        assert!(store.lookup("other.example.com").is_none());
    }

    #[test]
    fn duplicate_hostname_is_rejected() {
        let (cert_pem, key_pem) = gen_cert_pem(&["app.example.com"]);
        let mut store = CertStore::new();
        store
            .insert(
                CertEntry::from_pem(vec!["app.example.com".into()], &cert_pem, &key_pem).unwrap(),
            )
            .unwrap();
        let err = store
            .insert(
                CertEntry::from_pem(vec!["app.example.com".into()], &cert_pem, &key_pem).unwrap(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    #[test]
    fn expiring_reports_near_expiry() {
        let (cert_pem, key_pem) = gen_cert_pem(&["app.example.com"]);
        let entry =
            CertEntry::from_pem(vec!["app.example.com".into()], &cert_pem, &key_pem).unwrap();
        let exp = entry.expires_at().unwrap();
        let mut store = CertStore::new();
        store.insert(entry).unwrap();

        // 阈值设为剩余有效期 + 1 天 → 必然命中。
        let warn_before = exp - OffsetDateTime::now_utc() + time::Duration::days(1);
        let expiring = store.expiring(OffsetDateTime::now_utc(), warn_before);
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].0, "app.example.com");
        assert_eq!(expiring[0].1, exp);
    }
}
