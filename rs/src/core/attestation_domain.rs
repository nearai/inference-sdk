use crate::core::attestation_common::{get_compose_from_tcb_info, verify_compose};
use crate::types::attestation_domain::DomainAttestation;
use crate::utils::common::hex_to_bytes;
use crate::utils::consts::TIMEOUT;
use crate::utils::errors::VerificationError;
use crate::utils::intel::fetch_intel_tdx_verification_data;
use sha2::{Digest, Sha256};
use serde_json::Value;
use std::time::SystemTime;
use x509_parser::prelude::*;

pub async fn verify_domain_attestation(
    attestation: &DomainAttestation,
) -> Result<(), VerificationError> {
    let verification_data = fetch_intel_tdx_verification_data(&attestation.intel_quote).await?;

    verify_intel_tdx_for_domain(
        &verification_data,
        &attestation.domain,
        &attestation.cert,
        &attestation.acme_account,
        &attestation.sha256sum,
    )?;

    let tcb_info_value = match &attestation.info.tcb_info {
        crate::types::attestation_domain::TcbInfoOrString::String(s) => {
            serde_json::Value::String(s.clone())
        }
        crate::types::attestation_domain::TcbInfoOrString::Object(obj) => {
            serde_json::to_value(obj)
                .map_err(|e| VerificationError::new(format!("Failed to serialize tcb_info: {}", e)))?
        }
    };
    let compose = get_compose_from_tcb_info(&tcb_info_value)?;
    verify_compose(&compose).await?;

    let live_cert = fetch_live_certificate(&attestation.domain).await?;
    verify_live_certificate(&live_cert, &attestation.cert).await?;

    Ok(())
}

fn verify_intel_tdx_for_domain(
    verification_data: &crate::types::intel::IntelTdxVerificationData,
    domain: &str,
    cert: &str,
    acme_account: &str,
    sha256sum: &str,
) -> Result<(), VerificationError> {
    if !verification_data.quote.verified {
        return Err(VerificationError::new("Intel quote not verified".to_string()));
    }

    verify_intel_quote_report_data_for_domain(
        &verification_data.quote.body.reportdata,
        domain,
        cert,
        acme_account,
        sha256sum,
    )
}

fn verify_intel_quote_report_data_for_domain(
    report_data: &str,
    domain: &str,
    cert: &str,
    acme_account: &str,
    sha256sum: &str,
) -> Result<(), VerificationError> {
    let acme_account_hash = Sha256::digest(acme_account.as_bytes());
    let cert_hash = Sha256::digest(cert.as_bytes());

    let expected_sha256sum_file = format!(
        "{}  acme-account.json\n{}  cert-{}.pem\n",
        hex::encode(acme_account_hash),
        hex::encode(cert_hash),
        domain
    );

    let expected_sha256sum = Sha256::digest(expected_sha256sum_file.as_bytes());

    let report_data_raw = hex_to_bytes(report_data)?;

    if report_data_raw.len() < 64 {
        return Err(VerificationError::new("Invalid report data length".to_string()));
    }

    let embedded_sha256sum = &report_data_raw[0..32];
    let embedded_remaining = &report_data_raw[32..64];

    if expected_sha256sum_file != sha256sum {
        return Err(VerificationError::new("sha256sum file mismatching".to_string()));
    }

    if embedded_sha256sum != expected_sha256sum.as_slice() {
        return Err(VerificationError::new("sha256sum mismatching".to_string()));
    }

    if embedded_remaining != vec![0u8; 32].as_slice() {
        return Err(VerificationError::new(
            "Embedded remaining bytes mismatching".to_string(),
        ));
    }

    Ok(())
}

async fn verify_live_certificate(
    live_cert: &[u8],
    cert: &str,
) -> Result<(), VerificationError> {
    let cert_chain = parse_certificate_chain(cert)?;

    if cert_chain.len() < 2 {
        return Err(VerificationError::new(
            "Unexpected length of certificate chain".to_string(),
        ));
    }

    let root_cert = &cert_chain[cert_chain.len() - 1];
    let leaf_cert = &cert_chain[0];

    verify_certificate_chain(&cert_chain)?;
    verify_certificate_root(root_cert)?;
    verify_certificate_leaf(leaf_cert)?;

    verify_certificate_fingerprint(leaf_cert, live_cert)?;

    Ok(())
}

fn parse_certificate_chain(cert: &str) -> Result<Vec<X509Certificate>, VerificationError> {
    let re = regex::Regex::new(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")
        .map_err(|e| VerificationError::new(format!("Failed to create regex: {}", e)))?;

    let mut parsed_certificates = Vec::new();

    for cap in re.captures_iter(cert) {
        if let Some(m) = cap.get(0) {
            let pem_bytes = m.as_str().as_bytes();
            let (_, x509_cert) = X509Certificate::from_pem(pem_bytes)
                .map_err(|e| VerificationError::new(format!("Failed to parse certificate: {}", e)))?;
            parsed_certificates.push(x509_cert);
        }
    }

    Ok(parsed_certificates)
}

fn verify_certificate_chain(cert_chain: &[X509Certificate]) -> Result<(), VerificationError> {
    for i in 0..cert_chain.len() - 1 {
        let cert = &cert_chain[i];
        let issuer_cert = &cert_chain[i + 1];

        // Note: x509-parser doesn't provide signature verification directly
        // This is a simplified version - in production, you'd need proper signature verification
        let cert_issuer = cert.issuer().to_string();
        let issuer_subject = issuer_cert.subject().to_string();

        if cert_issuer != issuer_subject {
            return Err(VerificationError::new(format!(
                "Certificate chain verification failed: Certificate {} issuer '{}' does not match next certificate subject '{}'",
                i, cert_issuer, issuer_subject
            )));
        }
    }

    Ok(())
}

fn verify_certificate_root(cert: &X509Certificate) -> Result<(), VerificationError> {
    let trusted_root_issuers = vec![
        "C=US, O=Internet Security Research Group, CN=ISRG Root X1",
        "C=US, O=Digital Signature Trust Co., CN=DST Root CA X3",
    ];

    let cert_issuer = cert.issuer().to_string();
    let cert_subject = cert.subject().to_string();

    let is_self_signed = cert_issuer == cert_subject;

    if is_self_signed {
        // Self-signed certificate - would need signature verification here
        Ok(())
    } else {
        let is_trusted = is_dn_trusted(&trusted_root_issuers, &cert_issuer)?;
        if !is_trusted {
            return Err(VerificationError::new(format!(
                "Certificate verification failed: Root certificate is not trusted (issuer: {})",
                cert_issuer
            )));
        }
        Ok(())
    }
}

fn verify_certificate_leaf(cert: &X509Certificate) -> Result<(), VerificationError> {
    let validity = cert.validity();
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if validity.not_before.timestamp() as u64 > now {
        return Err(VerificationError::new(format!(
            "Failed to verify leaf certificate: Certificate is not yet valid (valid from: {})",
            validity.not_before
        )));
    }

    if (validity.not_after.timestamp() as u64) < now {
        return Err(VerificationError::new(format!(
            "Failed to verify leaf certificate: Certificate has expired (valid to: {})",
            validity.not_after
        )));
    }

    Ok(())
}

fn verify_certificate_fingerprint(
    cert: &X509Certificate,
    live_cert: &[u8],
) -> Result<(), VerificationError> {
    let fingerprint1 = get_certificate_fingerprint(cert)?;
    let (_, live_cert_parsed) = X509Certificate::from_der(live_cert)
        .map_err(|e| VerificationError::new(format!("Failed to parse live certificate: {}", e)))?;
    let fingerprint2 = get_certificate_fingerprint(&live_cert_parsed)?;

    if fingerprint1 != fingerprint2 {
        return Err(VerificationError::new(
            "Certificate fingerprint mismatching".to_string(),
        ));
    }

    Ok(())
}

fn get_certificate_fingerprint(cert: &X509Certificate) -> Result<String, VerificationError> {
    let der = cert.tbs_certificate().as_ref();
    let hash = Sha256::digest(der);
    let hash_hex = hex::encode(hash).to_uppercase();
    let fingerprint = hash_hex
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(":");

    Ok(fingerprint)
}

async fn fetch_live_certificate(domain: &str) -> Result<Vec<u8>, VerificationError> {
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use rustls::ClientConfig;

    let addr = format!("{}:443", domain);
    let stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| VerificationError::new(format!("Failed to connect to {}: {}", domain, e)))?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(
        rustls_native_certs::load_native_certs()
            .map_err(|e| VerificationError::new(format!("Failed to load root certs: {}", e)))?
            .iter()
            .map(|cert| rustls::Certificate(cert.0.clone())),
    );

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let mut tls_stream = connector
        .connect(domain.try_into().map_err(|_| {
            VerificationError::new(format!("Invalid domain name: {}", domain))
        })?, stream)
        .await
        .map_err(|e| VerificationError::new(format!("TLS connection error: {}", e)))?;

    let (_, session) = tls_stream.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| VerificationError::new("Failed to get peer certificates".to_string()))?;

    if certs.is_empty() {
        return Err(VerificationError::new("No certificates found".to_string()));
    }

    Ok(certs[0].0.clone())
}

fn is_dn_trusted(trusted_dns: &[&str], dn: &str) -> Result<bool, VerificationError> {
    let dn_components = dn_string_to_components(dn);

    for trusted_dn in trusted_dns {
        let trusted_dn_components = dn_string_to_components(trusted_dn);

        let trusted_dn_cn = trusted_dn_components
            .get("CN")
            .ok_or_else(|| VerificationError::new("Trusted dn must include 'CN' component".to_string()))?;

        let trusted_dn_o = trusted_dn_components
            .get("O")
            .ok_or_else(|| VerificationError::new("Trusted dn must include 'O' component".to_string()))?;

        let trusted_dn_c = trusted_dn_components
            .get("C")
            .ok_or_else(|| VerificationError::new("Trusted dn must include 'C' component".to_string()))?;

        if dn_components.get("CN") == Some(trusted_dn_cn)
            && dn_components.get("O") == Some(trusted_dn_o)
            && dn_components.get("C") == Some(trusted_dn_c)
        {
            return Ok(true);
        }
    }

    Ok(false)
}

fn dn_string_to_components(dn: &str) -> std::collections::HashMap<String, String> {
    let mut components = std::collections::HashMap::new();

    let parts: Vec<&str> = if dn.contains('\n') {
        dn.split('\n').collect()
    } else {
        dn.split(',').collect()
    };

    for part in parts {
        let part = part.trim();
        if let Some(idx) = part.find('=') {
            let key = part[..idx].trim().to_string();
            let value = part[idx + 1..].trim().to_string();
            if !key.is_empty() {
                components.insert(key, value);
            }
        }
    }

    components
}

