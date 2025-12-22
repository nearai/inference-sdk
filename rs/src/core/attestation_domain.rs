use crate::core::attestation_common::{get_compose_from_tcb_info, verify_compose};
use crate::types::attestation_domain::DomainAttestation;
use crate::types::intel::IntelTdxVerificationData;
use crate::utils::common::hex_to_bytes;
use crate::utils::errors::Error;
use crate::utils::intel::fetch_intel_tdx_verification_data;
use pem_rfc7468::decode_vec;
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

pub async fn verify_domain_attestation(attestation: &DomainAttestation) -> Result<(), Error> {
    let verification_data = fetch_intel_tdx_verification_data(&attestation.intel_quote).await?;

    verify_intel_tdx_for_domain(
        &verification_data,
        &attestation.domain,
        &attestation.cert,
        &attestation.acme_account,
        &attestation.sha256sum,
    )?;

    let compose = get_compose_from_tcb_info(&attestation.info.tcb_info)?;
    verify_compose(&compose).await?;

    let live_cert = fetch_live_certificate(&attestation.domain).await?;
    verify_live_certificate(&live_cert, &attestation.cert).await?;

    Ok(())
}

fn verify_intel_tdx_for_domain(
    verification_data: &IntelTdxVerificationData,
    domain: &str,
    cert: &str,
    acme_account: &str,
    sha256sum: &str,
) -> Result<(), Error> {
    if !verification_data.quote.verified {
        return Err(Error::verification("Intel quote not verified".to_owned()));
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
) -> Result<(), Error> {
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

    // The report data must be exactly 64 bytes: first 32 bytes are the SHA256,
    // the remaining 32 bytes must all be zero (see JS/Python SDKs).
    if report_data_raw.len() != 64 {
        return Err(Error::verification("invalid report data length".to_owned()));
    }

    let embedded_sha256sum = &report_data_raw[0..32];
    let embedded_remaining = &report_data_raw[32..];

    if expected_sha256sum_file != sha256sum {
        return Err(Error::verification("sha256sum file mismatching".to_owned()));
    }

    if embedded_sha256sum != expected_sha256sum.as_slice() {
        return Err(Error::verification("sha256sum mismatching".to_owned()));
    }

    if embedded_remaining != vec![0u8; 32].as_slice() {
        return Err(Error::verification(
            "embedded remaining bytes mismatching".to_owned(),
        ));
    }

    Ok(())
}

async fn verify_live_certificate(live_cert: &Certificate, cert: &str) -> Result<(), Error> {
    let cert_chain = parse_certificate_chain(cert)?;

    if cert_chain.len() < 2 {
        return Err(Error::verification(
            "unexpected length of certificate chain".to_owned(),
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

fn parse_certificate_chain(cert: &str) -> Result<Vec<Certificate>, Error> {
    let re = regex::Regex::new(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")
        .map_err(|e| Error::verification(format!("failed to create regex: {}", e)))?;

    let mut parsed_certificates = Vec::new();

    for cap in re.captures_iter(cert) {
        if let Some(m) = cap.get(0) {
            let pem_bytes = m.as_str().as_bytes();

            // Use pem_rfc7468 to decode PEM into DER
            let (label, der) = decode_vec(pem_bytes).map_err(|e| {
                Error::verification(format!("failed to decode PEM certificate: {}", e))
            })?;

            if label != "CERTIFICATE" {
                return Err(Error::verification(format!(
                    "unexpected PEM label: expected 'CERTIFICATE', got '{}'",
                    label
                )));
            }

            let x509_cert = Certificate::from_der(&der)
                .map_err(|e| Error::verification(format!("failed to parse certificate: {}", e)))?;
            parsed_certificates.push(x509_cert);
        }
    }

    Ok(parsed_certificates)
}

fn verify_certificate_chain(cert_chain: &[Certificate]) -> Result<(), Error> {
    for i in 0..cert_chain.len() - 1 {
        let cert = &cert_chain[i];
        let issuer_cert = &cert_chain[i + 1];

        // Note: this is still a simplified chain check: we only compare subject/issuer DNs.
        let cert_issuer = &cert.tbs_certificate.issuer;
        let issuer_subject = &issuer_cert.tbs_certificate.subject;

        if cert_issuer != issuer_subject {
            return Err(Error::verification(format!(
                "certificate chain verification failed: Certificate {} issuer '{}' does not match next certificate subject '{}'",
                i, cert_issuer, issuer_subject
            )));
        }
    }

    Ok(())
}

fn verify_certificate_root(cert: &Certificate) -> Result<(), Error> {
    let trusted_root_issuers = vec![
        "C=US, O=Internet Security Research Group, CN=ISRG Root X1",
        "C=US, O=Digital Signature Trust Co., CN=DST Root CA X3",
    ];

    let cert_issuer = &cert.tbs_certificate.issuer;
    let cert_subject = &cert.tbs_certificate.subject;

    let is_self_signed = cert_issuer == cert_subject;

    if is_self_signed {
        // Self-signed certificate - would need signature verification here
        Ok(())
    } else {
        let is_trusted = is_dn_trusted(
            &trusted_root_issuers,
            &format!("{}", cert_issuer),
        )?;
        if !is_trusted {
            return Err(Error::verification(format!(
                "certificate verification failed: Root certificate is not trusted (issuer: {})",
                cert_issuer
            )));
        }
        Ok(())
    }
}

fn verify_certificate_leaf(cert: &Certificate) -> Result<(), Error> {
    let validity = &cert.tbs_certificate.validity;
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();

    if not_before > now {
        return Err(Error::verification(format!(
            "failed to verify leaf certificate: Certificate is not yet valid (valid from: {:?})",
            validity.not_before
        )));
    }

    if not_after < now {
        return Err(Error::verification(format!(
            "failed to verify leaf certificate: Certificate has expired (valid to: {:?})",
            validity.not_after
        )));
    }

    Ok(())
}

fn verify_certificate_fingerprint(cert: &Certificate, live_cert: &Certificate) -> Result<(), Error> {
    let fingerprint1 = get_certificate_fingerprint(cert)?;
    let fingerprint2 = get_certificate_fingerprint(live_cert)?;

    if fingerprint1 != fingerprint2 {
        return Err(Error::verification(
            "certificate fingerprint mismatching".to_owned(),
        ));
    }

    Ok(())
}

fn get_certificate_fingerprint(cert: &Certificate) -> Result<String, Error> {
    // Use the full certificate DER (not just TBS) to match JS/Python fingerprint behaviour.
    let der = cert
        .to_der()
        .map_err(|e| Error::verification(format!("failed to encode certificate: {}", e)))?;
    let hash = Sha256::digest(&der);
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

async fn fetch_live_certificate(domain: &str) -> Result<Certificate, Error> {
    use rustls::ClientConfig;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let addr = format!("{}:443", domain);
    let stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| Error::verification(format!("failed to connect to {}: {}", domain, e)))?;

    // Load system root certificates into the Rustls root store so that the TLS
    // handshake performs normal certificate validation.
    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs()
        .map_err(|e| Error::verification(format!("failed to load root certs: {}", e)))?;
    root_store.add_parsable_certificates(native_certs);

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let tls_stream = connector
        .connect(
            domain
                .try_into()
                .map_err(|_| Error::verification(format!("invalid domain name: {}", domain)))?,
            stream,
        )
        .await
        .map_err(|e| Error::verification(format!("tls connection error: {}", e)))?;

    let (_, session) = tls_stream.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| Error::verification("failed to get peer certificates".to_owned()))?;

    if certs.is_empty() {
        return Err(Error::verification("no certificates found".to_owned()));
    }

    let der = certs[0].as_ref();
    let live_cert = Certificate::from_der(der)
        .map_err(|e| Error::verification(format!("failed to parse live certificate: {}", e)))?;

    Ok(live_cert)
}

fn is_dn_trusted(trusted_dns: &[&str], dn: &str) -> Result<bool, Error> {
    let dn_components = dn_string_to_components(dn);

    for trusted_dn in trusted_dns {
        let trusted_dn_components = dn_string_to_components(trusted_dn);

        let trusted_dn_cn = trusted_dn_components.get("CN").ok_or_else(|| {
            Error::verification("trusted dn must include 'CN' component".to_owned())
        })?;

        let trusted_dn_o = trusted_dn_components.get("O").ok_or_else(|| {
            Error::verification("trusted dn must include 'O' component".to_owned())
        })?;

        let trusted_dn_c = trusted_dn_components.get("C").ok_or_else(|| {
            Error::verification("trusted dn must include 'C' component".to_owned())
        })?;

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
            let key = part[..idx].trim().to_owned();
            let value = part[idx + 1..].trim().to_owned();
            if !key.is_empty() {
                components.insert(key, value);
            }
        }
    }

    components
}
