//! Pin TLS before HTTP writes while retaining certificate/hostname validation.
use crate::{
    errors::protocol,
    util::{require_hex_length, sha256},
    VerificationError,
};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use std::sync::Arc;
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

pub fn create_pinned_tls_client(
    fingerprints: &[String],
) -> Result<reqwest::Client, VerificationError> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    pinned_client(fingerprints, roots)
}

pub(crate) fn pinned_client(
    fingerprints: &[String],
    roots: rustls::RootCertStore,
) -> Result<reqwest::Client, VerificationError> {
    if fingerprints.is_empty() {
        return Err(VerificationError::SpkiFingerprintRequired);
    }
    let pins = fingerprints
        .iter()
        .map(|s| {
            require_hex_length(s, 32)
                .map_err(|_| protocol("input.invalid", "expected a SHA256 SPKI fingerprint"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let normal = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| protocol("input.invalid", "invalid TLS roots"))?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| protocol("input.invalid", "invalid TLS configuration"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { normal, pins }))
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .https_only(true)
        .tls_info(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| protocol("input.invalid", "could not create pinned TLS client"))
}
#[derive(Debug)]
struct PinnedVerifier {
    normal: Arc<WebPkiServerVerifier>,
    pins: Vec<Vec<u8>>,
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .normal
            .verify_server_cert(cert, intermediates, name, ocsp, now)?;
        let der = Certificate::from_der(cert.as_ref())
            .and_then(|c| c.tbs_certificate.subject_public_key_info.to_der())
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        if !self.pins.iter().any(|pin| pin.as_slice() == sha256(&der)) {
            return Err(rustls::Error::General(
                "binding.spki_fingerprint_mismatch".into(),
            ));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.normal.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.normal.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.normal.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestationClient, GatewayAttestationFetchOptions, SigningAlgo};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn pin_hostname_and_chain_failures_precede_http_writes() {
        for operation in ["chat", "model", "signature", "metadata", "gateway"] {
            for case in ["valid", "wrong_pin", "wrong_hostname", "untrusted"] {
                let certified =
                    rcgen::generate_simple_self_signed(vec![if case == "wrong_hostname" {
                        "elsewhere.test"
                    } else {
                        "localhost"
                    }
                    .to_owned()])
                    .unwrap();
                let cert = certified.cert.der().clone();
                let parsed = Certificate::from_der(cert.as_ref()).unwrap();
                let spki = parsed
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap();
                let actual_pin = hex::encode(sha256(spki));
                let private = rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certified.signing_key.serialize_der(),
                );
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let server = rustls::ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert.clone()], private.into())
                    .unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let reported_pin = actual_pin.clone();
                let task = tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
                    if let Ok(mut socket) = acceptor.accept(socket).await {
                        let mut buf = [0; 4096];
                        let count = socket.read(&mut buf).await.unwrap_or_default();
                        if count > 0 {
                            let request = std::str::from_utf8(&buf[..count]).unwrap();
                            let path = request.split_whitespace().nth(1).unwrap();
                            let url =
                                reqwest::Url::parse(&format!("https://localhost{path}")).unwrap();
                            let nonce = url
                                .query_pairs()
                                .find(|(name, _)| name == "nonce")
                                .map(|(_, value)| value.into_owned());
                            let report = json!({
                                "request_nonce": nonce,
                                "signing_algo": "ed25519",
                                "signing_address": "ab".repeat(32),
                                "intel_quote": "aa",
                                "report_data": "00".repeat(64),
                                "event_log": [],
                                "info": {"tcb_info": {"app_compose": "{}"}},
                            });
                            let body = match operation {
                                "model" => json!({"model_attestations": [report]}),
                                "gateway" => {
                                    let mut report = report;
                                    report["tls_cert_fingerprint"] = json!(reported_pin);
                                    json!({"gateway_attestation": report})
                                }
                                "signature" => json!({
                                    "signature_kind": "gateway", "text": "fixture",
                                    "signature": "00".repeat(64), "signing_algo": "ed25519",
                                    "signing_address": "ab".repeat(32),
                                }),
                                "metadata" => json!({"metadata": {"providerType": "vllm", "attestationSupported": true}}),
                                _ => json!({}),
                            }.to_string();
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                            socket.write_all(response.as_bytes()).await.unwrap();
                        }
                        count > 0
                    } else {
                        false
                    }
                });
                let pin = if case == "wrong_pin" {
                    "00".repeat(32)
                } else {
                    actual_pin.clone()
                };
                let mut roots = rustls::RootCertStore::empty();
                if case == "untrusted" {
                    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                } else {
                    roots.add(cert).unwrap();
                }
                let client = pinned_client(&[pin], roots).unwrap();
                let base_url = format!("https://localhost:{}/v1", address.port());
                let api = AttestationClient::with_base_url(Some("test-key".into()), &base_url)
                    .unwrap()
                    .with_http_client(client.clone());
                let succeeded = match operation {
                    "model" => api
                        .fetch_model_attestations("vendor/model", Some(SigningAlgo::Ed25519), None)
                        .await
                        .is_ok(),
                    "signature" => api
                        .fetch_completion_signature("completion", Some(SigningAlgo::Ed25519))
                        .await
                        .is_ok(),
                    "metadata" => api.fetch_model_metadata("vendor/model").await.is_ok(),
                    "gateway" => match api
                        .fetch_gateway_attestation(GatewayAttestationFetchOptions::default())
                        .await
                    {
                        Ok(fetched) => {
                            assert_eq!(
                                fetched.client_binding.spki_fingerprint.as_ref(),
                                Some(&actual_pin)
                            );
                            true
                        }
                        Err(_) => false,
                    },
                    _ => client
                        .post(format!("{base_url}/chat/completions"))
                        .body("confidential prompt")
                        .send()
                        .await
                        .is_ok(),
                };
                assert_eq!(succeeded, case == "valid", "{operation}/{case}");
                assert_eq!(
                    task.await.unwrap(),
                    case == "valid",
                    "HTTP was written for {operation}/{case}"
                );
            }
        }
    }
    #[test]
    fn rejects_empty_and_invalid_pins() {
        assert_eq!(
            create_pinned_tls_client(&[]).unwrap_err().code(),
            "binding.spki_fingerprint_required"
        );
        assert!(create_pinned_tls_client(&["not-hex".into()]).is_err());
    }
}
