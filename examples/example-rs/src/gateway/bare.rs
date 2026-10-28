// Standalone Gateway E2EE: authenticate evidence, retain ciphertext, verify receipts.
use example_rs::*;
use futures_util::StreamExt;
use nearai_inference_sdk::*;
use std::sync::{Arc, Mutex};
#[tokio::main]
async fn main() -> Result<()> {
    let key = api_key()?;
    let api = AttestationClient::with_base_url(key.clone(), &gateway())?;
    let fetched = api
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(algo()?),
            ..Default::default()
        })
        .await?;
    let images = GatewayImages;
    let verified_gateway = verify_gateway_attestation(
        &fetched.attestation,
        &fetched.client_binding,
        None,
        AttestationVerifiers {
            deployment: Some(&images),
            ..Default::default()
        },
    )
    .await?;
    let pin = match &verified_gateway.tls_binding {
        GatewayTlsBinding::Attested { spki_fingerprint } => spki_fingerprint,
        _ => return Err("Gateway did not supply attested TLS binding".into()),
    };
    let http = create_pinned_tls_client(std::slice::from_ref(pin))?;
    let fetched_models = api
        .fetch_model_attestations(&model(), Some(algo()?), None)
        .await?;
    let mut models = Vec::new();
    for report in &fetched_models.attestations {
        models.push(
            verify_model_attestation(
                report,
                &fetched_models.client_binding,
                None,
                ModelAttestationVerifiers {
                    deployment: Some(&ModelImages),
                    ..Default::default()
                },
            )
            .await?,
        );
    }
    let recipient_algo = algo()?;
    let recipient = models
        .iter()
        .find(|m| {
            m.evidence.signer.signing_algo == recipient_algo && m.signing_public_key.is_some()
        })
        .ok_or("No verified model public key")?;
    let model_key = E2eeModelKey {
        signing_algo: algo()?,
        public_key: recipient.signing_public_key.clone().unwrap(),
    };
    println!("Gateway/model deployments and Gateway images verified");
    for stream in [false, true] {
        let prepared = prepare_e2ee_chat_request(request(&gateway(), &key, stream)?, &model_key)?;
        let wire_request = prepared
            .request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .ok_or("Missing request body")?
            .to_vec();
        let response = http
            .execute(
                prepared
                    .request
                    .try_clone()
                    .ok_or("Request cannot be cloned")?,
            )
            .await?
            .error_for_status()?;
        // Capture ciphertext before decryption. Consume the actual network stream
        // through EOF; signatures cover these wire bytes, not the plaintext.
        let (wire_response, plaintext) = if stream {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let recording = captured.clone();
            let source: ByteStream = Box::pin(response.bytes_stream().map(move |chunk| {
                let chunk = chunk.map_err(|_| {
                    InferenceError::from(ApiError::Transport {
                        resource: ApiResource::Completion,
                        reason: ApiTransportReason::ResponseBody,
                    })
                })?;
                recording
                    .lock()
                    .expect("recording lock")
                    .extend_from_slice(&chunk);
                Ok(chunk)
            }));
            let output = read_stream(prepared.decrypt_sse(source)).await?;
            let wire = captured.lock().expect("recording lock").clone();
            (wire, output)
        } else {
            let wire = response.bytes().await?.to_vec();
            let plaintext = serde_json::to_vec(&prepared.decrypt_json(&wire)?)?;
            (wire, plaintext)
        };
        let id = completion_id(&plaintext, stream)?;
        let signature = api.fetch_completion_signature(&id, Some(algo()?)).await?;
        match signature.kind {
            CompletionSignatureKind::ProviderTee => {
                verify_model_response(&wire_request, &wire_response, &signature, recipient)?
            }
            CompletionSignatureKind::Gateway => verify_gateway_response(
                &wire_request,
                &wire_response,
                &signature,
                &verified_gateway,
            )?,
        }
        println!("Verified {:?} ciphertext receipt", signature.kind);
        display(&plaintext, stream)?;
    }
    Ok(())
}
