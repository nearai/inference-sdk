// Experimental standalone direct verification; sends plaintext over HTTPS.
use example_rs::*;
use nearai_inference_sdk::*;
#[tokio::main]
async fn main() -> Result<()> {
    let key = api_key()?;
    let api = DirectAttestationClient::new(DIRECT, Some(key.clone()))?;
    let fetched = api.fetch_model_attestations(Some(ALGO), None).await?;
    let verified = verify_direct_model_attestations(&fetched, None, Default::default()).await?;
    println!("Verified {} model reports", verified.attestations.len());
    // Direct TLS fingerprint fetching is disabled. Keep normal certificate/hostname
    // validation and disable redirects; use Gateway clients for production.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    for stream in [false, true] {
        let request = request(DIRECT, &key, stream)?;
        let wire_request = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .ok_or("Missing request body")?
            .to_vec();
        let bytes = http
            .execute(request)
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let id = completion_id(&bytes, stream)?;
        let signature = api.fetch_completion_signature(&id, Some(ALGO)).await?;
        let matching = verify_direct_model_response(
            &wire_request,
            &bytes,
            &signature,
            &verified.attestations,
        )?;
        println!(
            "Verified receipt against {} matching reports",
            matching.len()
        );
        display(&bytes, stream)?;
    }
    Ok(())
}
