use crate::internal::types::Context;

pub fn init_context() -> Context {
    let api_domain = std::env::var("API_DOMAIN").expect("Missing env API_DOMAIN");
    let api_key = std::env::var("API_KEY").expect("Missing env API_KEY");
    let model = std::env::var("MODEL").expect("Missing env MODEL");

    Context {
        api_url: format!("https://{}/v1", api_domain),
        api_domain,
        api_key,
        model,
    }
}
