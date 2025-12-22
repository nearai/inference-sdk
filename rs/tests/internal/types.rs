#[derive(Clone, Debug)]
pub struct Context {
    pub api_domain: String,
    pub api_url: String,
    pub api_key: String,
    pub model: String,
}

#[derive(Clone, Debug)]
pub struct ChatCompletionsResponse {
    pub id: String,
    pub request_body_raw: Vec<u8>,
    pub response_body_raw: Vec<u8>,
}
