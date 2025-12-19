use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelTdxVerificationData {
    pub quote: IntelQuote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelQuote {
    pub verified: bool,
    pub body: IntelQuoteBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelQuoteBody {
    pub reportdata: String,
    pub mrconfig: String,
}

