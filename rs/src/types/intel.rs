use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntelTdxVerificationData {
    pub quote: IntelQuote,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntelQuote {
    pub verified: bool,
    pub body: IntelQuoteBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntelQuoteBody {
    pub reportdata: String,
    pub mrconfig: String,
}
