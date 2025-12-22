use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgo {
    Ecdsa,
    Ed25519,
}

impl std::fmt::Display for SigningAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningAlgo::Ecdsa => f.write_str("ecdsa"),
            SigningAlgo::Ed25519 => f.write_str("ed25519"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcbInfo {
    pub app_compose: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TcbInfoOrRaw {
    Parsed(TcbInfo),
    Raw(String),
}

impl TryFrom<TcbInfoOrRaw> for TcbInfo {
    type Error = serde_json::Error;

    fn try_from(value: TcbInfoOrRaw) -> Result<Self, Self::Error> {
        match value {
            TcbInfoOrRaw::Parsed(info) => Ok(info),
            TcbInfoOrRaw::Raw(info) => serde_json::from_str(&info),
        }
    }
}
