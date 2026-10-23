//! System One wire types. Request business validation remains server-owned.
use crate::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum SystemOneContent {
    Text(String),
    Object(serde_json::Map<String, Value>),
    Array(Vec<Value>),
}

impl<'de> Deserialize<'de> for SystemOneContent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Decode JSON numbers before selecting the content shape. Serde's
        // untagged buffering otherwise exposes arbitrary-precision numbers as
        // a private map representation, which can be mistaken for an object.
        match Value::deserialize(deserializer)? {
            Value::String(text) => Ok(Self::Text(text)),
            Value::Object(object) => Ok(Self::Object(object)),
            Value::Array(array) => Ok(Self::Array(array)),
            _ => Err(serde::de::Error::custom("expected text, object or array")),
        }
    }
}

fn deserialize_json_number_field<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    // Internally tagged enums buffer fields through serde's Content type.
    // Restore arbitrary-precision Number values before decoding typed floats.
    serde_json::from_value(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SystemOneQuestion {
    Noul {
        instructions: SystemOneContent,
        #[serde(skip_serializing_if = "Option::is_none")]
        criteria: Option<BTreeMap<String, SystemOneContent>>,
    },
    Choice {
        instructions: SystemOneContent,
        criteria: BTreeMap<String, Option<SystemOneContent>>,
    },
    Score {
        instructions: SystemOneContent,
        criteria: Vec<SystemOneContent>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemOneRequest {
    pub model: String,
    pub state: SystemOneContent,
    pub questions: BTreeMap<String, SystemOneQuestion>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SystemOneAnswer {
    Noul {
        #[serde(deserialize_with = "deserialize_json_number_field")]
        noul: f64,
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    Choice {
        choice: String,
        #[serde(deserialize_with = "deserialize_json_number_field")]
        confidence: f64,
        #[serde(deserialize_with = "deserialize_json_number_field")]
        probabilities: BTreeMap<String, f64>,
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    Score {
        #[serde(deserialize_with = "deserialize_json_number_field")]
        score: f64,
        #[serde(deserialize_with = "deserialize_json_number_field")]
        confidence: f64,
        #[serde(deserialize_with = "deserialize_json_number_field")]
        probabilities: BTreeMap<String, f64>,
        legend: BTreeMap<String, SystemOneContent>,
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemOneUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemOneResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub model: String,
    pub answers: BTreeMap<String, SystemOneAnswer>,
    pub usage: SystemOneUsage,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
/// Unverified decision data. Call verify_response(decision_id) before using it.
#[derive(Clone, Debug)]
pub struct SystemOneResult {
    pub data: SystemOneResponse,
    pub decision_id: String,
}

pub(crate) fn decode_response(bytes: &[u8]) -> Result<SystemOneResponse, ApiError> {
    let invalid = || ApiError::InvalidResponse {
        path: "systemone".into(),
        expected: "a valid System One response".into(),
        actual: "missing or invalid".into(),
    };
    let response: SystemOneResponse = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if response.model.is_empty() {
        return Err(invalid());
    }
    let probability = |p: f64| p.is_finite() && (0.0..=1.0).contains(&p);
    for answer in response.answers.values() {
        let valid = match answer {
            SystemOneAnswer::Noul { noul, .. } => probability(*noul),
            SystemOneAnswer::Choice {
                confidence,
                probabilities,
                ..
            } => probability(*confidence) && probabilities.values().all(|p| probability(*p)),
            SystemOneAnswer::Score {
                score,
                confidence,
                probabilities,
                ..
            } => {
                score.is_finite()
                    && probability(*confidence)
                    && probabilities.values().all(|p| probability(*p))
            }
        };
        if !valid {
            return Err(invalid());
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_rejects_number_primitives_even_with_arbitrary_precision() {
        for value in ["0", "-0.0", "1e400", "18446744073709551616", "true", "null"] {
            assert!(
                serde_json::from_str::<SystemOneContent>(value).is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn question_instructions_are_required() {
        for mut question in [
            serde_json::json!({"type":"noul"}),
            serde_json::json!({"type":"choice","criteria":{"billing":null,"other":null}}),
            serde_json::json!({"type":"score","criteria":["low","high"]}),
        ] {
            assert!(serde_json::from_value::<SystemOneQuestion>(question.clone()).is_err());
            question["instructions"] = Value::Null;
            assert!(serde_json::from_value::<SystemOneQuestion>(question.clone()).is_err());
            for instructions in [
                serde_json::json!("Evaluate this request."),
                serde_json::json!({"task":"Evaluate this request."}),
                serde_json::json!(["Evaluate this request."]),
            ] {
                question["instructions"] = instructions.clone();
                let parsed: SystemOneQuestion = serde_json::from_value(question.clone()).unwrap();
                assert_eq!(
                    serde_json::to_value(parsed).unwrap()["instructions"],
                    instructions
                );
            }
        }
    }

    #[test]
    fn shared_response_vectors() {
        let fixture: Value =
            serde_json::from_str(include_str!("../test-fixtures/systemone-responses.json"))
                .unwrap();
        for value in fixture["valid"].as_array().unwrap() {
            let response = decode_response(&serde_json::to_vec(value).unwrap()).unwrap();
            assert!(response.answers.contains_key("__proto__"));
            assert_eq!(response.extra["future"], value["future"]);
        }
        for (name, value) in fixture["invalid"].as_object().unwrap() {
            assert!(
                decode_response(&serde_json::to_vec(value).unwrap()).is_err(),
                "{name}: accepted {value}"
            );
        }
    }
}
