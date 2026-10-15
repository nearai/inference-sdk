mod serialization;

use std::io::{self, Read};

use anyhow::{bail, Context};
use dcap_qvl::QuoteCollateralV3;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Request {
    operation: String,
    input: String,
    collateral: Option<QuoteCollateralV3>,
    now: Option<u64>,
    root: Option<String>,
}

fn run() -> anyhow::Result<Value> {
    let mut input = Vec::new();
    io::stdin()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;

    if input.len() > 16 * 1024 * 1024 {
        bail!("input exceeds verifier limit");
    }

    let request: Request = serde_json::from_slice(&input)?;
    let raw = hex::decode(request.input)?;

    match request.operation.as_str() {
        "parse" => serialization::parse(&raw),
        "pck" => serialization::pck(&raw),
        "verify" => {
            let collateral = request.collateral.context("missing collateral")?;
            let now = request.now.context("missing verification time")?;
            let root = request.root.map(hex::decode).transpose()?;

            serialization::verify(&raw, &collateral, now, root)
        }
        _ => bail!("unknown operation"),
    }
}

fn main() {
    let response = match run() {
        Ok(value) => json!({
            "result": value,
        }),
        Err(error) => json!({
            "error": format!("{error:#}"),
        }),
    };

    println!("{response}");
}
