use nearai_inference_sdk::{
    SystemOneAnswer, SystemOneBoxCoordinates, SystemOneContent, SystemOneQuestion,
    SystemOneRequest, SystemOneResponse,
};
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn external_callers_can_construct_every_question_variant() {
    let request = SystemOneRequest {
        model: "decision-model".into(),
        state: SystemOneContent::Text("A customer request".into()),
        questions: BTreeMap::from([
            (
                "yes_no".into(),
                SystemOneQuestion::Noul {
                    instructions: SystemOneContent::Text("Is this urgent?".into()),
                    criteria: None,
                },
            ),
            (
                "category".into(),
                SystemOneQuestion::Choice {
                    instructions: SystemOneContent::Text("Choose a category".into()),
                    criteria: BTreeMap::from([("billing".into(), None)]),
                },
            ),
            (
                "priority".into(),
                SystemOneQuestion::Score {
                    instructions: SystemOneContent::Text("Rate the priority".into()),
                    criteria: vec![SystemOneContent::Text("Urgent".into())],
                },
            ),
            (
                "region".into(),
                SystemOneQuestion::Box {
                    instructions: SystemOneContent::Text("Locate the rectangle".into()),
                },
            ),
        ]),
    };
    let encoded = serde_json::to_value(request).unwrap();
    assert_eq!(encoded["questions"]["yes_no"]["type"], "noul");
    assert_eq!(encoded["questions"]["region"]["type"], "box");
    assert!(encoded["questions"]["region"].get("criteria").is_none());
    assert_eq!(
        encoded["questions"]["category"]["criteria"],
        json!({"billing": null})
    );
    assert_eq!(
        encoded["questions"]["priority"]["criteria"],
        json!(["Urgent"])
    );
}

#[test]
fn external_callers_can_read_every_answer_payload() {
    let response: SystemOneResponse = serde_json::from_value(json!({
        "model": "decision-model",
        "answers": {
            "yes_no": {"type": "noul", "noul": 0.9, "future": true},
            "category": {
                "type": "choice", "choice": "billing", "confidence": 0.8,
                "probabilities": {"billing": 0.8}, "future": true
            },
            "priority": {
                "type": "score", "score": 1.0, "confidence": 0.7,
                "probabilities": {"1": 0.7}, "legend": {"1": "Urgent"}, "future": true
            },
            "region": {
                "type": "box", "confidence": 0.82, "future": true,
                "box": {"top": 0.31, "bottom": 0.69, "left": 0.25, "right": 0.75, "future": true}
            }
        },
        "usage": {"input_tokens": 1, "output_tokens": 1}
    }))
    .unwrap();
    let SystemOneAnswer::Noul { noul, extra } = &response.answers["yes_no"] else {
        panic!("expected noul");
    };
    assert_eq!(*noul, 0.9);
    assert_eq!(extra["future"], true);

    let SystemOneAnswer::Choice {
        choice,
        confidence,
        probabilities,
        extra,
    } = &response.answers["category"]
    else {
        panic!("expected choice");
    };
    assert_eq!(choice, "billing");
    assert_eq!(*confidence, 0.8);
    assert_eq!(probabilities["billing"], 0.8);
    assert_eq!(extra["future"], true);

    let SystemOneAnswer::Score {
        score,
        confidence,
        probabilities,
        legend,
        extra,
    } = &response.answers["priority"]
    else {
        panic!("expected score");
    };
    assert_eq!(*score, 1.0);
    assert_eq!(*confidence, 0.7);
    assert_eq!(probabilities["1"], 0.7);
    assert!(matches!(&legend["1"], SystemOneContent::Text(value) if value == "Urgent"));
    assert_eq!(extra["future"], true);

    let SystemOneAnswer::Box {
        bounds,
        confidence,
        extra,
    } = &response.answers["region"]
    else {
        panic!("expected box");
    };
    let bounds: &SystemOneBoxCoordinates = bounds;
    assert_eq!(
        [bounds.top, bounds.bottom, bounds.left, bounds.right],
        [0.31, 0.69, 0.25, 0.75]
    );
    assert_eq!(*confidence, Some(0.82));
    assert_eq!(bounds.extra["future"], true);
    assert_eq!(extra["future"], true);
}
