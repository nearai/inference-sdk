//! The live suites own one retry budget; response consumption is outside it.
use nearai_inference_sdk::{ApiError, ApiResource, InferenceError};
use std::{
    future::Future,
    time::{Duration, SystemTime},
};

pub(super) fn rate_limit_delay(status: u16, retry_after: Option<&str>) -> Option<Duration> {
    (status == 429).then(|| {
        retry_after
            .and_then(|v| retry_after_delay(v, SystemTime::now()))
            .unwrap_or_default()
    })
}

pub(super) fn error_delay(error: &InferenceError) -> Option<Duration> {
    match error {
        InferenceError::Api(ApiError::HttpStatus {
            resource: ApiResource::Ohttp | ApiResource::Completion,
            status,
            retry_after,
        }) => rate_limit_delay(*status, retry_after.as_deref()),
        _ => None,
    }
}

pub(super) async fn retry_rate_limit<T, E, F, Fut, C>(send: F, classify: C) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    C: Fn(&Result<T, E>) -> Option<Duration>,
{
    retry_with_sleep(send, classify, tokio::time::sleep).await
}

async fn retry_with_sleep<T, E, F, Fut, C, S, Wait>(
    mut send: F,
    classify: C,
    mut sleep: S,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    C: Fn(&Result<T, E>) -> Option<Duration>,
    S: FnMut(Duration) -> Wait,
    Wait: Future<Output = ()>,
{
    for backoff in [5, 10, 20] {
        let response = send().await;
        let Some(hint) = classify(&response) else {
            return response;
        };
        let wait = hint.max(Duration::from_secs(backoff));
        drop(response);
        eprintln!("Chat returned HTTP 429; retrying in {wait:?}");
        sleep(wait).await;
    }
    send().await
}

fn retry_after_delay(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    Some(
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or_default(),
    )
}

#[test]
fn retry_after_supports_seconds_dates_and_invalid_values() {
    let date = "Wed, 21 Oct 2015 07:28:00 GMT";
    let time = httpdate::parse_http_date(date).unwrap();
    assert_eq!(retry_after_delay("30", time), Some(Duration::from_secs(30)));
    assert_eq!(
        retry_after_delay(date, time - Duration::from_secs(30)),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        retry_after_delay(date, time + Duration::from_secs(30)),
        Some(Duration::ZERO)
    );
    assert_eq!(retry_after_delay("invalid", time), None);
}

#[tokio::test]
async fn oversized_retry_after_waits_until_the_case_deadline() {
    let header = "9".repeat(400);
    assert!(retry_after_delay(&header, SystemTime::now()).unwrap() > Duration::from_secs(180));
    let calls = std::cell::Cell::new(0);
    let pending = retry_rate_limit(
        || {
            calls.set(calls.get() + 1);
            std::future::ready(Ok::<_, ()>(429_u16))
        },
        |response| rate_limit_delay(*response.as_ref().unwrap(), Some(&header)),
    );
    assert!(tokio::time::timeout(Duration::from_millis(10), pending)
        .await
        .is_err());
    assert_eq!(calls.get(), 1);
}

#[test]
fn only_completion_and_ohttp_429_errors_are_retried() {
    for resource in [
        ApiResource::Completion,
        ApiResource::Ohttp,
        ApiResource::GatewayAttestation,
    ] {
        for status in [429, 503] {
            let error = ApiError::HttpStatus {
                resource,
                status,
                retry_after: Some("12".into()),
            }
            .into();
            let expected = if status == 429 && !matches!(resource, ApiResource::GatewayAttestation)
            {
                Some(Duration::from_secs(12))
            } else {
                None
            };
            assert_eq!(error_delay(&error), expected);
        }
    }
}

#[tokio::test]
async fn bounded_retry_budget_and_success_are_not_replayed() {
    use std::cell::{Cell, RefCell};
    for statuses in [
        vec![429, 429, 429, 429],
        vec![429, 200],
        vec![503],
        vec![200],
    ] {
        let calls = Cell::new(0);
        let waits = RefCell::new(vec![]);
        let result: Result<u16, ()> = retry_with_sleep(
            || {
                let index = calls.get();
                calls.set(index + 1);
                std::future::ready(Ok(statuses[index]))
            },
            |result| rate_limit_delay(*result.as_ref().unwrap(), Some("12")),
            |wait| {
                waits.borrow_mut().push(wait.as_secs());
                std::future::ready(())
            },
        )
        .await;
        assert_eq!(result, Ok(*statuses.last().unwrap()));
        assert_eq!(calls.get(), statuses.len());
        assert_eq!(*waits.borrow(), [12, 12, 20][..statuses.len() - 1]);
    }
}
