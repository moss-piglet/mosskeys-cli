//! Unit coverage for the API error taxonomy + config precedence — the pure
//! logic the CLI relies on to pick exit codes and resolve credentials without a
//! live server.

use mosskeys_core::ApiErrorCode;
use mosskeys_core::config::{Config, DEFAULT_BASE_URL};

#[test]
fn error_codes_map_from_server_strings() {
    assert_eq!(
        ApiErrorCode::parse("unauthorized"),
        ApiErrorCode::Unauthorized
    );
    assert_eq!(ApiErrorCode::parse("forbidden"), ApiErrorCode::Forbidden);
    assert_eq!(ApiErrorCode::parse("not_found"), ApiErrorCode::NotFound);
    assert_eq!(
        ApiErrorCode::parse("head_mismatch"),
        ApiErrorCode::HeadMismatch
    );
    assert_eq!(
        ApiErrorCode::parse("invalid_request"),
        ApiErrorCode::InvalidRequest
    );
    assert_eq!(
        ApiErrorCode::parse("unprocessable"),
        ApiErrorCode::InvalidRequest
    );
    assert_eq!(
        ApiErrorCode::parse("rate_limited"),
        ApiErrorCode::RateLimited
    );
    assert_eq!(
        ApiErrorCode::parse("quota_exceeded"),
        ApiErrorCode::RateLimited
    );
    assert_eq!(ApiErrorCode::parse("something_new"), ApiErrorCode::Unknown);
}

#[test]
fn only_rate_limited_is_retryable() {
    assert!(ApiErrorCode::RateLimited.is_retryable());
    for code in [
        ApiErrorCode::Unauthorized,
        ApiErrorCode::Forbidden,
        ApiErrorCode::NotFound,
        ApiErrorCode::HeadMismatch,
        ApiErrorCode::InvalidRequest,
        ApiErrorCode::Unknown,
    ] {
        assert!(!code.is_retryable(), "{code:?} must be terminal");
    }
}

#[test]
fn base_url_defaults_and_trims() {
    let cfg = Config::default();
    // No env, no config → production default.
    assert_eq!(cfg.effective_base_url(), DEFAULT_BASE_URL);

    let cfg = Config {
        base_url: Some("http://localhost:4001/".into()),
        ..Config::default()
    };
    assert_eq!(cfg.effective_base_url(), "http://localhost:4001");
}
