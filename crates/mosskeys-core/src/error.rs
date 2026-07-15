//! Typed errors for the MossKeys write API + local signing.
//!
//! The server speaks a single JSON envelope on failure:
//!
//! ```json
//! {"error": {"code": "head_mismatch", "message": "…"}}
//! ```
//!
//! We map those `code`s (and their HTTP statuses) to a closed enum so the CLI
//! can render a precise message and pick a stable process exit code. Anything
//! we do not recognise is preserved verbatim under [`ApiError::Other`] so a
//! future server code never degrades to an opaque failure.

use std::fmt;

/// The result type used throughout the core crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A top-level failure: a transport/local problem, or a structured API error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Network / TLS / timeout — the request never produced an API envelope.
    #[error("network error: {0}")]
    Transport(String),

    /// The server replied, but not with the JSON envelope we expected.
    #[error("unexpected response (HTTP {status}): {body}")]
    Malformed {
        /// The HTTP status code of the unexpected response.
        status: u16,
        /// The raw response body (truncated by the caller if needed).
        body: String,
    },

    /// A structured, server-reported API error (the JSON envelope).
    #[error("{0}")]
    Api(#[from] ApiError),

    /// Configuration / credential problem detected locally (before any request).
    #[error("configuration error: {0}")]
    Config(String),

    /// Local BYOK signing failed (bad key, malformed material).
    #[error("signing error: {0}")]
    Signing(String),

    /// Local key generation failed (an unsupported suite/level combination).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Local IO (reading a key file, config, stdin).
    #[error("io error: {0}")]
    Io(String),
}

/// The recognised `error.code` values from the #60b contract, with the HTTP
/// status that carries them. Ordering here mirrors the server documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    /// 401 — missing/invalid bearer token.
    Unauthorized,
    /// 403 — token lacks the capability, namespace scope, or plan.
    Forbidden,
    /// 404 — unknown slug, or a namespace owned by someone else.
    NotFound,
    /// 409 — a signed checkpoint no longer commits to the server's head.
    HeadMismatch,
    /// 422 — the request body was malformed or failed validation.
    InvalidRequest,
    /// 429 — per-token rate limit or per-account monthly quota exhausted.
    RateLimited,
    /// A server code we do not (yet) model.
    Unknown,
}

impl ApiErrorCode {
    /// Parse a server `error.code` string.
    #[must_use]
    pub fn parse(code: &str) -> Self {
        match code {
            "unauthorized" => Self::Unauthorized,
            "forbidden" => Self::Forbidden,
            "not_found" => Self::NotFound,
            "head_mismatch" => Self::HeadMismatch,
            "invalid_request" | "unprocessable" => Self::InvalidRequest,
            "rate_limited" | "quota_exceeded" => Self::RateLimited,
            _ => Self::Unknown,
        }
    }

    /// Whether retrying the identical request could plausibly succeed later.
    /// Drives the `sync` daemon's backoff decision: transient (`true`) vs.
    /// terminal (`false`, e.g. a 422 that will always be rejected).
    #[must_use]
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::RateLimited)
    }
}

/// A structured API error carrying the raw wire fields plus the parsed code.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP status that carried the envelope.
    pub status: u16,
    /// The parsed, closed-enum classification.
    pub code: ApiErrorCode,
    /// The raw `error.code` string (preserved even when `Unknown`).
    pub raw_code: String,
    /// The human-readable `error.message`.
    pub message: String,
    /// `Retry-After` seconds, when the server supplied one (429s).
    pub retry_after_secs: Option<u64>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.raw_code, self.status, self.message)
    }
}

impl std::error::Error for ApiError {}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Transport(e.to_string())
    }
}
