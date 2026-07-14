//! Blocking HTTP client for the owner-scoped MossKeys write API (#60b).
//!
//! One [`Client`] wraps a base URL + bearer token and exposes exactly the three
//! write operations the CLI needs, plus the checkpoint two-phase split. Every
//! non-2xx response is decoded through the shared `{"error":{code,message}}`
//! envelope into a typed [`ApiError`]; `Retry-After` is surfaced so `sync` can
//! honour the server's backoff.
//!
//! A blocking client keeps the daemon loop trivial (sleep + retry) and the
//! binary small — no async runtime in the graph.

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiErrorCode, Error, Result};

/// A configured API client bound to one base URL + token.
pub struct Client {
    http: reqwest::blocking::Client,
    base_url: String,
    token: String,
}

/// Public append material — exactly the fields the server accepts. Produced by
/// the operator's SDK/keygen; the CLI only transmits already-public data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryInput {
    /// Human-readable label for the entry.
    pub label: String,
    /// Public X25519 encryption key (base64).
    pub enc_x25519: String,
    /// Public post-quantum (ML-KEM) encryption key (base64).
    pub enc_pq: String,
    /// Public signing key (base64).
    pub signing_pub: String,
    /// Optional client timestamp (ms since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_ms: Option<i64>,
}

/// The server's response to a successful append (200; idempotent on retry).
#[derive(Debug, Clone, Deserialize)]
pub struct AppendResult {
    /// The stable leaf index (unchanged across idempotent retries).
    pub index: u64,
    /// The tree size after the append.
    pub size: u64,
    /// Base64 of the RFC 6962 root at `size`.
    pub root: String,
}

/// Phase-1 checkpoint material: the canonical head to sign OFFLINE.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckpointMaterial {
    /// The C2SP log origin.
    pub origin: String,
    /// The C2SP key name (used as the signature line name).
    pub name: String,
    /// The tree size the checkpoint commits to.
    pub size: u64,
    /// Base64 of the 32-byte RFC 6962 root at `size`.
    pub root: String,
}

/// Phase-2 result: the persisted, server-verified checkpoint (201).
#[derive(Debug, Clone, Deserialize)]
pub struct PublishedCheckpoint {
    /// The C2SP log origin.
    pub origin: String,
    /// The tree size the checkpoint commits to.
    pub size: u64,
    /// Base64 of the committed root.
    pub root: String,
    /// The published C2SP signed-note text.
    pub note: String,
}

impl Client {
    /// Build a client. `base_url` must not have a trailing slash.
    ///
    /// # Errors
    /// Fails if the underlying HTTP client cannot be constructed.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("mosskeys-cli/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.into(),
            token: token.into(),
        })
    }

    /// `POST /api/:slug/log/entries` — append one leaf (idempotent).
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx, or a transport error.
    pub fn append_entry(&self, slug: &str, entry: &EntryInput) -> Result<AppendResult> {
        let url = format!("{}/api/{slug}/log/entries", self.base_url);
        let resp = self.authed(self.http.post(url)).json(entry).send()?;
        decode(resp)
    }

    /// `POST /api/:slug/log/checkpoints` with no `note_text` — Phase 1: fetch the
    /// canonical head to sign offline.
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx, or a transport error.
    pub fn checkpoint_material(&self, slug: &str) -> Result<CheckpointMaterial> {
        let url = format!("{}/api/{slug}/log/checkpoints", self.base_url);
        let resp = self
            .authed(self.http.post(url))
            .json(&serde_json::json!({}))
            .send()?;
        decode(resp)
    }

    /// `POST /api/:slug/log/checkpoints` with `note_text` — Phase 2: publish the
    /// locally-signed C2SP note (server verifies + asserts head-match, 201).
    ///
    /// # Errors
    /// Returns [`ApiErrorCode::HeadMismatch`] (409) when the signed head no
    /// longer matches the server, or another typed [`ApiError`].
    pub fn publish_checkpoint(&self, slug: &str, note_text: &str) -> Result<PublishedCheckpoint> {
        let url = format!("{}/api/{slug}/log/checkpoints", self.base_url);
        let resp = self
            .authed(self.http.post(url))
            .json(&serde_json::json!({ "note_text": note_text }))
            .send()?;
        decode(resp)
    }

    fn authed(&self, rb: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        rb.bearer_auth(&self.token)
    }
}

/// The server's error envelope (the documented shape).
#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// The alternate shape emitted by the `:api_auth` plug on 401
/// (`{"error": "unauthorized"}`) and, defensively, by intermediaries.
#[derive(Deserialize)]
struct ErrorString {
    error: String,
}

/// Decode a response into `T` on 2xx, else a typed [`ApiError`].
///
/// Error decoding is intentionally lenient about the envelope shape: it accepts
/// the documented `{"error":{code,message}}`, the plug's `{"error":"code"}`
/// string form, and finally falls back to classifying by HTTP status. This
/// keeps exit-code mapping correct even when a proxy or an inconsistent
/// endpoint returns a non-canonical body.
fn decode<T: serde::de::DeserializeOwned>(resp: reqwest::blocking::Response) -> Result<T> {
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    let code = status.as_u16();
    let body = resp
        .text()
        .map_err(|e| Error::Transport(format!("reading response body: {e}")))?;

    if status.is_success() {
        return serde_json::from_str::<T>(&body)
            .map_err(|_| Error::Malformed { status: code, body });
    }

    let (raw_code, message) = if let Ok(env) = serde_json::from_str::<ErrorEnvelope>(&body) {
        (env.error.code, env.error.message)
    } else if let Ok(s) = serde_json::from_str::<ErrorString>(&body) {
        let msg = default_message_for(code);
        (s.error, msg)
    } else if let Some(raw) = raw_code_for_status(code) {
        (raw.to_string(), default_message_for(code))
    } else {
        return Err(Error::Malformed { status: code, body });
    };

    Err(Error::Api(ApiError {
        status: code,
        code: ApiErrorCode::parse(&raw_code),
        raw_code,
        message,
        retry_after_secs: retry_after,
    }))
}

/// Infer a canonical `error.code` from an HTTP status when the body carries no
/// usable code (defensive fallback).
fn raw_code_for_status(status: u16) -> Option<&'static str> {
    match status {
        401 => Some("unauthorized"),
        403 => Some("forbidden"),
        404 => Some("not_found"),
        409 => Some("head_mismatch"),
        422 => Some("invalid_request"),
        429 => Some("rate_limited"),
        _ => None,
    }
}

fn default_message_for(status: u16) -> String {
    match status {
        401 => "Unauthorized — check your API token.",
        403 => "Forbidden — the token lacks the required capability, scope, or plan.",
        404 => "Not found.",
        409 => "The signed checkpoint no longer matches the log's current head.",
        422 => "The request was rejected as invalid.",
        429 => "Rate limit or quota exceeded.",
        _ => "Request failed.",
    }
    .to_string()
}
