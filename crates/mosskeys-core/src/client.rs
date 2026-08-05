//! Blocking HTTP client for a namespace's MossKeys log API.
//!
//! Two surfaces share one [`Client`]:
//!
//! * the owner-scoped **write** API (#60b) — [`Client::new`] with a bearer
//!   token, exposing `append_entry`, the checkpoint two-phase split, etc.;
//! * the public, unauthenticated **read/serve** API (#42/#98) — [`Client::new_read`]
//!   with NO token, exposing the verifier-facing GETs (`latest_checkpoint`,
//!   `label_head`, `inclusion`, `consistency`, `reconcile`).
//!
//! The read methods NEVER attach an `Authorization` header: public logs verify
//! with no credential, so `verify` must not present (or require) a write token.
//! Every non-2xx response is decoded through the shared
//! `{"error":{code,message}}` envelope into a typed [`ApiError`]; `Retry-After`
//! is surfaced so `sync` can honour the server's backoff.
//!
//! A blocking client keeps the daemon loop trivial (sleep + retry) and the
//! binary small — no async runtime in the graph.

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiErrorCode, Error, Result};

/// A configured API client bound to one base URL, optionally carrying a bearer
/// token for the write surface. Read methods ignore the token entirely.
pub struct Client {
    http: reqwest::blocking::Client,
    base_url: String,
    token: Option<String>,
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

/// A latest-checkpoint response (`GET /api/:slug/checkpoint`), and the shape
/// echoed inside a [`LabelHead`] / [`ReconcileBundle`].
#[derive(Debug, Clone, Deserialize)]
pub struct LatestCheckpoint {
    /// The C2SP log origin.
    pub origin: String,
    /// The tree size the checkpoint commits to.
    pub size: u64,
    /// Base64 of the 32-byte RFC 6962 root at `size`.
    pub root: String,
    /// The full C2SP signed-note text (body + signature lines).
    pub note: String,
}

/// An RFC 6962 inclusion proof (`GET /api/:slug/log/proof/inclusion`), also
/// bundled inside a [`LabelHead`] when the head entry is anchored.
#[derive(Debug, Clone, Deserialize)]
pub struct InclusionProof {
    /// The leaf index the proof is for.
    pub index: u64,
    /// The tree size the proof is against (a checkpoint's `size`).
    pub size: u64,
    /// Base64 of the leaf hash at `index`.
    pub leaf_hash: String,
    /// The base64 audit-path node hashes.
    pub proof: Vec<String>,
}

/// An RFC 6962 consistency proof (`GET /api/:slug/log/proof/consistency`).
#[derive(Debug, Clone, Deserialize)]
pub struct ConsistencyProof {
    /// The smaller (pinned) tree size.
    pub from: u64,
    /// The larger (current) tree size.
    pub to: u64,
    /// The base64 consistency-path node hashes.
    pub proof: Vec<String>,
}

/// A label-head response (`GET /api/:slug/log/label/:label`): the newest entry
/// for an exact label plus, when anchored, the checkpoint + inclusion proof.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelHead {
    /// The leaf index of the label's newest entry.
    pub index: u64,
    /// The exact label this entry is bound to.
    pub label: String,
    /// Base64 of the canonical leaf bytes.
    pub leaf: String,
    /// Base64 of the leaf hash.
    pub leaf_hash: String,
    /// Base64 of the entry hash (the key-history chain link).
    pub entry_hash: String,
    /// Base64 of the previous entry hash, or `None` for the chain head's first
    /// version.
    pub prev_entry_hash: Option<String>,
    /// The current tree size.
    pub tree_size: u64,
    /// The latest signed checkpoint, or `None` when the namespace has none yet.
    pub checkpoint: Option<LatestCheckpoint>,
    /// An inclusion proof for this entry against `checkpoint`, or `None` when
    /// the entry is newer than the latest checkpoint (not yet anchored).
    pub inclusion_proof: Option<InclusionProof>,
}

/// A one-shot reconcile bundle (`GET /api/:slug/log/reconcile?since=`): the
/// current signed checkpoint plus the consistency proof from the pinned size.
#[derive(Debug, Clone, Deserialize)]
pub struct ReconcileBundle {
    /// The current signed checkpoint (the head to re-pin).
    pub checkpoint: LatestCheckpoint,
    /// The consistency proof from the pinned `since` size to the head.
    pub consistency_proof: ConsistencyProof,
}

impl Client {
    /// Build an **authenticated** client for the write surface. `base_url` must
    /// not have a trailing slash.
    ///
    /// # Errors
    /// Fails if the underlying HTTP client cannot be constructed.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: Self::http()?,
            base_url: base_url.into(),
            token: Some(token.into()),
        })
    }

    /// Build a **read-only, public** client for the verifier-facing read API.
    /// It carries NO bearer token; every read method hits the unauthenticated
    /// `LogController` surface. `base_url` must not have a trailing slash.
    ///
    /// # Errors
    /// Fails if the underlying HTTP client cannot be constructed.
    pub fn new_read(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: Self::http()?,
            base_url: base_url.into(),
            token: None,
        })
    }

    fn http() -> Result<reqwest::blocking::Client> {
        Ok(reqwest::blocking::Client::builder()
            .user_agent(concat!("mosskeys-cli/", env!("CARGO_PKG_VERSION")))
            .build()?)
    }

    /// `POST /api/:slug/log/entries` — append one leaf (idempotent).
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx, or a transport error.
    pub fn append_entry(&self, slug: &str, entry: &EntryInput) -> Result<AppendResult> {
        let url = format!("{}/api/{slug}/log/entries", self.base_url);
        let resp = self.authed(self.http.post(url))?.json(entry).send()?;
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
            .authed(self.http.post(url))?
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
            .authed(self.http.post(url))?
            .json(&serde_json::json!({ "note_text": note_text }))
            .send()?;
        decode(resp)
    }

    // ---- Read surface (public, no bearer) -----------------------------------

    /// `GET /api/:slug/checkpoint` — the latest client-signed checkpoint (STH).
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx (e.g. 404 when the namespace
    /// has no checkpoint yet), or a transport error.
    pub fn latest_checkpoint(&self, slug: &str) -> Result<LatestCheckpoint> {
        let url = format!("{}/api/{slug}/checkpoint", self.base_url);
        decode(self.http.get(url).send()?)
    }

    /// `GET /api/:slug/log/label/:label` — the newest entry for an exact label,
    /// plus (when anchored) an inclusion proof against the latest checkpoint.
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx (404 when the label is
    /// unknown), or a transport error.
    pub fn label_head(&self, slug: &str, label: &str) -> Result<LabelHead> {
        // Build the URL through `Url` so the label path segment is
        // percent-encoded (labels routinely contain `@`, `.`, `:` etc.).
        let mut url = reqwest::Url::parse(&format!(
            "{}/api/{slug}/log/label/placeholder",
            self.base_url
        ))
        .map_err(|e| Error::Config(format!("invalid base URL: {e}")))?;
        url.path_segments_mut()
            .map_err(|()| Error::Config("base URL cannot be a base".into()))?
            .pop()
            .push(label);
        decode(self.http.get(url).send()?)
    }

    /// `GET /api/:slug/log/proof/inclusion?index=&size=` — inclusion proof.
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx, or a transport error.
    pub fn inclusion(&self, slug: &str, index: u64, size: u64) -> Result<InclusionProof> {
        let url = format!(
            "{}/api/{slug}/log/proof/inclusion?index={index}&size={size}",
            self.base_url
        );
        decode(self.http.get(url).send()?)
    }

    /// `GET /api/:slug/log/proof/consistency?from=&to=` — consistency proof.
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx, or a transport error.
    pub fn consistency(&self, slug: &str, from: u64, to: u64) -> Result<ConsistencyProof> {
        let url = format!(
            "{}/api/{slug}/log/proof/consistency?from={from}&to={to}",
            self.base_url
        );
        decode(self.http.get(url).send()?)
    }

    /// `GET /api/:slug/log/reconcile?since=<size>` — one-shot reconcile bundle:
    /// the latest signed checkpoint plus the consistency proof from the client's
    /// pinned `since` size to that checkpoint's head.
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx (404 when there is no
    /// checkpoint, 400 when `since` is beyond the head), or a transport error.
    pub fn reconcile(&self, slug: &str, since: u64) -> Result<ReconcileBundle> {
        let url = format!("{}/api/{slug}/log/reconcile?since={since}", self.base_url);
        decode(self.http.get(url).send()?)
    }

    // ---- Directory lookup surface (public, no bearer) ------------------------

    /// `GET /api/:slug/directory-proof` — the directory head: the public
    /// parameter set every CONIKS lookup proof verifies against.
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx, or a transport error.
    pub fn directory_head(&self, slug: &str) -> Result<crate::lookup::DirectoryHead> {
        let url = format!("{}/api/{slug}/directory-proof", self.base_url);
        decode(self.http.get(url).send()?)
    }

    /// `POST /api/:slug/oprf/evaluate` — the POPRF blinded evaluation (RFC 9497
    /// step 1). Public and rate-limited server-side; the blinded element
    /// reveals nothing about the label.
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx (400 on a non-POPRF
    /// namespace or a malformed element), or a transport error.
    pub fn oprf_evaluate(
        &self,
        slug: &str,
        blinded_element_b64: &str,
    ) -> Result<crate::lookup::OprfEvaluation> {
        let url = format!("{}/api/{slug}/oprf/evaluate", self.base_url);
        let resp = self
            .http
            .post(url)
            .json(&serde_json::json!({ "blinded_element": blinded_element_b64 }))
            .send()?;
        decode(resp)
    }

    /// `GET /api/:slug/lookup/index?index=` — the by-index presence/absence
    /// proof (RFC 9497 step 2).
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx (400 on a malformed index),
    /// or a transport error.
    pub fn lookup_index(
        &self,
        slug: &str,
        index_b64: &str,
    ) -> Result<crate::lookup::IndexedLookup> {
        let mut url = reqwest::Url::parse(&format!("{}/api/{slug}/lookup/index", self.base_url))
            .map_err(|e| Error::Config(format!("invalid base URL: {e}")))?;
        url.query_pairs_mut().append_pair("index", index_b64);
        decode(self.http.get(url).send()?)
    }

    /// `GET /api/:slug/lookup?label=` — the legacy VRF-blinded lookup (legacy
    /// namespaces; the label is sent to the server for evaluation).
    ///
    /// # Errors
    /// Returns a typed [`ApiError`] for any non-2xx (400 on a POPRF namespace,
    /// which refuses cleartext lookups), or a transport error.
    pub fn lookup_label(&self, slug: &str, label: &str) -> Result<crate::lookup::LabelLookup> {
        let mut url = reqwest::Url::parse(&format!("{}/api/{slug}/lookup", self.base_url))
            .map_err(|e| Error::Config(format!("invalid base URL: {e}")))?;
        url.query_pairs_mut().append_pair("label", label);
        decode(self.http.get(url).send()?)
    }

    /// Attach the bearer token to a write request, or fail if this is a
    /// read-only client (a programmer error — read methods never call this).
    fn authed(
        &self,
        rb: reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        match &self.token {
            Some(token) => Ok(rb.bearer_auth(token)),
            None => Err(Error::Config(
                "this operation requires an authenticated client".into(),
            )),
        }
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
