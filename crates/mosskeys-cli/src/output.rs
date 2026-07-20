//! Output + process exit-code mapping.
//!
//! Two output modes share one call site:
//!   * human — brand-themed, glyph-prefixed lines on stderr for status and
//!     stdout for primary results;
//!   * `--json` — a single machine-readable JSON object on stdout, nothing else,
//!     so agents/scripts can parse results and errors uniformly.
//!
//! Exit codes are stable and map the #60b error taxonomy so shell/CI callers
//! can branch without parsing text.

use mosskeys_core::{ApiErrorCode, Error, VerifyError};

use crate::theme::Theme;

/// Stable process exit codes.
pub mod exit {
    pub const OK: i32 = 0;
    pub const GENERIC: i32 = 1;
    // 2 is reserved for clap usage errors.
    pub const CONFIG: i32 = 3;
    pub const UNAUTHORIZED: i32 = 4;
    pub const FORBIDDEN: i32 = 5;
    pub const NOT_FOUND: i32 = 6;
    pub const HEAD_MISMATCH: i32 = 7;
    pub const INVALID_REQUEST: i32 = 8;
    pub const RATE_LIMITED: i32 = 9;
    pub const SIGNING: i32 = 10;
    pub const TRANSPORT: i32 = 11;
    /// A verification check failed (bad inclusion proof, forged co-signature,
    /// unanchored entry, or digest mismatch). Consistency failures map to
    /// [`HEAD_MISMATCH`] instead, since a failed consistency proof *is* a
    /// rewritten head.
    pub const VERIFICATION: i32 = 12;
}

/// The exit code for a given error, mapping the API taxonomy.
#[must_use]
pub fn exit_code(err: &Error) -> i32 {
    match err {
        Error::Api(api) => match api.code {
            ApiErrorCode::Unauthorized => exit::UNAUTHORIZED,
            ApiErrorCode::Forbidden => exit::FORBIDDEN,
            ApiErrorCode::NotFound => exit::NOT_FOUND,
            ApiErrorCode::HeadMismatch => exit::HEAD_MISMATCH,
            ApiErrorCode::InvalidRequest => exit::INVALID_REQUEST,
            ApiErrorCode::RateLimited => exit::RATE_LIMITED,
            ApiErrorCode::Unknown => exit::GENERIC,
        },
        Error::Config(_) => exit::CONFIG,
        Error::Signing(_) => exit::SIGNING,
        Error::Transport(_) => exit::TRANSPORT,
        // A failed consistency proof means the log head was rewritten — the
        // same class of failure as the write path's 409, so it shares the code.
        Error::Verification(VerifyError::Consistency) => exit::HEAD_MISMATCH,
        Error::Verification(VerifyError::Malformed(_)) => exit::GENERIC,
        Error::Verification(_) => exit::VERIFICATION,
        Error::Crypto(_) | Error::Malformed { .. } | Error::Io(_) => exit::GENERIC,
    }
}

/// A reporter bound to an output mode + theme.
#[derive(Clone, Copy)]
pub struct Reporter {
    pub json: bool,
    pub theme: Theme,
}

impl Reporter {
    #[must_use]
    pub fn new(json: bool) -> Self {
        Reporter {
            json,
            theme: Theme::resolve(json),
        }
    }

    /// Print the brand banner once (human mode only, on stderr). Skipped in
    /// JSON mode and when colour is disabled to keep pipes/CI clean.
    pub fn banner(self) {
        if !self.json && self.theme.color_enabled() {
            eprintln!("{}", self.theme.banner());
        }
    }

    /// A status/progress line (human mode only, on stderr so stdout stays clean
    /// for piped results).
    pub fn status(self, line: &str) {
        if !self.json {
            eprintln!("{line}");
        }
    }

    /// A success status line.
    pub fn success(self, line: &str) {
        self.status(&self.theme.success(line));
    }

    /// Emit the primary result. In JSON mode prints the value as one line on
    /// stdout; in human mode invokes `human` to render themed output.
    pub fn result(self, value: &serde_json::Value, human: impl FnOnce(Theme)) {
        if self.json {
            println!("{value}");
        } else {
            human(self.theme);
        }
    }

    /// Render a terminal error to stderr (human) or stdout (JSON envelope).
    pub fn report_error(self, err: &Error) {
        if self.json {
            let obj = error_json(err);
            println!("{obj}");
        } else {
            eprintln!("{}", self.theme.error(&err.to_string()));
            if let Error::Api(api) = err {
                if let Some(secs) = api.retry_after_secs {
                    eprintln!("{}", self.theme.dim(&format!("  retry after {secs}s")));
                }
            }
        }
    }
}

/// The JSON error envelope emitted in `--json` mode (mirrors the server shape).
fn error_json(err: &Error) -> serde_json::Value {
    match err {
        Error::Api(api) => serde_json::json!({
            "ok": false,
            "error": {
                "code": api.raw_code,
                "message": api.message,
                "status": api.status,
                "retry_after_secs": api.retry_after_secs,
            }
        }),
        Error::Verification(v) => serde_json::json!({
            "ok": false,
            "error": { "code": verify_code(v), "message": v.to_string() }
        }),
        other => serde_json::json!({
            "ok": false,
            "error": { "code": "client_error", "message": other.to_string() }
        }),
    }
}

/// Stable machine code for a verification failure (mirrors the exit taxonomy).
fn verify_code(v: &VerifyError) -> &'static str {
    match v {
        VerifyError::Inclusion => "inclusion_failed",
        VerifyError::Consistency => "head_mismatch",
        VerifyError::WitnessCosig => "cosignature_failed",
        VerifyError::NotAnchored => "not_anchored",
        VerifyError::DigestMismatch => "digest_mismatch",
        VerifyError::Malformed(_) => "malformed_input",
    }
}
