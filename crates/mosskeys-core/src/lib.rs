//! `mosskeys-core` — the zero-knowledge SDK core behind the MossKeys CLI.
//!
//! Three concerns, cleanly separated:
//!
//! * [`config`] — persistent config + credential resolution (env-first).
//! * [`client`] — the blocking write-API client (#60b), with typed errors.
//! * [`signing`] — local BYOK checkpoint signing via the native crypto core.
//!
//! The crate transmits only already-public material and client-signed notes;
//! signing keys are read locally and never logged or sent. It is published as a
//! standalone crate so third parties can build against the same audited surface
//! (the Rust rung of the layered SDK strategy).

// Security posture matching the `metamorphic-crypto` / `metamorphic-log` core:
// no `unsafe` anywhere in the crate, and every public item documented.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod config;
pub mod error;
pub mod signing;

pub use client::{AppendResult, CheckpointMaterial, Client, EntryInput, PublishedCheckpoint};
pub use config::Config;
pub use error::{ApiError, ApiErrorCode, Error, Result};
