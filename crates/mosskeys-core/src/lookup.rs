//! Directory lookup (CONIKS presence/absence) — the client side of #172.
//!
//! Two serving paths, one entry point ([`lookup`]):
//!
//! * **Oblivious (POPRF, RFC 9497)** — the default for new namespaces. The
//!   client blinds the label locally (`metamorphic-crypto`), the server
//!   evaluates the blinded element (never seeing the label), the client
//!   unblinds + verifies the DLEQ proof, derives the 32-byte tree index, and
//!   fetches the presence/absence proof by index, verifying it against the
//!   pinned directory root (`metamorphic-log`). The cleartext label never
//!   leaves the client.
//! * **Legacy (VRF)** — existing namespaces until the owner upgrades. The
//!   server evaluates its VRF over the cleartext label at query time; the
//!   client verifies the returned VRF proof. Honest about the trade-off: the
//!   operator sees the label in memory while answering.
//!
//! This module adds **zero cryptography of its own**: every primitive comes
//! from `metamorphic-crypto` and every proof verification from
//! `metamorphic-log` — the same audited cores the server, the browser WASM
//! SDK, and the native verifiers use.

use base64::Engine as _;
use serde::Deserialize;

use metamorphic_crypto::{PoprfBlindState, poprf_blind, poprf_finalize};
use metamorphic_log::coniks::{
    self, IndexedAbsenceProof, IndexedLookupProof, LookupProof, Namespace,
};
use metamorphic_log::vrf::{Ecvrf, VrfPublicKey};

use crate::client::Client;
use crate::error::{Error, Result, VerifyError};

fn b64_decode(what: &str, s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| Error::Verification(VerifyError::Malformed(format!("{what} is not base64"))))
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The namespace's directory head (`GET /api/:slug/directory-proof`): the
/// public parameter set every lookup proof verifies against.
#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryHead {
    /// The index-derivation scheme this namespace serves (`"vrf"` | `"poprf"`).
    pub index_version: String,
    /// The namespace origin string proofs verify under.
    pub namespace: String,
    /// Base64 of the 64-byte SHA3-512 directory root.
    pub root: String,
    /// The index-derivation suite identifier bound into leaf hashes.
    pub suite_id: u8,
    /// The number of distinct identities in the directory.
    pub entries: u64,
    /// The VRF public key (legacy namespaces).
    pub vrf_public: Option<String>,
    /// The POPRF public key clients blind under (POPRF namespaces).
    pub poprf_public: Option<String>,
    /// The public POPRF `info` metadata (POPRF namespaces).
    pub poprf_info: Option<String>,
}

/// The server's blinded-evaluation response (`POST /api/:slug/oprf/evaluate`).
#[derive(Debug, Clone, Deserialize)]
pub struct OprfEvaluation {
    /// Base64 of the 32-byte evaluated element.
    pub evaluated_element: String,
    /// Base64 of the 64-byte DLEQ proof.
    pub proof: String,
}

/// A by-index lookup response (`GET /api/:slug/lookup/index?index=`).
#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLookup {
    /// `"present"` (with `value`) or `"absent"`.
    pub status: String,
    /// Base64 of the bound value (present only).
    pub value: Option<String>,
    /// Base64 of the canonical index-bound proof.
    pub proof: String,
    /// Base64 of the directory root the proof verifies against.
    pub root: String,
    /// The index-derivation suite identifier.
    pub suite_id: u8,
    /// The number of distinct identities in the directory.
    pub entries: u64,
}

/// A legacy VRF lookup response (`GET /api/:slug/lookup?label=`).
#[derive(Debug, Clone, Deserialize)]
pub struct LabelLookup {
    /// `"present"` (with `value`) or `"absent"`.
    pub status: String,
    /// Base64 of the bound value (present only).
    pub value: Option<String>,
    /// Base64 of the canonical VRF-bound proof.
    pub proof: String,
    /// Base64 of the directory root the proof verifies against.
    pub root: String,
    /// The namespace origin string the proof verifies under.
    pub namespace: String,
    /// The VRF public key the proof verifies under.
    pub vrf_public: String,
    /// The number of distinct identities in the directory.
    pub entries: u64,
}

/// The verified outcome of a [`lookup`]: the label is either **present** with
/// its bound value (the current key-history head's `entry_hash`), or
/// **absent** — proven against the pinned directory root either way.
#[derive(Debug, Clone)]
pub enum LookupOutcome {
    /// The label is bound; carries the base64 value.
    Present {
        /// Base64 of the bound value (the label's current key-history head).
        value: String,
        /// Base64 of the directory root the proof verified against.
        root: String,
        /// The number of distinct identities in the directory.
        entries: u64,
    },
    /// The label is provably unbound.
    Absent {
        /// Base64 of the directory root the proof verified against.
        root: String,
        /// The number of distinct identities in the directory.
        entries: u64,
    },
}

/// Which serving path a lookup took — surfaced so the CLI can report the
/// verification chain honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupPath {
    /// Oblivious POPRF (RFC 9497): blind → evaluate → unblind/verify → by-index.
    Poprf,
    /// Legacy VRF: server-evaluated over the cleartext label at query time.
    Vrf,
}

/// The full result of a [`lookup`]: the verified outcome plus the path taken.
#[derive(Debug, Clone)]
pub struct LookupReport {
    /// The verified presence/absence outcome.
    pub outcome: LookupOutcome,
    /// The serving path (drives which verification steps the CLI lists).
    pub path: LookupPath,
}

/// Look up `label` in the namespace's CONIKS directory, choosing the serving
/// path from the namespace's published directory head and verifying every
/// proof client-side.
///
/// On a POPRF namespace the label never leaves the client. On a legacy VRF
/// namespace the label is sent to the server for evaluation — the response is
/// still fully verified, but the operator sees the label at query time (the
/// reason #172 exists; the CLI says so in its output).
///
/// # Errors
/// Returns a typed [`crate::ApiError`] for transport/API failures,
/// [`VerifyError::Malformed`] for structurally invalid server responses, and
/// [`VerifyError::Directory`] when a proof does not verify.
pub fn lookup(client: &Client, slug: &str, label: &str) -> Result<LookupReport> {
    let head = client.directory_head(slug)?;
    match head.index_version.as_str() {
        "poprf" => lookup_poprf(client, slug, label, &head),
        "vrf" => lookup_vrf(client, slug, label),
        other => Err(Error::Verification(VerifyError::Malformed(format!(
            "unknown index_version {other:?}"
        )))),
    }
}

/// The oblivious POPRF flow (RFC 9497): the label never leaves the client.
fn lookup_poprf(
    client: &Client,
    slug: &str,
    label: &str,
    head: &DirectoryHead,
) -> Result<LookupReport> {
    let malformed = |m: &str| Error::Verification(VerifyError::Malformed(m.to_string()));
    let poprf_public = head
        .poprf_public
        .as_deref()
        .ok_or_else(|| malformed("directory head is missing poprf_public"))?;
    let poprf_info = head
        .poprf_info
        .as_deref()
        .ok_or_else(|| malformed("directory head is missing poprf_info"))?;

    let info = b64_decode("poprf_info", poprf_info)?;
    let pk = b64_decode("poprf_public", poprf_public)?;

    // Step 1: blind locally. Only the blinded element leaves the client. The
    // POPRF input is the raw label bytes (exactly what the server inserted).
    let PoprfBlindState {
        blind,
        blinded_element,
        tweaked_key,
    } = poprf_blind(label.as_bytes(), &info, &pk)
        .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;

    // Step 2: the server evaluates the blinded element (an online, rate-limited
    // oracle — it learns nothing about the label).
    let evaluation = client.oprf_evaluate(slug, &b64_encode(&blinded_element))?;

    // Step 3: unblind + verify the DLEQ proof, then derive the 32-byte index.
    let output = poprf_finalize(
        label.as_bytes(),
        &blind,
        &b64_decode("evaluated element", &evaluation.evaluated_element)?,
        &blinded_element,
        &b64_decode("dleq proof", &evaluation.proof)?,
        &info,
        &tweaked_key,
    )
    .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?
    .ok_or(Error::Verification(VerifyError::Directory))?;
    let index: [u8; 32] = output[..32]
        .try_into()
        .map_err(|_| malformed("poprf output is shorter than 32 bytes"))?;
    let index_b64 = b64_encode(&index);

    // Step 4: fetch + verify the presence/absence proof by index against the
    // pinned head root.
    let result = client.lookup_index(slug, &index_b64)?;
    if result.root != head.root {
        // The directory rotated between the two fetches: a retry signal, not a
        // forgery. Surface as malformed-with-context so the caller retries.
        return Err(malformed("directory root rotated mid-lookup — retry"));
    }
    let root: [u8; 64] = b64_decode("directory root", &result.root)?
        .try_into()
        .map_err(|_| malformed("directory root is not 64 bytes"))?;
    let namespace = Namespace::parse(&head.namespace)
        .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;

    match result.status.as_str() {
        "present" => {
            let proof = IndexedLookupProof::from_bytes(&b64_decode("proof", &result.proof)?)
                .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
            let value =
                coniks::verify_indexed_lookup(&namespace, result.suite_id, &root, &index, &proof)
                    .map_err(|_| Error::Verification(VerifyError::Directory))?;
            Ok(LookupReport {
                outcome: LookupOutcome::Present {
                    value: b64_encode(&value),
                    root: result.root.clone(),
                    entries: result.entries,
                },
                path: LookupPath::Poprf,
            })
        }
        "absent" => {
            let proof = IndexedAbsenceProof::from_bytes(&b64_decode("proof", &result.proof)?)
                .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
            coniks::verify_indexed_absence(&namespace, result.suite_id, &root, &index, &proof)
                .map_err(|_| Error::Verification(VerifyError::Directory))?;
            Ok(LookupReport {
                outcome: LookupOutcome::Absent {
                    root: result.root.clone(),
                    entries: result.entries,
                },
                path: LookupPath::Poprf,
            })
        }
        other => Err(malformed(&format!("unknown lookup status {other:?}"))),
    }
}

/// The legacy VRF flow: the label is sent to the server for evaluation at
/// query time; the returned proof is verified client-side.
fn lookup_vrf(client: &Client, slug: &str, label: &str) -> Result<LookupReport> {
    let malformed = |m: &str| Error::Verification(VerifyError::Malformed(m.to_string()));
    let result = client.lookup_label(slug, label)?;

    let namespace = Namespace::parse(&result.namespace)
        .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
    let vrf_public = VrfPublicKey::from_bytes(b64_decode("vrf_public", &result.vrf_public)?);
    let root: [u8; 64] = b64_decode("directory root", &result.root)?
        .try_into()
        .map_err(|_| malformed("directory root is not 64 bytes"))?;

    match result.status.as_str() {
        "present" => {
            let proof = LookupProof::from_bytes(&b64_decode("proof", &result.proof)?)
                .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
            let value = coniks::verify_lookup(
                &Ecvrf,
                &namespace,
                &vrf_public,
                &root,
                label.as_bytes(),
                &proof,
            )
            .map_err(|_| Error::Verification(VerifyError::Directory))?;
            Ok(LookupReport {
                outcome: LookupOutcome::Present {
                    value: b64_encode(&value),
                    root: result.root.clone(),
                    entries: result.entries,
                },
                path: LookupPath::Vrf,
            })
        }
        "absent" => {
            let proof = coniks::AbsenceProof::from_bytes(&b64_decode("proof", &result.proof)?)
                .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
            coniks::verify_absence(
                &Ecvrf,
                &namespace,
                &vrf_public,
                &root,
                label.as_bytes(),
                &proof,
            )
            .map_err(|_| Error::Verification(VerifyError::Directory))?;
            Ok(LookupReport {
                outcome: LookupOutcome::Absent {
                    root: result.root.clone(),
                    entries: result.entries,
                },
                path: LookupPath::Vrf,
            })
        }
        other => Err(malformed(&format!("unknown lookup status {other:?}"))),
    }
}
