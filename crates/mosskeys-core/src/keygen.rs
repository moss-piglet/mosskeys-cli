//! Local, offline generation of the `mosslet/key-history/v1` published-identity
//! key set (the customer-facing BYOK keygen surface).
//!
//! This is the Rust rung of the single audited keygen path. The browser (WASM,
//! board #77) and the operator Mix task (`mix mosskeys.keygen`, board #78) call
//! the SAME `metamorphic-crypto` core; this module calls it natively. All three
//! therefore emit byte-for-byte interoperable artifacts and the frozen leaf
//! schema stays identical.
//!
//! A published log identity carries THREE public keys:
//!
//!   * `enc_x25519`  — classical X25519 KEM public half (`generate_keypair`).
//!   * `enc_pq`      — post-quantum hybrid KEM public half whose PQ strength
//!     tracks the level (`generate_hybrid_keypair_suite`).
//!   * `signing_pub` — HYBRID ML-DSA + Ed25519 composite
//!     (`generate_signing_keypair_suite`).
//!
//! ## Crypto review (#77/#78, frozen)
//! The crypto core exposes no *standalone* ML-KEM keygen, so `enc_pq` uses the
//! suite-parameterised hybrid KEM at [`Suite::Hybrid`], whose PQ parameter set
//! tracks the level (cat3 → ML-KEM-768, cat5 → ML-KEM-1024). The browser and
//! Mix reference impls take this same path, so the base64 halves are
//! byte-identical and the log treats all three as opaque bytes.
//!
//! ## Zero-knowledge / secret hygiene
//! The PRIVATE halves are written to an operator-controlled file (mode `0600`,
//! refusing to overwrite). Only the PUBLIC halves are ever printed. Nothing is
//! sent to the server and no private material is ever logged.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use metamorphic_crypto::{
    SecurityLevel as CryptoKemLevel, SignatureLevel as CryptoSigLevel, Suite, generate_keypair,
    hybrid::generate_hybrid_keypair_suite, sign::generate_signing_keypair_suite,
};
use serde::Serialize;

use crate::error::{Error, Result};

/// The internal wire tag for the leaf format. NOT a product name — it is the
/// versioned `<namespace>/<record-type>/v<N>` label the transparency log binds
/// into the content hash, shared verbatim across the browser and Mix impls.
pub const LEAF_FORMAT: &str = "mosslet/key-history/v1";

/// The NIST security posture for a generated key set. Mirrors the namespace
/// policy `security_level` and drives both the KEM and signature parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Category 3: ML-KEM-768 / ML-DSA-65 (~AES-192).
    Cat3,
    /// Category 5: ML-KEM-1024 / ML-DSA-87 (~AES-256).
    Cat5,
}

impl SecurityLevel {
    /// Parse a `cat3` / `cat5` string (case-insensitive).
    ///
    /// # Errors
    /// Returns [`Error::Config`] for any other value.
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cat3" => Ok(Self::Cat3),
            "cat5" => Ok(Self::Cat5),
            other => Err(Error::Config(format!(
                "invalid security level {other:?}; expected one of: cat3, cat5"
            ))),
        }
    }

    /// The canonical lowercase string (`"cat3"` / `"cat5"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cat3 => "cat3",
            Self::Cat5 => "cat5",
        }
    }

    fn kem_level(self) -> CryptoKemLevel {
        match self {
            Self::Cat3 => CryptoKemLevel::Cat3,
            Self::Cat5 => CryptoKemLevel::Cat5,
        }
    }

    fn sig_level(self) -> CryptoSigLevel {
        match self {
            Self::Cat3 => CryptoSigLevel::Cat3,
            Self::Cat5 => CryptoSigLevel::Cat5,
        }
    }
}

/// A public-or-private key triple (base64). Field order is part of the frozen
/// artifact schema and must not be reordered.
#[derive(Debug, Clone, Serialize)]
pub struct KeyTriple {
    /// X25519 encryption key (base64).
    pub enc_x25519: String,
    /// Hybrid PQ (ML-KEM) encryption key (base64).
    pub enc_pq: String,
    /// Hybrid signing key (ML-DSA + Ed25519 composite; base64).
    pub signing_pub: String,
}

/// The generated key set: public halves (safe to publish) and private halves
/// (written locally, never transmitted).
#[derive(Debug, Clone)]
pub struct KeySet {
    /// Public halves — base64, safe to publish.
    pub public: KeyTriple,
    /// Private halves — base64, NEVER sent anywhere.
    pub private: KeyTriple,
}

/// Namespace metadata recorded in the artifact. All fields are optional because
/// the CLI cannot read the SaaS DB; they are operator-supplied.
#[derive(Debug, Clone, Serialize)]
pub struct NamespaceMeta {
    /// Namespace slug, if known.
    pub slug: Option<String>,
    /// Namespace UUID, if the operator supplied one.
    pub id: Option<String>,
    /// Derived public host (`<slug>.mosskeys.com`), if `slug` is present.
    pub host: Option<String>,
}

impl NamespaceMeta {
    /// Build metadata from an optional slug + optional id, deriving `host`.
    #[must_use]
    pub fn new(slug: Option<String>, id: Option<String>) -> Self {
        let host = slug.as_ref().map(|s| format!("{s}.mosskeys.com"));
        Self { slug, id, host }
    }
}

/// The frozen `mosslet/key-history/v1` artifact. Serialized field order is the
/// wire schema shared byte-for-byte with #77 (browser) and #78 (Mix task).
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    /// Always `"mosskeys"`.
    pub product: &'static str,
    /// Human-readable provenance note.
    pub description: String,
    /// Namespace metadata (may hold nulls).
    pub namespace: NamespaceMeta,
    /// Subject / key-id for this identity.
    pub label: String,
    /// `"cat3"` | `"cat5"`.
    pub security_level: String,
    /// ISO-8601 UTC generation timestamp.
    pub generated_at: String,
    /// Loud reminder that the private halves are unrecoverable.
    pub warning: String,
    /// Public halves — safe to publish.
    pub public_keys: KeyTriple,
    /// Private halves — keep local; never sent.
    pub private_keys: KeyTriple,
    /// Internal wire tag ([`LEAF_FORMAT`]).
    pub leaf_format: &'static str,
}

/// Generate the key set via the audited native crypto core.
///
/// Mirrors `generateKeyHistoryKeySet` (#77) and `mix mosskeys.keygen` (#78):
/// `enc_x25519` = X25519 keypair, `enc_pq` = [`Suite::Hybrid`] KEM at the level,
/// `signing_pub` = [`Suite::Hybrid`] signing suite at the level.
///
/// # Errors
/// Returns [`Error::Crypto`] only for unsupported suite/level combinations
/// (never for `Suite::Hybrid`, which supports every level).
pub fn generate_key_set(level: SecurityLevel) -> Result<KeySet> {
    let x = generate_keypair();
    let pq = generate_hybrid_keypair_suite(Suite::Hybrid, level.kem_level())
        .map_err(|e| Error::Crypto(format!("hybrid KEM keygen: {e}")))?;
    let sig = generate_signing_keypair_suite(Suite::Hybrid, level.sig_level())
        .map_err(|e| Error::Crypto(format!("hybrid signing keygen: {e}")))?;

    Ok(KeySet {
        public: KeyTriple {
            enc_x25519: x.public_key,
            enc_pq: pq.public_key,
            signing_pub: sig.public_key.clone(),
        },
        private: KeyTriple {
            enc_x25519: x.private_key,
            enc_pq: pq.secret_key,
            signing_pub: sig.secret_key.clone(),
        },
    })
}

/// Assemble the frozen artifact from a key set + metadata.
#[must_use]
pub fn build_artifact(
    key_set: KeySet,
    level: SecurityLevel,
    label: String,
    namespace: NamespaceMeta,
) -> Artifact {
    Artifact {
        product: "mosskeys",
        description: "mosskeys published-key set — the private halves generated locally with \
             `mosskeys keygen`; mosskeys never received these. Only the public halves are \
             published to your namespace's transparency log."
            .to_string(),
        namespace,
        label,
        security_level: level.as_str().to_string(),
        generated_at: iso8601_now(),
        warning: "PRIVATE KEYS — store them securely. Anyone with them can impersonate this \
             identity. mosskeys cannot recover or reset them for you."
            .to_string(),
        public_keys: key_set.public,
        private_keys: key_set.private,
        leaf_format: LEAF_FORMAT,
    }
}

/// The default output path for the private artifact, mirroring #78:
/// `mosskeys-<slug|keyset>-<safe-label>-private-keys.json`.
#[must_use]
pub fn default_out_path(namespace: &NamespaceMeta, label: &str) -> String {
    let slug = namespace.slug.as_deref().unwrap_or("keyset");
    let safe_label = sanitize(label);
    format!("mosskeys-{slug}-{safe_label}-private-keys.json")
}

/// Write the PRIVATE artifact to `path` with mode `0600`, refusing to overwrite
/// an existing file.
///
/// # Errors
/// Returns [`Error::Config`] if the file already exists, or [`Error::Io`] on a
/// write/permission failure.
pub fn write_private_artifact(path: &Path, artifact: &Artifact) -> Result<()> {
    if path.exists() {
        return Err(Error::Config(format!(
            "refusing to overwrite existing file: {} (choose another --out path)",
            path.display()
        )));
    }
    let body = serde_json::to_string_pretty(artifact)
        .map_err(|e| Error::Config(format!("serializing artifact: {e}")))?;
    std::fs::write(path, body)
        .map_err(|e| Error::Io(format!("writing {}: {e}", path.display())))?;
    restrict_permissions(path)
}

/// Replace any character outside `[A-Za-z0-9._-]` with `-` (collapsing runs).
fn sanitize(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut last_dash = false;
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    if out.is_empty() {
        out.push_str("identity");
    }
    out
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::Io(format!("chmod 0600 {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (second precision), matching the
/// ISO-8601 shape the reference impls emit. Uses the civil-from-days algorithm
/// (Howard Hinnant) so we need no date/time dependency in the graph.
fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert days since the Unix epoch to a `(year, month, day)` civil date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_level_parse_roundtrip() {
        assert_eq!(SecurityLevel::parse("cat3").unwrap(), SecurityLevel::Cat3);
        assert_eq!(SecurityLevel::parse("CAT5").unwrap(), SecurityLevel::Cat5);
        assert!(SecurityLevel::parse("cat1").is_err());
    }

    #[test]
    fn sanitize_replaces_unsafe_chars() {
        assert_eq!(sanitize("alice@example.com"), "alice-example.com");
        assert_eq!(sanitize("a b/c"), "a-b-c");
        assert_eq!(sanitize(""), "identity");
    }

    #[test]
    fn iso8601_epoch_and_known_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        let now = iso8601_now();
        assert_eq!(now.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(now.ends_with('Z'));
    }
}
