//! `mosskeys verify` — read-only, offline-capable key-history verification.
//!
//! This is the command that lets *anyone* — a relying party, a CI job, an edge
//! device — check a MossKeys log without an account or a write token. It proves
//! three things, all with the linked `metamorphic-log` verifier (ZERO new
//! crypto, the same core the server and browser use):
//!
//!   1. **inclusion** — the label's current key material is actually committed
//!      in the log at the claimed position, under a signed checkpoint root;
//!   2. **consistency** — the current head is an append-only extension of a
//!      checkpoint you pinned earlier (history was not rewritten); and
//!   3. **witness co-signatures** — the checkpoint is co-signed by the verifier
//!      key(s) you pin (the log's own key and/or independent witnesses).
//!
//! ## Honest scope
//!
//! Together these establish that, *in an append-only log, the history you are
//! shown has not been rewritten*. They do NOT, on their own, detect a **split
//! view** — the log presenting a different head to someone else. Catching that
//! needs independent witnesses observing the same head (the witness network,
//! #19/#300). The command says so in its help rather than overclaiming.
//!
//! ## Three modes (exactly one)
//!
//!   * `--label <LABEL>` (alias `--identity`) — online: look a label up, verify
//!     its inclusion against the latest signed checkpoint, optionally check
//!     append-only consistency against a `--pin`ned checkpoint, and optionally
//!     verify co-signatures against `--verifier-key`s.
//!   * `--checkpoint <FILE>` — offline (#26): verify a pinned checkpoint note's
//!     co-signatures (and, with `--consistency`, append-only continuity from an
//!     `--against` checkpoint) with no network at all.
//!   * `--digest <HEX>` — supply-chain (#317): prove a specific artifact/leaf
//!     digest is committed at `--index` under the current signed head.

use std::path::PathBuf;

use clap::Args;
use mosskeys_core::{
    Client, CosignReport, Error, LatestCheckpoint, Result, VerifyError, parse_checkpoint_head,
    verify_consistency, verify_inclusion, verify_witness_cosigs,
};

use crate::cli::{Ctx, GlobalArgs};
use crate::output::Reporter;
use crate::theme::Theme;

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("target")
        .required(true)
        .args(["label", "checkpoint", "digest"])
))]
pub struct VerifyArgs {
    /// Verify a label's current key history (online). `--identity` is an alias.
    #[arg(long, visible_alias = "identity", value_name = "LABEL")]
    pub label: Option<String>,

    /// Verify a pinned checkpoint note FILE offline (no network).
    #[arg(long, value_name = "FILE")]
    pub checkpoint: Option<PathBuf>,

    /// Prove a leaf/artifact digest (hex) is committed at `--index`.
    #[arg(long, value_name = "HEX")]
    pub digest: Option<String>,

    /// Leaf index for `--digest` verification.
    #[arg(long, value_name = "N", requires = "digest")]
    pub index: Option<u64>,

    /// Trusted verifier key(s) (C2SP `vkey` strings) to check checkpoint
    /// co-signatures against — the log's own key and/or independent witnesses.
    /// Repeatable. Without any, co-signatures are reported as "not checked".
    #[arg(long = "verifier-key", value_name = "VKEY")]
    pub verifier_keys: Vec<String>,

    /// A previously pinned checkpoint note FILE to check append-only consistency
    /// against (the earlier head). With `--label`/`--digest` the proof is
    /// fetched from the server; with `--checkpoint` use `--consistency` too.
    #[arg(long, value_name = "FILE")]
    pub pin: Option<PathBuf>,

    /// An offline consistency-proof FILE (`{"from","to","proof":[..]}`) binding
    /// `--pin` (older) to `--checkpoint` (newer). Offline mode only.
    #[arg(long, value_name = "FILE", requires = "checkpoint")]
    pub consistency: Option<PathBuf>,
}

/// The pass/skip/fail state of one verification check, for rendering + JSON.
enum Check {
    Pass(String),
    Skip(String),
}

impl Check {
    fn render(&self, t: Theme) -> String {
        match self {
            Check::Pass(s) => t.check_pass(s),
            Check::Skip(s) => t.check_skip(s),
        }
    }

    fn json(&self) -> &'static str {
        match self {
            Check::Pass(_) => "pass",
            Check::Skip(_) => "skipped",
        }
    }
}

pub fn run(global: &GlobalArgs, args: &VerifyArgs) -> Result<()> {
    let ctx = Ctx::load(global)?;
    let r = ctx.reporter;

    if let Some(label) = &args.label {
        let slug = ctx.namespace(global)?;
        let client = ctx.read_client(global)?;
        verify_label(&client, r, &slug, label, args)
    } else if let Some(path) = &args.checkpoint {
        verify_checkpoint_file(r, path, args)
    } else if let Some(digest) = &args.digest {
        let slug = ctx.namespace(global)?;
        let client = ctx.read_client(global)?;
        let index = args
            .index
            .ok_or_else(|| Error::Config("`--digest` requires `--index <N>`".into()))?;
        verify_digest(&client, r, &slug, digest, index, args)
    } else {
        // clap's required ArgGroup makes this unreachable.
        Err(Error::Config("nothing to verify".into()))
    }
}

// ---- Mode 1: --label (online) ----------------------------------------------

fn verify_label(
    client: &Client,
    r: Reporter,
    slug: &str,
    label: &str,
    args: &VerifyArgs,
) -> Result<()> {
    let head = client.label_head(slug, label)?;

    let checkpoint = head
        .checkpoint
        .clone()
        .ok_or(Error::Verification(VerifyError::NotAnchored))?;

    // Inclusion: prefer the bundled proof, else fetch one against the head.
    let inclusion = match head.inclusion_proof.clone() {
        Some(p) => p,
        None => {
            // The entry is newer than the latest checkpoint: not yet anchored.
            if head.index >= checkpoint.size {
                return Err(Error::Verification(VerifyError::NotAnchored));
            }
            client.inclusion(slug, head.index, checkpoint.size)?
        }
    };
    verify_inclusion(
        inclusion.index,
        inclusion.size,
        &inclusion.leaf_hash,
        &inclusion.proof,
        &checkpoint.root,
    )?;
    let inclusion_check = Check::Pass("inclusion proof verified".to_string());

    // Consistency (only when a prior checkpoint is pinned).
    let consistency_check = match &args.pin {
        Some(pin_path) => {
            let pinned = parse_checkpoint_head(&read_text(pin_path)?)?;
            let proof = client.consistency(slug, pinned.size, checkpoint.size)?;
            verify_consistency(
                pinned.size,
                checkpoint.size,
                &proof.proof,
                &pinned.root_b64,
                &checkpoint.root,
            )?;
            Check::Pass(format!(
                "consistency proof verified (from size {})",
                pinned.size
            ))
        }
        None => Check::Skip(
            "consistency not checked (pass --pin <checkpoint> to prove append-only)".to_string(),
        ),
    };

    let (cosign, suite) = cosign_check(&checkpoint, &args.verifier_keys)?;
    render(
        r,
        "label",
        Some(label),
        &checkpoint,
        Some(head.index),
        inclusion_check,
        consistency_check,
        cosign,
        suite,
    );
    Ok(())
}

// ---- Mode 2: --checkpoint (offline) ----------------------------------------

fn verify_checkpoint_file(r: Reporter, path: &PathBuf, args: &VerifyArgs) -> Result<()> {
    let note = read_text(path)?;
    let head = parse_checkpoint_head(&note)?;
    let checkpoint = LatestCheckpoint {
        origin: head.origin.clone(),
        size: head.size,
        root: head.root_b64.clone(),
        note: note.clone(),
    };

    // Consistency (offline): needs both a pinned older checkpoint and its proof.
    let consistency_check = match (&args.pin, &args.consistency) {
        (Some(pin_path), Some(proof_path)) => {
            let pinned = parse_checkpoint_head(&read_text(pin_path)?)?;
            let proof: ProofFile = serde_json::from_str(&read_text(proof_path)?)
                .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
            verify_consistency(
                pinned.size,
                head.size,
                &proof.proof,
                &pinned.root_b64,
                &head.root_b64,
            )?;
            Check::Pass(format!(
                "consistency proof verified (from size {})",
                pinned.size
            ))
        }
        _ => Check::Skip(
            "consistency not checked (pass --pin <old> --consistency <proof.json>)".to_string(),
        ),
    };

    let (cosign, suite) = cosign_check(&checkpoint, &args.verifier_keys)?;
    // No leaf/inclusion in checkpoint-only mode.
    let inclusion_check =
        Check::Skip("inclusion not checked (checkpoint-only; use --label or --digest)".to_string());
    render(
        r,
        "checkpoint",
        None,
        &checkpoint,
        None,
        inclusion_check,
        consistency_check,
        cosign,
        suite,
    );
    Ok(())
}

// ---- Mode 3: --digest (supply-chain) ---------------------------------------

fn verify_digest(
    client: &Client,
    r: Reporter,
    slug: &str,
    digest_hex: &str,
    index: u64,
    args: &VerifyArgs,
) -> Result<()> {
    let want = hex_to_bytes(digest_hex)
        .ok_or_else(|| Error::Verification(VerifyError::Malformed("digest is not hex".into())))?;

    let checkpoint = client.latest_checkpoint(slug)?;
    let inclusion = client.inclusion(slug, index, checkpoint.size)?;

    // The committed leaf hash must equal the supplied digest.
    let committed = base64_to_bytes(&inclusion.leaf_hash).ok_or_else(|| {
        Error::Verification(VerifyError::Malformed("leaf hash not base64".into()))
    })?;
    if committed != want {
        return Err(Error::Verification(VerifyError::DigestMismatch));
    }

    verify_inclusion(
        inclusion.index,
        inclusion.size,
        &inclusion.leaf_hash,
        &inclusion.proof,
        &checkpoint.root,
    )?;
    let inclusion_check = Check::Pass("digest committed at the claimed index".to_string());
    let consistency_check =
        Check::Skip("consistency not checked (pass --label with --pin for continuity)".to_string());
    let (cosign, suite) = cosign_check(&checkpoint, &args.verifier_keys)?;
    render(
        r,
        "digest",
        None,
        &checkpoint,
        Some(index),
        inclusion_check,
        consistency_check,
        cosign,
        suite,
    );
    Ok(())
}

// ---- Shared: co-signature check + rendering --------------------------------

fn cosign_check(checkpoint: &LatestCheckpoint, keys: &[String]) -> Result<(Check, Option<String>)> {
    if keys.is_empty() {
        return Ok((
            Check::Skip(
                "checkpoint co-signatures not checked (pass --verifier-key to verify)".to_string(),
            ),
            None,
        ));
    }
    let report = verify_witness_cosigs(&checkpoint.note, keys)?;
    Ok((Check::Pass(cosign_line(&report)), report.suite))
}

fn cosign_line(report: &CosignReport) -> String {
    match report.witnesses {
        0 => "checkpoint signature verified".to_string(),
        1 => "checkpoint co-signed by 1 witness".to_string(),
        n => format!("checkpoint co-signed by {n} witnesses"),
    }
}

#[allow(clippy::too_many_arguments)]
fn render(
    r: Reporter,
    mode: &str,
    label: Option<&str>,
    checkpoint: &LatestCheckpoint,
    leaf_index: Option<u64>,
    inclusion: Check,
    consistency: Check,
    cosign: Check,
    suite: Option<String>,
) {
    let conclusion = conclusion_line(&inclusion, &consistency);
    let root_short = short_root(&checkpoint.root);

    let value = serde_json::json!({
        "ok": true,
        "mode": mode,
        "label": label,
        "origin": checkpoint.origin,
        "size": checkpoint.size,
        "root": checkpoint.root,
        "leaf_index": leaf_index,
        "suite": suite,
        "checks": {
            "inclusion": inclusion.json(),
            "consistency": consistency.json(),
            "witnesses": cosign.json(),
        },
        "conclusion": conclusion,
    });

    r.result(&value, |t| {
        println!("{}", inclusion.render(t));
        println!("{}", consistency.render(t));
        println!("{}", cosign.render(t));
        println!();
        if let Some(suite) = &suite {
            println!("{}", t.kv("suite", suite));
        }
        if let Some(idx) = leaf_index {
            println!("{}", t.kv("leaf", &format!("#{}", with_commas(idx))));
        }
        println!("{}", t.kv("root", &root_short));
        println!();
        println!("{}", t.info(&conclusion));
    });
}

fn conclusion_line(inclusion: &Check, consistency: &Check) -> String {
    match (inclusion, consistency) {
        (Check::Pass(_), Check::Pass(_)) => {
            "key history is append-only and tamper-evident".to_string()
        }
        (Check::Pass(_), Check::Skip(_)) => {
            "entry is included in the current signed checkpoint".to_string()
        }
        _ => "checkpoint verified".to_string(),
    }
}

// ---- Small, dependency-free helpers ----------------------------------------

#[derive(serde::Deserialize)]
struct ProofFile {
    #[allow(dead_code)]
    from: Option<u64>,
    #[allow(dead_code)]
    to: Option<u64>,
    proof: Vec<String>,
}

fn read_text(path: &PathBuf) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::Io(format!("reading {}: {e}", path.display())))
}

/// A compact `0x9acf…e8e8` display of a base64 root (first + last 2 bytes).
fn short_root(root_b64: &str) -> String {
    match base64_to_bytes(root_b64) {
        Some(bytes) if bytes.len() >= 4 => {
            let n = bytes.len();
            format!(
                "0x{:02x}{:02x}…{:02x}{:02x}",
                bytes[0],
                bytes[1],
                bytes[n - 2],
                bytes[n - 1]
            )
        }
        _ => format!("0x{root_b64}"),
    }
}

fn with_commas(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let first = bytes.len() % 3;
    for (i, b) in bytes.iter().enumerate() {
        if i != 0 && (i - first) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn base64_to_bytes(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}
