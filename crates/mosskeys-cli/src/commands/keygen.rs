//! `mosskeys keygen` — generate a `mosskeys/key-history/v1` key set locally.
//!
//! The customer-facing companion to the browser flow (#77) and the operator Mix
//! task (#78). Keys are generated entirely on this machine via the native
//! `metamorphic-crypto` core (the SDK logic lives in [`mosskeys_core::keygen`]),
//! so the artifact is byte-for-byte interoperable with the other two surfaces.
//!
//! The PRIVATE halves are written to an operator-controlled file (mode `0600`,
//! refusing to overwrite); only the PUBLIC halves are printed. Nothing touches
//! the network — keygen is fully offline, so the security level is
//! operator-supplied rather than fetched from the SaaS DB.
//!
//! ## Output contract
//! The written FILE is the frozen artifact schema (including the private
//! halves) shared with #77/#78. In `--json` mode stdout carries a machine
//! envelope with only the PUBLIC halves + the file path — private material is
//! never emitted to stdout or logs.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use mosskeys_core::keygen::{self, NamespaceMeta};
use mosskeys_core::{Result, SecurityLevel};

use crate::cli::GlobalArgs;
use crate::output::Reporter;

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Security posture for the key set (mirrors the namespace policy).
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub security_level: SecurityLevelArg,

    /// Subject / key-id for this identity.
    #[arg(long, default_value = "identity")]
    pub label: String,

    /// Optional namespace UUID, recorded in the artifact.
    #[arg(long, value_name = "UUID")]
    pub namespace_id: Option<String>,

    /// Output file for the PRIVATE halves (default:
    /// `mosskeys-<slug|keyset>-<label>-private-keys.json`).
    #[arg(long, short = 'o', value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Generate + show the PUBLIC halves without writing the private file.
    #[arg(long)]
    pub dry_run: bool,
}

/// The `--security-level` value set, kept in sync with [`SecurityLevel`].
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SecurityLevelArg {
    /// Category 3: ML-KEM-768 / ML-DSA-65.
    Cat3,
    /// Category 5: ML-KEM-1024 / ML-DSA-87.
    Cat5,
}

impl From<SecurityLevelArg> for SecurityLevel {
    fn from(a: SecurityLevelArg) -> Self {
        match a {
            SecurityLevelArg::Cat3 => SecurityLevel::Cat3,
            SecurityLevelArg::Cat5 => SecurityLevel::Cat5,
        }
    }
}

pub fn run(global: &GlobalArgs, args: &KeygenArgs) -> Result<()> {
    let r = Reporter::new(global.json);
    let level: SecurityLevel = args.security_level.into();

    let namespace = NamespaceMeta::new(global.namespace.clone(), args.namespace_id.clone());
    let key_set = keygen::generate_key_set(level)?;
    let artifact = keygen::build_artifact(key_set, level, args.label.clone(), namespace);

    if args.dry_run {
        return dry_run(r, &artifact);
    }

    let out = args.out.clone().unwrap_or_else(|| {
        PathBuf::from(keygen::default_out_path(
            &artifact.namespace,
            &artifact.label,
        ))
    });

    keygen::write_private_artifact(&out, &artifact)?;

    report(r, &artifact, Some(&out));
    Ok(())
}

fn dry_run(r: Reporter, artifact: &keygen::Artifact) -> Result<()> {
    r.result(&public_envelope(artifact, None, true), |t| {
        println!();
        println!("{}", t.heading("dry-run — key set NOT written to disk"));
        print_public(t, artifact);
    });
    Ok(())
}

fn report(r: Reporter, artifact: &keygen::Artifact, out: Option<&PathBuf>) {
    r.success(&format!(
        "generated {} key set ({}) for label {:?}",
        keygen::LEAF_FORMAT,
        artifact.security_level,
        artifact.label
    ));
    r.result(&public_envelope(artifact, out, false), |t| {
        if let Some(path) = out {
            println!();
            println!(
                "{}",
                t.info(&format!(
                    "private halves written (chmod 0600) — keep safe, never sent: {}",
                    path.display()
                ))
            );
        }
        print_public(t, artifact);
        println!();
        println!(
            "{}",
            t.dim(
                "  next: paste the public halves into the publish form, or run `mosskeys publish`"
            )
        );
    });
}

fn print_public(t: crate::theme::Theme, artifact: &keygen::Artifact) {
    let pub_keys = &artifact.public_keys;
    println!();
    println!("{}", t.heading("PUBLIC halves (safe to publish):"));
    println!();
    println!("{}", t.field("enc_x25519", &pub_keys.enc_x25519));
    println!("{}", t.field("enc_pq", &pub_keys.enc_pq));
    println!("{}", t.field("signing_pub", &pub_keys.signing_pub));
}

/// The machine envelope: PUBLIC halves + metadata only. Private material is
/// deliberately excluded — it lives only in the written file.
fn public_envelope(
    artifact: &keygen::Artifact,
    out: Option<&PathBuf>,
    dry_run: bool,
) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "dry_run": dry_run,
        "product": artifact.product,
        "namespace": artifact.namespace,
        "label": artifact.label,
        "security_level": artifact.security_level,
        "generated_at": artifact.generated_at,
        "leaf_format": artifact.leaf_format,
        "public_keys": artifact.public_keys,
        "out": out.map(|p| p.display().to_string()),
    })
}
