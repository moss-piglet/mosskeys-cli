//! `mosskeys checkpoint` — local BYOK checkpoint signing (Option C).
//!
//! The two-phase handshake against #60b, with the signing step performed
//! entirely on operator infrastructure:
//!
//!   1. Phase 1 — POST with no `note_text`; the server returns the canonical
//!      head material (`origin`, `name`, `size`, `root`).
//!   2. Sign that material OFFLINE with the local composite hybrid key.
//!   3. Phase 2 — POST the signed C2SP note; the server verifies it and asserts
//!      it commits to the current head before persisting (409 on drift).
//!
//! In `--watch` mode this repeats on a cadence so a namespace is checkpointed
//! automatically. The signing key never leaves this process and is never logged.

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use mosskeys_core::{ApiErrorCode, Client, Error, Result, signing};

use crate::cli::{Ctx, GlobalArgs};
use crate::output::Reporter;

#[derive(Debug, Args)]
pub struct CheckpointArgs {
    /// Path to the local BYOK signing key (base64 composite secret key).
    /// Defaults to the configured `signing_key_path`.
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Run continuously, signing a checkpoint every INTERVAL seconds.
    #[arg(long, value_name = "SECONDS")]
    pub watch: Option<u64>,

    /// Fetch + sign the material but do NOT publish (prints the signed note).
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(global: &GlobalArgs, args: &CheckpointArgs) -> Result<()> {
    let ctx = Ctx::load(global)?;
    let r = ctx.reporter;
    let slug = ctx.namespace(global)?;

    let key_path = args
        .key
        .clone()
        .or_else(|| ctx.config.signing_key_path.clone())
        .ok_or_else(|| {
            Error::Config(
                "no signing key — pass --key or set one with `mosskeys config set-key`".into(),
            )
        })?;
    let secret_key = signing::read_signing_key(&key_path)?;

    let client = ctx.client(global)?;

    match args.watch {
        None => checkpoint_once(&client, r, &slug, &secret_key, args.dry_run),
        Some(interval) => {
            r.status(&r.theme.info(&format!(
                "checkpoint daemon started (every {interval}s) for {slug}"
            )));
            loop {
                if let Err(err) = checkpoint_once(&client, r, &slug, &secret_key, args.dry_run) {
                    // In watch mode a single failure should not kill the daemon;
                    // report and continue on the cadence.
                    r.report_error(&err);
                }
                std::thread::sleep(Duration::from_secs(interval));
            }
        }
    }
}

fn checkpoint_once(
    client: &Client,
    r: Reporter,
    slug: &str,
    secret_key: &str,
    dry_run: bool,
) -> Result<()> {
    // Phase 1: canonical head to sign.
    let material = client.checkpoint_material(slug)?;
    r.status(&r.theme.info(&format!(
        "phase 1: head at size {} for {}",
        material.size, material.origin
    )));

    // Sign offline with the local key.
    let note_text = signing::sign_material(&material, secret_key)?;

    if dry_run {
        r.result(
            &serde_json::json!({
                "ok": true,
                "dry_run": true,
                "namespace": slug,
                "size": material.size,
                "note": note_text,
            }),
            |t| {
                println!();
                println!("{}", t.heading("dry-run — signed note (not published)"));
                println!();
                println!("{note_text}");
            },
        );
        return Ok(());
    }

    // Phase 2: publish the signed note (server verifies + head-match).
    match client.publish_checkpoint(slug, &note_text) {
        Ok(cp) => {
            r.success(&format!(
                "checkpoint published at size {} ({})",
                cp.size, cp.origin
            ));
            r.result(
                &serde_json::json!({
                    "ok": true,
                    "namespace": slug,
                    "origin": cp.origin,
                    "size": cp.size,
                    "root": cp.root,
                    "note": cp.note,
                }),
                |t| {
                    println!();
                    println!("{}", t.heading("checkpoint published"));
                    println!();
                    println!("{}", t.kv("origin", &cp.origin));
                    println!("{}", t.kv("size", &crate::output::with_commas(cp.size)));
                    println!("{}", t.kv("root", &crate::output::short_root(&cp.root)));
                },
            );
            Ok(())
        }
        Err(err) => {
            if matches!(&err, Error::Api(api) if api.code == ApiErrorCode::HeadMismatch) {
                // The head advanced between Phase 1 and Phase 2 — a benign race.
                r.status(&r.theme.warn(
                    "head advanced during signing (head_mismatch); re-run to checkpoint the new head",
                ));
            }
            Err(err)
        }
    }
}
