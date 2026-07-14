//! `mosskeys publish` — append public-key entries to a namespace's log.
//!
//! Entry material can come from single-entry flags, a `--file`, or piped stdin
//! (a JSON object or array). Only already-public fields are transmitted. The
//! append endpoint is dedup-idempotent, so re-publishing identical material is
//! safe and returns the same stable index.

use std::io::Read;
use std::path::PathBuf;

use clap::Args;
use mosskeys_core::{Client, EntryInput, Error, Result};

use crate::cli::{Ctx, GlobalArgs};
use crate::output::Reporter;

#[derive(Debug, Args)]
pub struct PublishArgs {
    /// Human-readable label for the entry.
    #[arg(long)]
    pub label: Option<String>,
    /// Public X25519 encryption key (base64).
    #[arg(long)]
    pub enc_x25519: Option<String>,
    /// Public post-quantum (ML-KEM) encryption key (base64).
    #[arg(long)]
    pub enc_pq: Option<String>,
    /// Public signing key (base64).
    #[arg(long)]
    pub signing_pub: Option<String>,
    /// Optional client timestamp (ms since epoch).
    #[arg(long)]
    pub ts_ms: Option<i64>,

    /// Read entries from a JSON file (object or array) instead of flags.
    #[arg(long, value_name = "PATH", conflicts_with = "label")]
    pub file: Option<PathBuf>,

    /// Validate + show what would be sent without contacting the server.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(global: &GlobalArgs, args: &PublishArgs) -> Result<()> {
    let ctx = Ctx::load(global)?;
    let r = ctx.reporter;
    let slug = ctx.namespace(global)?;
    let entries = collect_entries(args)?;

    if entries.is_empty() {
        return Err(Error::Config("no entries to publish".into()));
    }

    if args.dry_run {
        return dry_run(r, &slug, &entries);
    }

    let client = ctx.client(global)?;
    publish_all(&client, r, &slug, &entries)
}

/// Publish every entry, reporting each result. Shared with `sync`.
pub fn publish_all(client: &Client, r: Reporter, slug: &str, entries: &[EntryInput]) -> Result<()> {
    let mut results = Vec::with_capacity(entries.len());
    for entry in entries {
        let res = client.append_entry(slug, entry)?;
        r.success(&format!(
            "published {} → index {} (size {})",
            entry.label, res.index, res.size
        ));
        results.push(serde_json::json!({
            "label": entry.label,
            "index": res.index,
            "size": res.size,
            "root": res.root,
        }));
    }

    r.result(
        &serde_json::json!({ "ok": true, "namespace": slug, "published": results }),
        |_t| {},
    );
    Ok(())
}

fn dry_run(r: Reporter, slug: &str, entries: &[EntryInput]) -> Result<()> {
    r.result(
        &serde_json::json!({
            "ok": true,
            "dry_run": true,
            "namespace": slug,
            "entries": entries,
        }),
        |t| {
            println!(
                "{}",
                t.heading(&format!("dry-run — {} entry(ies)", entries.len()))
            );
            for e in entries {
                println!("{}", t.info(&format!("would publish to {slug}")));
                println!("{}", t.field("label", &e.label));
            }
        },
    );
    Ok(())
}

/// Assemble entries from flags, a file, or stdin (in that precedence).
fn collect_entries(args: &PublishArgs) -> Result<Vec<EntryInput>> {
    if args.label.is_some()
        || args.enc_x25519.is_some()
        || args.enc_pq.is_some()
        || args.signing_pub.is_some()
    {
        return Ok(vec![entry_from_flags(args)?]);
    }

    let raw = match &args.file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("reading {}: {e}", path.display())))?,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| Error::Io(format!("reading stdin: {e}")))?;
            buf
        }
    };

    parse_entries(&raw)
}

fn entry_from_flags(args: &PublishArgs) -> Result<EntryInput> {
    let req = |name: &str, v: &Option<String>| -> Result<String> {
        v.clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Config(format!("--{name} is required")))
    };
    Ok(EntryInput {
        label: req("label", &args.label)?,
        enc_x25519: req("enc-x25519", &args.enc_x25519)?,
        enc_pq: req("enc-pq", &args.enc_pq)?,
        signing_pub: req("signing-pub", &args.signing_pub)?,
        ts_ms: args.ts_ms,
    })
}

/// Parse a JSON object or array of [`EntryInput`].
pub fn parse_entries(raw: &str) -> Result<Vec<EntryInput>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| Error::Config(format!("invalid JSON: {e}")))?;
    let entries = match value {
        serde_json::Value::Array(_) => serde_json::from_value(value),
        _ => serde_json::from_value(value).map(|e: EntryInput| vec![e]),
    }
    .map_err(|e| Error::Config(format!("invalid entry shape: {e}")))?;
    Ok(entries)
}
