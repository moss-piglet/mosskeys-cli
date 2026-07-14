//! `mosskeys sync` — long-running daemon that continuously publishes.
//!
//! Polls a JSON source on a cadence and publishes every entry. Delivery is
//! at-least-once: the append endpoint is dedup-idempotent (#60b), so replaying
//! the whole source each cycle never creates duplicate leaves — a previously
//! published entry simply returns its existing index. This makes the daemon
//! crash-safe and lets it recover from transient outages by design.
//!
//! Retryable failures (429 rate-limit/quota, transport errors) trigger bounded
//! exponential backoff that honours a server `Retry-After`. Terminal failures
//! (e.g. 422 validation) are reported and skipped so one bad entry cannot wedge
//! the daemon.

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use mosskeys_core::{Client, EntryInput, Error, Result};

use crate::cli::{Ctx, GlobalArgs};
use crate::commands::publish::parse_entries;
use crate::output::Reporter;

#[derive(Debug, Args)]
pub struct SyncArgs {
    /// JSON source file (object or array of entries) to watch + publish.
    #[arg(long, value_name = "PATH")]
    pub source: PathBuf,

    /// Poll + republish the source every INTERVAL seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    pub interval: u64,

    /// Maximum retry attempts per entry before giving up for this cycle.
    #[arg(long, default_value_t = 5)]
    pub max_retries: u32,

    /// Run exactly one cycle then exit (useful for cron / testing).
    #[arg(long)]
    pub once: bool,
}

pub fn run(global: &GlobalArgs, args: &SyncArgs) -> Result<()> {
    let ctx = Ctx::load(global)?;
    let r = ctx.reporter;
    let slug = ctx.namespace(global)?;
    let client = ctx.client(global)?;

    r.status(&r.theme.info(&format!(
        "sync daemon started for {} (source {}, every {}s)",
        slug,
        args.source.display(),
        args.interval
    )));

    loop {
        if let Err(err) = cycle(&client, r, &slug, args) {
            r.report_error(&err);
        }
        if args.once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(args.interval));
    }
}

fn cycle(client: &Client, r: Reporter, slug: &str, args: &SyncArgs) -> Result<()> {
    let raw = std::fs::read_to_string(&args.source)
        .map_err(|e| Error::Io(format!("reading {}: {e}", args.source.display())))?;
    let entries = parse_entries(&raw)?;

    let mut published = 0u64;
    for entry in &entries {
        match publish_with_backoff(client, r, slug, entry, args.max_retries) {
            Ok(()) => published += 1,
            // Terminal error for this entry: report + skip, keep the daemon alive.
            Err(err) => r.report_error(&err),
        }
    }

    r.status(&r.theme.success(&format!(
        "cycle complete: {published}/{} delivered",
        entries.len()
    )));
    Ok(())
}

/// Publish one entry, retrying retryable failures with bounded exponential
/// backoff (base 1s, capped at 60s), honouring a server `Retry-After`.
fn publish_with_backoff(
    client: &Client,
    r: Reporter,
    slug: &str,
    entry: &EntryInput,
    max_retries: u32,
) -> Result<()> {
    let mut attempt = 0u32;
    loop {
        match client.append_entry(slug, entry) {
            Ok(res) => {
                r.status(&r.theme.success(&format!(
                    "{} → index {} (size {})",
                    entry.label, res.index, res.size
                )));
                return Ok(());
            }
            Err(err) if is_retryable(&err) && attempt < max_retries => {
                let delay = backoff_delay(&err, attempt);
                attempt += 1;
                r.status(&r.theme.warn(&format!(
                    "{} failed ({}); retry {}/{} in {}s",
                    entry.label,
                    short_reason(&err),
                    attempt,
                    max_retries,
                    delay.as_secs()
                )));
                std::thread::sleep(delay);
            }
            Err(err) => return Err(err),
        }
    }
}

fn is_retryable(err: &Error) -> bool {
    match err {
        Error::Transport(_) => true,
        Error::Api(api) => api.code.is_retryable(),
        _ => false,
    }
}

/// Exponential backoff (1,2,4,…s capped at 60s), overridden by `Retry-After`.
fn backoff_delay(err: &Error, attempt: u32) -> Duration {
    if let Error::Api(api) = err {
        if let Some(secs) = api.retry_after_secs {
            return Duration::from_secs(secs.max(1));
        }
    }
    let secs = 1u64.checked_shl(attempt).unwrap_or(60).min(60);
    Duration::from_secs(secs)
}

fn short_reason(err: &Error) -> String {
    match err {
        Error::Api(api) => api.raw_code.clone(),
        Error::Transport(_) => "network".into(),
        _ => "error".into(),
    }
}
