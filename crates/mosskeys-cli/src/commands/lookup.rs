//! `mosskeys lookup` — privacy-preserving directory lookup (#172).
//!
//! Resolves a label to its current key-history head (the bound `entry_hash`)
//! with a fully client-verified proof, choosing the serving path from the
//! namespace's published directory head:
//!
//!   * **oblivious (POPRF, RFC 9497)** — the default for new namespaces: the
//!     label is blinded locally and the server only ever sees a blinded element
//!     and a pseudorandom index;
//!   * **legacy (VRF)** — the label is sent to the server for evaluation; the
//!     proof still verifies client-side, and the output says plainly that the
//!     operator saw the label at query time.
//!
//! Read-only and unauthenticated, like `verify`.

use clap::Args;
use mosskeys_core::{LookupOutcome, LookupPath, LookupReport, Result, lookup};

use crate::cli::{Ctx, GlobalArgs};
use crate::output::Reporter;

#[derive(Debug, Args)]
pub struct LookupArgs {
    /// The exact label to look up. On a POPRF namespace it never leaves this
    /// host; on a legacy VRF namespace it is sent to the server (the output
    /// says which happened).
    #[arg(value_name = "LABEL")]
    pub label: String,
}

pub fn run(global: &GlobalArgs, args: &LookupArgs) -> Result<()> {
    let ctx = Ctx::load(global)?;
    let r = ctx.reporter;
    let slug = ctx.namespace(global)?;
    let client = ctx.read_client(global)?;

    let report = lookup(&client, &slug, &args.label)?;
    render(r, &slug, &args.label, &report);
    Ok(())
}

fn render(r: Reporter, slug: &str, label: &str, report: &LookupReport) {
    let (status, value, root, entries) = match &report.outcome {
        LookupOutcome::Present {
            value,
            root,
            entries,
        } => ("present", Some(value.as_str()), root.as_str(), *entries),
        LookupOutcome::Absent { root, entries } => ("absent", None, root.as_str(), *entries),
    };

    let path = match report.path {
        LookupPath::Poprf => "poprf",
        LookupPath::Vrf => "vrf",
    };

    let json = serde_json::json!({
        "ok": true,
        "namespace": slug,
        "label": label,
        "path": path,
        "status": status,
        "value": value,
        "root": root,
        "entries": entries,
        "checks": {
            "evaluation": "pass",
            "directory_proof": "pass",
        },
    });

    r.result(&json, |t| {
        match report.path {
            LookupPath::Poprf => {
                println!(
                    "{}",
                    t.check_pass("DLEQ proof verified — the server saw only a blinded element")
                );
            }
            LookupPath::Vrf => {
                println!(
                    "{}",
                    t.check_pass("VRF proof verified against the published key")
                );
            }
        }
        println!(
            "{}",
            t.check_pass(&format!("{status} proof verified against the directory root"))
        );
        println!();

        println!("{}", t.kv("label", label));
        println!("{}", t.kv("status", status));
        if let Some(value) = value {
            println!("{}", t.kv("value", value));
        }
        println!("{}", t.kv("entries", &entries.to_string()));
        println!();

        match report.path {
            LookupPath::Poprf => {
                println!(
                    "{}",
                    t.dim("  oblivious lookup (RFC 9497): the label never left this host")
                );
            }
            LookupPath::Vrf => {
                println!(
                    "{}",
                    t.dim(
                        "  legacy lookup: the operator saw this label at query time (the namespace can upgrade to oblivious lookups)"
                    )
                );
            }
        }
    });
}
