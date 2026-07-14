//! `mosskeys config …` — manage config + credentials.

use std::io::Read;
use std::path::PathBuf;

use clap::Subcommand;
use mosskeys_core::config::{Redacted, TOKEN_ENV};
use mosskeys_core::{Config, Error, Result};

use crate::cli::{Ctx, GlobalArgs};

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Store the bearer token. Omit TOKEN to read it from stdin (keeps it out
    /// of shell history). Prefer the MOSSKEYS_TOKEN env var for secret-free CI.
    SetToken {
        /// The `msk_live_…` token. If omitted, one line is read from stdin.
        token: Option<String>,
    },
    /// Set the default namespace slug.
    SetNamespace { slug: String },
    /// Set the API base URL (e.g. http://localhost:4001 for local dev).
    SetBaseUrl { url: String },
    /// Set the path to the local BYOK checkpoint signing key.
    SetKey { path: PathBuf },
    /// Show the effective configuration (token is always redacted).
    Show,
    /// Print the config file path.
    Path,
}

pub fn run(global: &GlobalArgs, cmd: &ConfigCmd) -> Result<()> {
    let mut ctx = Ctx::load(global)?;
    let r = ctx.reporter;

    match cmd {
        ConfigCmd::SetToken { token } => {
            let token = match token {
                Some(t) => t.clone(),
                None => read_stdin_line()?,
            };
            let token = token.trim().to_string();
            if token.is_empty() {
                return Err(Error::Config("empty token".into()));
            }
            ctx.config.token = Some(Redacted(token));
            ctx.config.save(&ctx.config_path)?;
            r.success("token saved");
            Ok(())
        }
        ConfigCmd::SetNamespace { slug } => {
            ctx.config.namespace = Some(slug.clone());
            ctx.config.save(&ctx.config_path)?;
            r.success(&format!("default namespace set to {slug}"));
            Ok(())
        }
        ConfigCmd::SetBaseUrl { url } => {
            ctx.config.base_url = Some(url.trim_end_matches('/').to_string());
            ctx.config.save(&ctx.config_path)?;
            r.success(&format!("base URL set to {url}"));
            Ok(())
        }
        ConfigCmd::SetKey { path } => {
            ctx.config.signing_key_path = Some(path.clone());
            ctx.config.save(&ctx.config_path)?;
            r.success(&format!("signing key path set to {}", path.display()));
            Ok(())
        }
        ConfigCmd::Show => {
            show(&ctx.config, r);
            Ok(())
        }
        ConfigCmd::Path => {
            println!("{}", ctx.config_path.display());
            Ok(())
        }
    }
}

fn show(config: &Config, r: crate::output::Reporter) {
    let token_source = if std::env::var(TOKEN_ENV).is_ok_and(|v| !v.is_empty()) {
        "env (MOSSKEYS_TOKEN)"
    } else if config.token.is_some() {
        "config (redacted)"
    } else {
        "unset"
    };

    r.result(
        &serde_json::json!({
            "ok": true,
            "base_url": config.effective_base_url(),
            "namespace": config.namespace,
            "signing_key_path": config.signing_key_path,
            "token_source": token_source,
        }),
        |t| {
            println!("{}", t.heading("configuration"));
            println!("{}", t.field("base_url", &config.effective_base_url()));
            println!(
                "{}",
                t.field(
                    "namespace",
                    config.namespace.as_deref().unwrap_or("<unset>")
                )
            );
            println!(
                "{}",
                t.field(
                    "signing_key_path",
                    &config
                        .signing_key_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unset>".into())
                )
            );
            println!("{}", t.field("token", token_source));
        },
    );
}

fn read_stdin_line() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| Error::Io(format!("reading token from stdin: {e}")))?;
    Ok(buf)
}
