//! Command-line surface (clap derive) + shared context resolution.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use mosskeys_core::{Client, Config};

use crate::output::Reporter;

/// MossKeys — publish public key material and sign checkpoints locally (BYOK).
#[derive(Debug, Parser)]
#[command(name = "mosskeys", version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Options common to every subcommand.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Emit machine-readable JSON on stdout (implies no colour/banner).
    #[arg(long, global = true)]
    pub json: bool,

    /// Path to the config file (defaults to the platform config dir).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// API base URL override (else config, else MOSSKEYS_BASE_URL, else prod).
    #[arg(long, global = true, value_name = "URL")]
    pub base_url: Option<String>,

    /// Namespace slug (else the configured default).
    #[arg(long, short = 'n', global = true, value_name = "SLUG")]
    pub namespace: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Append one or more public-key entries to a namespace's log.
    Publish(crate::commands::publish::PublishArgs),

    /// Long-running daemon: watch a source and continuously publish.
    Sync(crate::commands::sync::SyncArgs),

    /// Sign checkpoints locally (BYOK) and publish them (two-phase handshake).
    Checkpoint(crate::commands::checkpoint::CheckpointArgs),

    /// Manage config + credentials (~/.config/mosskeys/config.toml).
    #[command(subcommand)]
    Config(crate::commands::config::ConfigCmd),
}

/// Resolved runtime context shared by the data-plane commands.
pub struct Ctx {
    pub reporter: Reporter,
    pub config: Config,
    pub config_path: PathBuf,
}

impl Ctx {
    /// Resolve the reporter + load config from the global args.
    ///
    /// # Errors
    /// Fails if the config path cannot be resolved or the file is malformed.
    pub fn load(global: &GlobalArgs) -> mosskeys_core::Result<Self> {
        let config_path = match &global.config {
            Some(p) => p.clone(),
            None => Config::default_path()?,
        };
        let config = Config::load(&config_path)?;
        Ok(Ctx {
            reporter: Reporter::new(global.json),
            config,
            config_path,
        })
    }

    /// The effective namespace slug (CLI flag wins over config default).
    ///
    /// # Errors
    /// Fails if no namespace is available from either source.
    pub fn namespace(&self, global: &GlobalArgs) -> mosskeys_core::Result<String> {
        global
            .namespace
            .clone()
            .or_else(|| self.config.namespace.clone())
            .ok_or_else(|| {
                mosskeys_core::Error::Config(
                    "no namespace — pass --namespace or set one with `mosskeys config set-namespace`"
                        .into(),
                )
            })
    }

    /// Build an authenticated client for the effective base URL + token.
    ///
    /// # Errors
    /// Fails if no token is configured or the client cannot be built.
    pub fn client(&self, global: &GlobalArgs) -> mosskeys_core::Result<Client> {
        let base_url = global
            .base_url
            .clone()
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|| self.config.effective_base_url());
        let token = self.config.effective_token()?;
        Client::new(base_url, token)
    }
}
