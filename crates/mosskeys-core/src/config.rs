//! Persistent CLI configuration + credential resolution.
//!
//! Config lives at the platform config dir (`~/.config/mosskeys/config.toml` on
//! Linux, `~/Library/Application Support/mosskeys/config.toml` on macOS) and is
//! deliberately minimal. The bearer token can be stored there OR supplied via
//! the `MOSSKEYS_TOKEN` environment variable, which always wins so CI/agents
//! never have to write a secret to disk.
//!
//! ## Zero-knowledge / secret hygiene
//! The checkpoint signing key is referenced by *path only* — it is read at sign
//! time and never copied into the config file, never logged, and never sent to
//! the server. `Debug` for [`Config`] redacts the token.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Environment variable that overrides the on-disk token.
pub const TOKEN_ENV: &str = "MOSSKEYS_TOKEN";

/// Environment variable that overrides the API base URL (handy for staging /
/// local dev, e.g. `http://localhost:4001`).
pub const BASE_URL_ENV: &str = "MOSSKEYS_BASE_URL";

/// Default production API base URL.
pub const DEFAULT_BASE_URL: &str = "https://mosskeys.com";

/// The persisted configuration document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// API base URL (no trailing slash). Defaults to [`DEFAULT_BASE_URL`].
    #[serde(default)]
    pub base_url: Option<String>,

    /// Bearer token (`msk_live_…`). Prefer [`TOKEN_ENV`] for secret-free configs.
    #[serde(default)]
    pub token: Option<Redacted>,

    /// Default namespace slug so `--namespace` can be omitted.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Path to the local BYOK checkpoint signing key (base64 composite secret
    /// key). Read at sign time; the key never leaves operator infra.
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,
}

/// A string that never reveals itself through `Debug` (defence-in-depth against
/// accidental token logging).
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Redacted(pub String);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"***redacted***\"")
    }
}

impl Config {
    /// The default config file path for this platform.
    ///
    /// # Errors
    /// Fails if no home/config directory can be determined.
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("app", "MossKeys", "mosskeys")
            .ok_or_else(|| Error::Config("could not resolve a config directory".into()))?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Load config from `path`, returning [`Config::default`] when it is absent.
    ///
    /// # Errors
    /// Fails on a present-but-unreadable or malformed file.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents)
                .map_err(|e| Error::Config(format!("invalid config at {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::Io(format!("reading {}: {e}", path.display()))),
        }
    }

    /// Persist to `path`, creating the parent directory and restricting the file
    /// to owner-only (`0600`) on Unix since it may hold a token.
    ///
    /// # Errors
    /// Fails on serialization or IO error.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Io(format!("creating {}: {e}", parent.display())))?;
        }
        let body = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("serializing config: {e}")))?;
        std::fs::write(path, body)
            .map_err(|e| Error::Io(format!("writing {}: {e}", path.display())))?;
        restrict_permissions(path)?;
        Ok(())
    }

    /// The effective base URL: `MOSSKEYS_BASE_URL` env, then config, then default.
    #[must_use]
    pub fn effective_base_url(&self) -> String {
        std::env::var(BASE_URL_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| self.base_url.clone())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string()
    }

    /// The effective bearer token: [`TOKEN_ENV`] env wins, else config.
    ///
    /// # Errors
    /// Fails if neither source supplies a token.
    pub fn effective_token(&self) -> Result<String> {
        std::env::var(TOKEN_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| self.token.as_ref().map(|r| r.0.clone()))
            .ok_or_else(|| {
                Error::Config(format!(
                    "no API token found — set {TOKEN_ENV} or run `mosskeys config set-token`"
                ))
            })
    }
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
