//! Config loading via figment (TOML + env vars).

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use thiserror::Error;

use crate::{cli::CliArgs, config::ExporterConfig};

/// Error returned when config loading fails.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigLoadError {
    /// figment extraction failed.
    #[error("config extraction failed: {0}")]
    Extract(String),
}

/// Load [`ExporterConfig`] by merging sources:
///
/// 1. Built-in defaults (constructed by `ExporterConfig::default()`).
/// 2. TOML file at `args.config` (silently ignored if the file is absent).
/// 3. `NLX_`-prefixed environment variables (double-underscore nesting
///    separator: `NLX_COLLECTORS__ETHTOOL=true`).
/// 4. CLI argument overrides (e.g. `--listen-addr`).
///
/// # Errors
///
/// Returns [`ConfigLoadError::Extract`] if figment cannot deserialise the
/// merged configuration into [`ExporterConfig`].
pub fn load_config(args: &CliArgs) -> Result<ExporterConfig, ConfigLoadError> {
    // Start from built-in defaults by serialising the default struct to a
    // figment TOML string, then layering the file and env on top.
    let default_toml = toml::to_string(&ExporterConfig::default()).unwrap_or_default();

    let mut config: ExporterConfig = Figment::new()
        .merge(Toml::string(&default_toml))
        .merge(Toml::file(&args.config))
        .merge(Env::prefixed("NLX_").split("__"))
        .extract()
        .map_err(|e| ConfigLoadError::Extract(e.to_string()))?;

    // CLI flag overrides (highest precedence after env vars).
    if let Some(addr) = &args.listen_addr {
        addr.clone_into(&mut config.listen_addr);
    }

    // Only override log_level when the CLI flag differs from its default.
    if args.log_level != "info" {
        config.log_level.clone_from(&args.log_level);
    }

    Ok(config)
}
