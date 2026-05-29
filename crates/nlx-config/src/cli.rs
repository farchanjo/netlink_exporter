//! CLI argument definitions parsed by `clap`.

use clap::Parser;

/// Command-line arguments for `netlink_exporter`.
#[derive(Debug, Parser)]
#[command(
    name = "netlink_exporter",
    about = "Prometheus / OpenMetrics exporter for Linux netlink subsystems"
)]
pub struct CliArgs {
    /// Path to the TOML configuration file.
    ///
    /// If absent, the exporter looks for `nft_exporter.toml` in the current
    /// working directory.  Built-in defaults are used if the file is missing.
    #[arg(long, env = "NLX_CONFIG_PATH", default_value = "nft_exporter.toml")]
    pub config: String,

    /// Override the HTTP listen address (e.g. `0.0.0.0:33400`).
    ///
    /// Takes precedence over the TOML `listen_addr` key and the
    /// `NLX_LISTEN_ADDR` environment variable.
    #[arg(long, env = "NLX_LISTEN_ADDR")]
    pub listen_addr: Option<String>,

    /// Log level (`trace`, `debug`, `info`, `warn`, `error`).
    #[arg(long, env = "NLX_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}
