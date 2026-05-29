//! # nlx-config — Configuration Loader
//!
//! **Hexagonal role: DRIVEN ADAPTER (configuration port).**
//!
//! This crate provides [`ExporterConfig`], which implements
//! [`nlx_ports::driven::ConfigPort`] (declared in `nlx-ports`).
//!
//! Configuration sources (in order of precedence, highest first):
//!
//! 1. Environment variables (prefix `NLX_`, e.g. `NLX_LISTEN_ADDR`).
//! 2. TOML configuration file (path from `--config` CLI flag or
//!    `NLX_CONFIG_PATH` env var; default `nft_exporter.toml`).
//! 3. Built-in defaults (e.g. `listen_addr = "0.0.0.0:33400"`).
//!
//! Merging is handled by [`figment`] with
//! `Figment::with(Toml::file(...)).merge(Env::prefixed("NLX_"))`.
//!
//! ## Hexagonal note
//!
//! `figment` and `clap` are confined to this crate.  They must not appear in
//! `nlx-domain` or `nlx-ports` (ADR-0002).

#![deny(missing_docs)]

mod cli;
mod config;
mod loader;

pub use cli::CliArgs;
pub use config::ExporterConfig;
pub use loader::{ConfigLoadError, load_config};
