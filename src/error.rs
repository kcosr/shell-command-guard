use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {0}")]
    IoPlain(#[from] std::io::Error),
    #[error("failed to parse TOML config at {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid regex for {field}: {source}")]
    Regex {
        field: String,
        #[source]
        source: regex::Error,
    },
    #[error("command is empty")]
    EmptyCommand,
    #[error("could not resolve real command for {0}")]
    CommandNotFound(String),
    #[error("resolved command points back to guard binary: {0}")]
    RecursiveCommand(PathBuf),
    #[error("delegate not found: {0}")]
    DelegateNotFound(String),
    #[error("delegate timed out: {0}")]
    DelegateTimedOut(String),
    #[error("delegate failed: {0}")]
    DelegateFailed(String),
}

pub type Result<T> = std::result::Result<T, GuardError>;
