#![forbid(unsafe_code)]

pub mod config;
pub mod metrics;
pub mod net;
pub mod pool;
pub mod proxy;
pub mod server;

use std::fmt;

pub type Result<T> = std::result::Result<T, ConfigError>;

// Only construct from static descriptions and vetted identifiers / numeric data.
// In particular, never wrap deserializer, HTTP, TLS or DNS error Debug output.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl From<&'static str> for ConfigError {
    fn from(value: &'static str) -> Self {
        Self(value.into())
    }
}
impl fmt::Display for ConfigError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}
