//! Persistent configuration for the CMR GUI client.
//!
//! Config is stored in `~/.config/cmr-gui/config.toml`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Returns the canonical config file path: `~/.config/cmr-gui/config.toml`.
#[must_use]
pub fn default_config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("cmr-gui").join("config.toml")
}

/// Identity type: local HTTP inbox or email address.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum IdentityConfig {
    /// Local HTTP inbox — the GUI runs a small HTTP server and uses it as
    /// the CMR address.  The router can deliver returned messages here.
    Local {
        /// Bind address for the local HTTP server, e.g. `"0.0.0.0:8080"`.
        bind: String,
        /// URL path for the inbox endpoint, e.g. `"/cmr"`.
        path: String,
    },
    /// Email-only identity — the user's `mailto:` address.  The GUI cannot
    /// receive messages inline; users are directed to check their email.
    Email {
        /// Email address (without the `mailto:` scheme).
        email: String,
    },
}

impl IdentityConfig {
    /// Returns the CMR address string used as the sender identity.
    ///
    /// For local identities this is a `http://` URL; for email identities
    /// it is a `mailto:` URI.
    #[must_use]
    pub fn address(&self) -> String {
        match self {
            Self::Local { bind, path } => {
                // Derive a usable host from the bind address.
                let host = if bind.starts_with("0.0.0.0:") {
                    bind.replacen("0.0.0.0:", "127.0.0.1:", 1)
                } else if bind.starts_with("[::]:") {
                    bind.replacen("[::]:", "[::1]:", 1)
                } else {
                    bind.clone()
                };
                let norm_path = if path.starts_with('/') {
                    path.clone()
                } else {
                    format!("/{path}")
                };
                format!("http://{host}{norm_path}")
            }
            Self::Email { email } => format!("mailto:{email}"),
        }
    }
}

/// Router connection configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterConfig {
    /// HTTP(S) URL of the cmr-peer router daemon,
    /// e.g. `"http://localhost:7777/cmr"`.
    pub url: String,
}

/// Signing key configuration.
///
/// The key is used to sign messages sent to the configured router as a
/// pairwise HMAC-SHA-256 secret.  The same key must be registered on the
/// router side.  Leaving the key empty disables signing (unsigned messages).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct KeyConfig {
    /// Key bytes encoded as lower-case hexadecimal.  Empty if unsigned.
    #[serde(default)]
    pub hex: String,
}

impl KeyConfig {
    /// Decodes the stored hex key into bytes.
    ///
    /// Returns `None` if the key is empty or the hex is invalid.
    #[must_use]
    pub fn bytes(&self) -> Option<Vec<u8>> {
        if self.hex.is_empty() {
            return None;
        }
        hex::decode(&self.hex).ok()
    }
}

/// Top-level application configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// User identity (local HTTP inbox or email).
    pub identity: IdentityConfig,
    /// CMR router connection.
    pub router: RouterConfig,
    /// Pairwise signing key for this router.
    #[serde(default)]
    pub key: KeyConfig,
}

/// Errors that can occur when loading or saving the config.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// TOML deserialization failure.
    #[error("config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    /// TOML serialization failure.
    #[error("config serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl Config {
    /// Loads the config from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// Saves the config to `path`, creating parent directories as needed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be written or serialized.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Returns `true` when a config file already exists at `path`.
    #[must_use]
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }
}
