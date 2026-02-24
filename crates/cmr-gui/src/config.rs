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
        /// Optional globally reachable address advertised in message headers.
        ///
        /// Example: `"http://cmr-client.example.net:8080/cmr"`.
        #[serde(default)]
        advertised_address: Option<String>,
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
            Self::Local {
                bind,
                path,
                advertised_address,
            } => {
                if let Some(advertised) = advertised_address
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    return advertised.to_owned();
                }
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

    /// Returns a human-readable identity kind label.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Local { .. } => "Local HTTP",
            Self::Email { .. } => "Email",
        }
    }
}

/// Named identity profile shown in the GUI identity picker.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityProfile {
    /// Friendly display name.
    pub name: String,
    /// Identity configuration.
    pub identity: IdentityConfig,
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
    /// Legacy single identity (backward compatibility for older config files).
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    /// Named identity profiles available for sending.
    #[serde(default)]
    pub identities: Vec<IdentityProfile>,
    /// Selected identity index in `identities`.
    #[serde(default)]
    pub selected_identity: usize,
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
    /// Invalid semantic configuration.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    /// Loads the config from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        let mut cfg = toml::from_str::<Self>(&text)?;
        cfg.normalize_identities()?;
        Ok(cfg)
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
        let mut to_save = self.clone();
        to_save.normalize_identities()?;
        // Persist canonical multi-identity shape.
        to_save.identity = None;
        let text = toml::to_string_pretty(&to_save)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Returns `true` when a config file already exists at `path`.
    #[must_use]
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Returns all identity profiles, normalized and non-empty.
    pub fn identity_profiles(&self) -> Result<Vec<IdentityProfile>, ConfigError> {
        let mut cloned = self.clone();
        cloned.normalize_identities()?;
        Ok(cloned.identities)
    }

    /// Returns selected identity profile.
    pub fn selected_identity_profile(&self) -> Result<IdentityProfile, ConfigError> {
        let mut cloned = self.clone();
        cloned.normalize_identities()?;
        let idx = cloned
            .selected_identity
            .min(cloned.identities.len().saturating_sub(1));
        cloned
            .identities
            .get(idx)
            .cloned()
            .ok_or_else(|| ConfigError::Invalid("no identities configured".to_owned()))
    }

    fn normalize_identities(&mut self) -> Result<(), ConfigError> {
        if self.identities.is_empty()
            && let Some(legacy) = self.identity.clone()
        {
            self.identities.push(IdentityProfile {
                name: "default".to_owned(),
                identity: legacy,
            });
        }
        if self.identities.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one identity must be configured".to_owned(),
            ));
        }
        for profile in &mut self.identities {
            let trimmed = profile.name.trim();
            if trimmed.is_empty() {
                "identity".clone_into(&mut profile.name);
            } else {
                profile.name = trimmed.to_owned();
            }
        }
        self.selected_identity = self
            .selected_identity
            .min(self.identities.len().saturating_sub(1));
        Ok(())
    }
}
