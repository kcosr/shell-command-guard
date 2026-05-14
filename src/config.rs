use std::{
    collections::{HashMap, HashSet},
    env,
    path::{Path, PathBuf},
};

use regex::Regex;
use serde::Deserialize;

use crate::error::{GuardError, Result};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/shell-command-guard/config.toml";
pub const ENV_CONFIG: &str = "SHELL_COMMAND_GUARD_CONFIG";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub install: InstallConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub delegates: HashMap<String, DelegateConfig>,
    #[serde(default)]
    pub commands: HashMap<String, CommandConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallConfig {
    pub bin_dir: PathBuf,
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CommandConfig {
    pub real_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_deny_exit_code")]
    pub deny_exit_code: i32,
    #[serde(default = "default_deny_prefix")]
    pub deny_prefix: String,
    #[serde(default)]
    pub reveal_guard_name: bool,
    #[serde(default)]
    pub reveal_rule_id: bool,
    #[serde(default)]
    pub allow_env_config_override: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            deny_exit_code: default_deny_exit_code(),
            deny_prefix: default_deny_prefix(),
            reveal_guard_name: false,
            reveal_rule_id: false,
            allow_env_config_override: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_log_path")]
    pub path: PathBuf,
    #[serde(default)]
    pub log_allows: bool,
    #[serde(default = "default_true")]
    pub log_denies: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_log_path(),
            log_allows: false,
            log_denies: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub default: PolicyAction,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: PolicyAction::Allow,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    #[default]
    Allow,
    Deny,
    Delegate,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: Option<String>,
    pub action: PolicyAction,
    pub command: Option<String>,
    #[serde(default)]
    pub commands: Vec<String>,
    pub command_regex: Option<String>,
    #[serde(default)]
    pub args_prefix: Vec<String>,
    pub argv_regex: Option<String>,
    pub shell_regex: Option<String>,
    pub cwd_regex: Option<String>,
    pub delegate: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DelegateConfig {
    #[serde(rename = "type")]
    pub kind: DelegateKind,
    #[serde(default = "default_delegate_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub on_error: DelegateOnError,
    pub script: Option<String>,
    pub command: Option<PathBuf>,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DelegateKind {
    Shell,
    Exec,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DelegateOnError {
    #[default]
    Deny,
    Allow,
    Error,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let path = expand_tilde_path(path);
        let text = std::fs::read_to_string(&path).map_err(|source| GuardError::Io {
            path: path.clone(),
            source,
        })?;
        let mut config: Config =
            toml::from_str(&text).map_err(|source| GuardError::Toml { path, source })?;
        config.expand_paths();
        config.validate()?;
        Ok(config)
    }

    pub fn load_for_management(explicit_path: Option<&Path>) -> Result<Self> {
        let path = match explicit_path {
            Some(path) => path.to_path_buf(),
            None => env::var_os(ENV_CONFIG)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
        };
        Self::load(&path)
    }

    pub fn load_for_runtime() -> Result<Self> {
        let env_path = env::var_os(ENV_CONFIG).map(PathBuf::from);
        Self::load_for_runtime_from(Path::new(DEFAULT_CONFIG_PATH), env_path.as_deref())
    }

    fn load_for_runtime_from(default_path: &Path, env_path: Option<&Path>) -> Result<Self> {
        if !default_path.exists() {
            if let Some(path) = env_path {
                return Self::load(path);
            }
        }
        let mut config = Self::load(default_path)?;
        if config.runtime.allow_env_config_override {
            if let Some(path) = env_path {
                config = Self::load(path)?;
            }
        }
        Ok(config)
    }

    fn expand_paths(&mut self) {
        self.install.bin_dir = expand_tilde_path(&self.install.bin_dir);
        self.logging.path = expand_tilde_path(&self.logging.path);
        for command in self.commands.values_mut() {
            if let Some(real_path) = &command.real_path {
                command.real_path = Some(expand_tilde_path(real_path));
            }
        }
        for delegate in self.delegates.values_mut() {
            if let Some(command) = &delegate.command {
                delegate.command = Some(expand_tilde_path(command));
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "1" {
            return Err(GuardError::InvalidConfig(format!(
                "unsupported schema_version {:?}; expected \"1\"",
                self.schema_version
            )));
        }
        if self.install.commands.is_empty() {
            return Err(GuardError::InvalidConfig(
                "install.commands must include at least one command".to_string(),
            ));
        }
        if self.policy.default == PolicyAction::Delegate {
            return Err(GuardError::InvalidConfig(
                "policy.default must be allow or deny".to_string(),
            ));
        }
        let mut seen = HashSet::new();
        for command in &self.install.commands {
            validate_command_name(command)?;
            if !seen.insert(command) {
                return Err(GuardError::InvalidConfig(format!(
                    "duplicate install command {command:?}"
                )));
            }
        }
        for name in self.commands.keys() {
            validate_command_name(name)?;
        }
        for rule in &self.policy.rules {
            if let Some(command) = &rule.command {
                validate_command_name(command)?;
            }
            for command in &rule.commands {
                validate_command_name(command)?;
            }
            if let Some(pattern) = &rule.command_regex {
                Regex::new(pattern).map_err(|source| GuardError::Regex {
                    field: "command_regex".to_string(),
                    source,
                })?;
            }
            if let Some(pattern) = &rule.argv_regex {
                Regex::new(pattern).map_err(|source| GuardError::Regex {
                    field: "argv_regex".to_string(),
                    source,
                })?;
            }
            if let Some(pattern) = &rule.shell_regex {
                Regex::new(pattern).map_err(|source| GuardError::Regex {
                    field: "shell_regex".to_string(),
                    source,
                })?;
            }
            if let Some(pattern) = &rule.cwd_regex {
                Regex::new(pattern).map_err(|source| GuardError::Regex {
                    field: "cwd_regex".to_string(),
                    source,
                })?;
            }
            match rule.action {
                PolicyAction::Delegate => {
                    let name = rule.delegate.as_deref().ok_or_else(|| {
                        GuardError::InvalidConfig(format!(
                            "delegate rule {:?} is missing delegate",
                            rule.id.as_deref().unwrap_or("<unnamed>")
                        ))
                    })?;
                    if !self.delegates.contains_key(name) {
                        return Err(GuardError::InvalidConfig(format!(
                            "rule {:?} references missing delegate {name:?}",
                            rule.id.as_deref().unwrap_or("<unnamed>")
                        )));
                    }
                }
                PolicyAction::Allow | PolicyAction::Deny => {
                    if rule.delegate.is_some() {
                        return Err(GuardError::InvalidConfig(format!(
                            "non-delegate rule {:?} must not set delegate",
                            rule.id.as_deref().unwrap_or("<unnamed>")
                        )));
                    }
                }
            }
        }
        for (name, delegate) in &self.delegates {
            match delegate.kind {
                DelegateKind::Shell => {
                    if delegate.script.as_deref().unwrap_or("").trim().is_empty() {
                        return Err(GuardError::InvalidConfig(format!(
                            "shell delegate {name:?} requires script"
                        )));
                    }
                    if delegate.command.is_some() {
                        return Err(GuardError::InvalidConfig(format!(
                            "shell delegate {name:?} must not set command"
                        )));
                    }
                }
                DelegateKind::Exec => {
                    if delegate.command.is_none() {
                        return Err(GuardError::InvalidConfig(format!(
                            "exec delegate {name:?} requires command"
                        )));
                    }
                    if delegate.script.is_some() {
                        return Err(GuardError::InvalidConfig(format!(
                            "exec delegate {name:?} must not set script"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn expand_tilde_path(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if text == "~" {
        return home_dir().unwrap_or_else(|| path.to_path_buf());
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    path.to_path_buf()
}

fn validate_command_name(command: &str) -> Result<()> {
    let valid = !command.is_empty()
        && command != "."
        && command != ".."
        && !command.starts_with('-')
        && command
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'));
    if !valid {
        return Err(GuardError::InvalidConfig(format!(
            "invalid command name {command:?}"
        )));
    }
    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

fn default_schema_version() -> String {
    "1".to_string()
}

fn default_deny_exit_code() -> i32 {
    126
}

fn default_deny_prefix() -> String {
    "blocked by policy".to_string()
}

fn default_true() -> bool {
    true
}

fn default_log_path() -> PathBuf {
    PathBuf::from("/var/log/shell-command-guard/events.log")
}

fn default_delegate_timeout_ms() -> u64 {
    2000
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn runtime_uses_env_config_when_default_is_absent() {
        let temp = TempDir::new().unwrap();
        let env_config = write_config(temp.path(), "env", false);
        let default_config = temp.path().join("missing/config.toml");

        let config =
            Config::load_for_runtime_from(&default_config, Some(env_config.as_path())).unwrap();
        assert_eq!(config.install.commands, ["env"]);
    }

    #[test]
    fn runtime_ignores_env_config_when_default_exists_without_override() {
        let temp = TempDir::new().unwrap();
        let default_config = write_config(temp.path(), "default", false);
        let env_config = write_config(&temp.path().join("env"), "env", false);

        let config =
            Config::load_for_runtime_from(default_config.as_path(), Some(env_config.as_path()))
                .unwrap();
        assert_eq!(config.install.commands, ["default"]);
    }

    #[test]
    fn runtime_uses_env_config_when_default_enables_override() {
        let temp = TempDir::new().unwrap();
        let default_config = write_config(temp.path(), "default", true);
        let env_config = write_config(&temp.path().join("env"), "env", false);

        let config =
            Config::load_for_runtime_from(default_config.as_path(), Some(env_config.as_path()))
                .unwrap();
        assert_eq!(config.install.commands, ["env"]);
    }

    fn write_config(root: &Path, command: &str, allow_env_override: bool) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        let path = root.join(format!("{command}.toml"));
        fs::write(
            &path,
            format!(
                r#"
schema_version = "1"

[install]
bin_dir = "/tmp/scg-test-bin"
commands = ["{command}"]

[runtime]
allow_env_config_override = {allow_env_override}

[logging]
enabled = false

[policy]
default = "allow"
"#
            ),
        )
        .unwrap();
        path
    }
}
