use regex::Regex;

use crate::{
    config::{Config, PolicyAction, RuleConfig},
    error::{GuardError, Result},
    invocation::Invocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow {
        rule_id: Option<String>,
    },
    Deny {
        rule_id: Option<String>,
        message: Option<String>,
    },
    Delegate {
        rule_id: Option<String>,
        delegate: String,
        message: Option<String>,
    },
}

impl Decision {
    pub fn action_name(&self) -> &'static str {
        match self {
            Decision::Allow { .. } => "allow",
            Decision::Deny { .. } => "deny",
            Decision::Delegate { .. } => "delegate",
        }
    }

    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Decision::Allow { rule_id }
            | Decision::Deny { rule_id, .. }
            | Decision::Delegate { rule_id, .. } => rule_id.as_deref(),
        }
    }
}

pub fn evaluate(config: &Config, invocation: &Invocation) -> Result<Decision> {
    for rule in &config.policy.rules {
        if rule_matches(rule, invocation)? {
            return rule_decision(rule);
        }
    }
    Ok(match config.policy.default {
        PolicyAction::Allow => Decision::Allow { rule_id: None },
        PolicyAction::Deny => Decision::Deny {
            rule_id: None,
            message: None,
        },
        PolicyAction::Delegate => unreachable!("policy.default cannot deserialize to delegate"),
    })
}

fn rule_decision(rule: &RuleConfig) -> Result<Decision> {
    let rule_id = rule.id.clone();
    let message = rule.message.clone();
    Ok(match rule.action {
        PolicyAction::Allow => Decision::Allow { rule_id },
        PolicyAction::Deny => Decision::Deny { rule_id, message },
        PolicyAction::Delegate => Decision::Delegate {
            rule_id,
            delegate: rule.delegate.clone().ok_or_else(|| {
                GuardError::InvalidConfig("delegate rule missing delegate".into())
            })?,
            message,
        },
    })
}

fn rule_matches(rule: &RuleConfig, invocation: &Invocation) -> Result<bool> {
    let command_for_predicates = if rule.shell_regex.is_some() {
        &invocation.original_command
    } else {
        &invocation.effective_command
    };
    if let Some(command) = &rule.command {
        if command_for_predicates != command {
            return Ok(false);
        }
    }
    if !rule.commands.is_empty()
        && !rule
            .commands
            .iter()
            .any(|command| command == command_for_predicates)
    {
        return Ok(false);
    }
    if let Some(pattern) = &rule.command_regex {
        if !Regex::new(pattern)
            .map_err(|source| GuardError::Regex {
                field: "command_regex".to_string(),
                source,
            })?
            .is_match(command_for_predicates)
        {
            return Ok(false);
        }
    }
    if !rule.args_prefix.is_empty() {
        if invocation.effective_args.len() < rule.args_prefix.len() {
            return Ok(false);
        }
        if invocation.effective_args[..rule.args_prefix.len()] != rule.args_prefix {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.argv_regex {
        if !Regex::new(pattern)
            .map_err(|source| GuardError::Regex {
                field: "argv_regex".to_string(),
                source,
            })?
            .is_match(&invocation.argv_string())
        {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.shell_regex {
        let Some(script) = &invocation.shell_script else {
            return Ok(false);
        };
        if !Regex::new(pattern)
            .map_err(|source| GuardError::Regex {
                field: "shell_regex".to_string(),
                source,
            })?
            .is_match(script)
        {
            return Ok(false);
        }
    }
    if let Some(pattern) = &rule.cwd_regex {
        if !Regex::new(pattern)
            .map_err(|source| GuardError::Regex {
                field: "cwd_regex".to_string(),
                source,
            })?
            .is_match(&invocation.cwd.to_string_lossy())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf};

    use crate::config::{InstallConfig, LoggingConfig, PolicyConfig, RuntimeConfig};

    use super::*;

    fn config_with_rules(rules: Vec<RuleConfig>) -> Config {
        Config {
            schema_version: "1".into(),
            install: InstallConfig {
                bin_dir: PathBuf::from("/tmp/bin"),
                commands: vec!["git".into()],
            },
            runtime: RuntimeConfig::default(),
            logging: LoggingConfig::default(),
            policy: PolicyConfig {
                default: PolicyAction::Allow,
                rules,
            },
            delegates: HashMap::new(),
            commands: HashMap::new(),
        }
    }

    #[test]
    fn ordered_rules_return_first_match() {
        let config = config_with_rules(vec![
            RuleConfig {
                id: Some("first".into()),
                action: PolicyAction::Deny,
                command: Some("git".into()),
                commands: vec![],
                command_regex: None,
                args_prefix: vec!["push".into()],
                argv_regex: None,
                shell_regex: None,
                cwd_regex: None,
                delegate: None,
                message: Some("no push".into()),
            },
            RuleConfig {
                id: Some("second".into()),
                action: PolicyAction::Allow,
                command: Some("git".into()),
                commands: vec![],
                command_regex: None,
                args_prefix: vec![],
                argv_regex: None,
                shell_regex: None,
                cwd_regex: None,
                delegate: None,
                message: None,
            },
        ]);
        let invocation = Invocation::new("git".into(), vec!["push".into()]).unwrap();
        assert_eq!(
            evaluate(&config, &invocation).unwrap(),
            Decision::Deny {
                rule_id: Some("first".into()),
                message: Some("no push".into())
            }
        );
    }
}
