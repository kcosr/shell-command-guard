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

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    default: PolicyAction,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule: RuleConfig,
    command_regex: Option<Regex>,
    argv_regex: Option<Regex>,
    shell_regex: Option<Regex>,
    cwd_regex: Option<Regex>,
}

impl CompiledPolicy {
    pub fn compile(config: &Config) -> Result<Self> {
        let mut rules = Vec::with_capacity(config.policy.rules.len());
        for rule in &config.policy.rules {
            if rule.action == PolicyAction::Delegate && rule.delegate.is_none() {
                return Err(GuardError::InvalidConfig(format!(
                    "delegate rule {:?} is missing delegate",
                    rule.id.as_deref().unwrap_or("<unnamed>")
                )));
            }
            rules.push(CompiledRule {
                rule: rule.clone(),
                command_regex: compile_regex(rule.command_regex.as_deref(), "command_regex")?,
                argv_regex: compile_regex(rule.argv_regex.as_deref(), "argv_regex")?,
                shell_regex: compile_regex(rule.shell_regex.as_deref(), "shell_regex")?,
                cwd_regex: compile_regex(rule.cwd_regex.as_deref(), "cwd_regex")?,
            });
        }
        Ok(Self {
            default: config.policy.default,
            rules,
        })
    }
}

pub fn evaluate(policy: &CompiledPolicy, invocation: &Invocation) -> Decision {
    for rule in &policy.rules {
        if rule_matches(rule, invocation) {
            return rule_decision(rule);
        }
    }
    match policy.default {
        PolicyAction::Allow => Decision::Allow { rule_id: None },
        PolicyAction::Deny => Decision::Deny {
            rule_id: None,
            message: None,
        },
        PolicyAction::Delegate => unreachable!("policy.default cannot deserialize to delegate"),
    }
}

fn rule_decision(rule: &CompiledRule) -> Decision {
    let rule = &rule.rule;
    let rule_id = rule.id.clone();
    let message = rule.message.clone();
    match rule.action {
        PolicyAction::Allow => Decision::Allow { rule_id },
        PolicyAction::Deny => Decision::Deny { rule_id, message },
        PolicyAction::Delegate => Decision::Delegate {
            rule_id,
            delegate: rule.delegate.clone().unwrap_or_default(),
            message,
        },
    }
}

fn rule_matches(compiled: &CompiledRule, invocation: &Invocation) -> bool {
    let rule = &compiled.rule;
    let command_for_predicates = if compiled.shell_regex.is_some() {
        &invocation.original_command
    } else {
        &invocation.effective_command
    };
    if let Some(command) = &rule.command {
        if command_for_predicates != command {
            return false;
        }
    }
    if !rule.commands.is_empty()
        && !rule
            .commands
            .iter()
            .any(|command| command == command_for_predicates)
    {
        return false;
    }
    if let Some(pattern) = &compiled.command_regex {
        if !pattern.is_match(command_for_predicates) {
            return false;
        }
    }
    if !rule.args_prefix.is_empty() {
        if invocation.effective_args.len() < rule.args_prefix.len() {
            return false;
        }
        if invocation.effective_args[..rule.args_prefix.len()] != rule.args_prefix {
            return false;
        }
    }
    if let Some(pattern) = &compiled.argv_regex {
        if !pattern.is_match(&invocation.argv_string()) {
            return false;
        }
    }
    if let Some(pattern) = &compiled.shell_regex {
        let Some(script) = &invocation.shell_script else {
            return false;
        };
        if !pattern.is_match(script) {
            return false;
        }
    }
    if let Some(pattern) = &compiled.cwd_regex {
        if !pattern.is_match(&invocation.cwd.to_string_lossy()) {
            return false;
        }
    }
    true
}

fn compile_regex(pattern: Option<&str>, field: &str) -> Result<Option<Regex>> {
    pattern
        .map(|pattern| {
            Regex::new(pattern).map_err(|source| GuardError::Regex {
                field: field.to_string(),
                source,
            })
        })
        .transpose()
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
        let policy = CompiledPolicy::compile(&config).unwrap();
        assert_eq!(
            evaluate(&policy, &invocation),
            Decision::Deny {
                rule_id: Some("first".into()),
                message: Some("no push".into())
            }
        );
    }
}
