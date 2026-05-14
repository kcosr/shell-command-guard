use std::{
    process::{Command, Stdio},
    time::Duration,
};

use wait_timeout::ChildExt;

use crate::{
    config::{Config, DelegateKind, DelegateOnError},
    error::{GuardError, Result},
    invocation::Invocation,
    policy::Decision,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegateOutcome {
    Allow {
        exit_code: Option<i32>,
    },
    Deny {
        exit_code: Option<i32>,
        error: Option<String>,
    },
}

impl DelegateOutcome {
    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Deny {
                error: Some(error), ..
            } => Some(error),
            Self::Allow { .. } | Self::Deny { error: None, .. } => None,
        }
    }
}

pub fn run_delegate(
    config: &Config,
    invocation: &Invocation,
    rule_id: Option<&str>,
    delegate_name: &str,
) -> Result<DelegateOutcome> {
    let delegate = config
        .delegates
        .get(delegate_name)
        .ok_or_else(|| GuardError::DelegateNotFound(delegate_name.to_string()))?;

    let mut command = match delegate.kind {
        DelegateKind::Shell => {
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg(delegate.script.as_deref().unwrap_or(""));
            command
        }
        DelegateKind::Exec => {
            let mut command = Command::new(delegate.command.as_ref().ok_or_else(|| {
                GuardError::InvalidConfig(format!(
                    "exec delegate {delegate_name:?} missing command"
                ))
            })?);
            command.args(&delegate.args);
            command
        }
    };

    command
        .current_dir(&invocation.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    add_context_env(&mut command, invocation, rule_id);

    match run_with_timeout(command, Duration::from_millis(delegate.timeout_ms)) {
        Ok(Some(code)) if code == 0 => Ok(DelegateOutcome::Allow {
            exit_code: Some(code),
        }),
        Ok(code) => Ok(DelegateOutcome::Deny {
            exit_code: code,
            error: None,
        }),
        Err(err @ GuardError::DelegateTimedOut(_)) | Err(err @ GuardError::DelegateFailed(_)) => {
            match delegate.on_error {
                DelegateOnError::Allow => Ok(DelegateOutcome::Allow { exit_code: None }),
                DelegateOnError::Deny => Ok(DelegateOutcome::Deny {
                    exit_code: None,
                    error: Some(err.to_string()),
                }),
                DelegateOnError::Error => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

pub fn decision_after_delegate(delegate_decision: &Decision, outcome: DelegateOutcome) -> Decision {
    match (delegate_decision, outcome) {
        (Decision::Delegate { rule_id, .. }, DelegateOutcome::Allow { .. }) => Decision::Allow {
            rule_id: rule_id.clone(),
        },
        (
            Decision::Delegate {
                rule_id, message, ..
            },
            DelegateOutcome::Deny { .. },
        ) => Decision::Deny {
            rule_id: rule_id.clone(),
            message: message.clone(),
        },
        (decision, _) => decision.clone(),
    }
}

fn run_with_timeout(mut command: Command, timeout: Duration) -> Result<Option<i32>> {
    let mut child = command
        .spawn()
        .map_err(|source| GuardError::DelegateFailed(source.to_string()))?;
    match child
        .wait_timeout(timeout)
        .map_err(|source| GuardError::DelegateFailed(source.to_string()))?
    {
        Some(status) => Ok(status.code()),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Err(GuardError::DelegateTimedOut(format!(
                "exceeded {}ms",
                timeout.as_millis()
            )))
        }
    }
}

fn add_context_env(command: &mut Command, invocation: &Invocation, rule_id: Option<&str>) {
    command.env("SCG_COMMAND", &invocation.effective_command);
    command.env(
        "SCG_ARGS_JSON",
        serde_json::to_string(&invocation.effective_args).unwrap_or_else(|_| "[]".to_string()),
    );
    command.env(
        "SCG_ARGV_JSON",
        serde_json::to_string(&invocation.effective_argv()).unwrap_or_else(|_| "[]".to_string()),
    );
    command.env("SCG_ARGV_STRING", invocation.argv_string());
    command.env("SCG_CWD", &invocation.cwd);
    command.env("SCG_ORIGINAL_COMMAND", &invocation.original_command);
    command.env(
        "SCG_ORIGINAL_ARGV_JSON",
        serde_json::to_string(&invocation.original_argv).unwrap_or_else(|_| "[]".to_string()),
    );
    if let Some(rule_id) = rule_id {
        command.env("SCG_RULE_ID", rule_id);
    }
    if let Some(shell_script) = &invocation.shell_script {
        command.env("SCG_SHELL_SCRIPT", shell_script);
    }
    if let Some(real_command) = &invocation.real_command {
        command.env("SCG_REAL_COMMAND", real_command);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf};

    use crate::config::{
        DelegateConfig, InstallConfig, LoggingConfig, PolicyConfig, RuntimeConfig,
    };

    use super::*;

    fn config_with_delegate(script: &str) -> Config {
        config_with_delegate_options(script, 1000, DelegateOnError::Deny)
    }

    fn config_with_delegate_options(
        script: &str,
        timeout_ms: u64,
        on_error: DelegateOnError,
    ) -> Config {
        let mut delegates = HashMap::new();
        delegates.insert(
            "check".into(),
            DelegateConfig {
                kind: DelegateKind::Shell,
                timeout_ms,
                on_error,
                script: Some(script.into()),
                command: None,
                args: vec![],
            },
        );
        Config {
            schema_version: "1".into(),
            install: InstallConfig {
                bin_dir: PathBuf::from("/tmp/bin"),
                commands: vec!["git".into()],
            },
            runtime: RuntimeConfig::default(),
            logging: LoggingConfig::default(),
            policy: PolicyConfig::default(),
            delegates,
            commands: HashMap::new(),
        }
    }

    #[test]
    fn shell_delegate_exit_zero_allows() {
        let config = config_with_delegate("test \"$SCG_COMMAND\" = git");
        let invocation = Invocation::new("git".into(), vec!["status".into()]).unwrap();
        let outcome = run_delegate(&config, &invocation, Some("r1"), "check").unwrap();
        assert!(matches!(outcome, DelegateOutcome::Allow { .. }));
    }

    #[test]
    fn shell_delegate_nonzero_denies() {
        let config = config_with_delegate("exit 7");
        let invocation = Invocation::new("git".into(), vec!["status".into()]).unwrap();
        let outcome = run_delegate(&config, &invocation, Some("r1"), "check").unwrap();
        assert!(matches!(
            outcome,
            DelegateOutcome::Deny {
                exit_code: Some(7),
                error: None
            }
        ));
    }

    #[test]
    fn delegate_timeout_allows_when_configured() {
        let config = config_with_delegate_options("sleep 1", 10, DelegateOnError::Allow);
        let invocation = Invocation::new("git".into(), vec!["status".into()]).unwrap();
        let outcome = run_delegate(&config, &invocation, Some("r1"), "check").unwrap();
        assert!(matches!(
            outcome,
            DelegateOutcome::Allow { exit_code: None }
        ));
    }

    #[test]
    fn delegate_timeout_denies_when_configured() {
        let config = config_with_delegate_options("sleep 1", 10, DelegateOnError::Deny);
        let invocation = Invocation::new("git".into(), vec!["status".into()]).unwrap();
        let outcome = run_delegate(&config, &invocation, Some("r1"), "check").unwrap();
        assert!(matches!(
            outcome,
            DelegateOutcome::Deny {
                exit_code: None,
                error: Some(_)
            }
        ));
    }

    #[test]
    fn delegate_timeout_errors_when_configured() {
        let config = config_with_delegate_options("sleep 1", 10, DelegateOnError::Error);
        let invocation = Invocation::new("git".into(), vec!["status".into()]).unwrap();
        let error = run_delegate(&config, &invocation, Some("r1"), "check").unwrap_err();
        assert!(matches!(error, GuardError::DelegateTimedOut(_)));
    }
}
