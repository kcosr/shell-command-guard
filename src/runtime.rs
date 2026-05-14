use std::{env, os::unix::process::CommandExt, process::Command};

use crate::{
    config::Config,
    delegate::{decision_after_delegate, run_delegate},
    error::{GuardError, Result},
    invocation::Invocation,
    logging::log_decision,
    policy::{evaluate, CompiledPolicy, Decision},
    resolve::{path_without_wrapper_dir, resolve_real_command},
};

pub fn run_wrapper(argv: Vec<String>) -> i32 {
    match run_wrapper_inner(argv) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("shell-command-guard error: {error}");
            runtime_error_exit_code(&error)
        }
    }
}

fn run_wrapper_inner(argv: Vec<String>) -> Result<i32> {
    let config = Config::load_for_runtime()?;
    let policy = CompiledPolicy::compile(&config)?;
    let guard_exe = env::current_exe()?;
    let mut invocation = Invocation::from_runtime_argv(argv)?;
    let real_command = match resolve_real_command(&config, &invocation.original_command, &guard_exe)
    {
        Ok(real_command) => real_command,
        Err(error) => {
            let error_string = error.to_string();
            let error_decision = Decision::Deny {
                rule_id: None,
                message: Some("runtime error".to_string()),
            };
            log_decision(
                &config,
                &invocation,
                &error_decision,
                Some(&error_string),
                None,
            );
            return Err(error);
        }
    };
    invocation.real_command = Some(real_command.clone());

    let mut decision = evaluate(&policy, &invocation);
    let mut delegate_name = None;
    let mut delegate_error = None;
    if let Decision::Delegate {
        rule_id, delegate, ..
    } = &decision
    {
        delegate_name = Some(delegate.clone());
        match run_delegate(&config, &invocation, rule_id.as_deref(), delegate) {
            Ok(outcome) => {
                delegate_error = outcome.error().map(str::to_string);
                decision = decision_after_delegate(&decision, outcome);
            }
            Err(error) => {
                let error_string = error.to_string();
                let error_decision = Decision::Deny {
                    rule_id: rule_id.clone(),
                    message: Some("delegate failed".to_string()),
                };
                log_decision(
                    &config,
                    &invocation,
                    &error_decision,
                    Some(&error_string),
                    delegate_name.as_deref(),
                );
                return Err(error);
            }
        }
    }

    log_decision(
        &config,
        &invocation,
        &decision,
        delegate_error.as_deref(),
        delegate_name.as_deref(),
    );
    match &decision {
        Decision::Allow { .. } => {
            let mut command = Command::new(real_command);
            command.args(&invocation.original_args);
            command.env("PATH", path_without_wrapper_dir(&config));
            let error = command.exec();
            let error = GuardError::from(error);
            let error_string = error.to_string();
            log_decision(&config, &invocation, &decision, Some(&error_string), None);
            Err(error)
        }
        Decision::Deny { .. } => {
            deny(&config, &decision);
            Ok(config.runtime.deny_exit_code)
        }
        Decision::Delegate { .. } => unreachable!("delegate decision should be resolved"),
    }
}

fn runtime_error_exit_code(error: &GuardError) -> i32 {
    match error {
        GuardError::CommandNotFound(_) => 127,
        _ => 126,
    }
}

pub fn deny(config: &Config, decision: &Decision) {
    let mut message = config.runtime.deny_prefix.clone();
    if let Decision::Deny {
        rule_id,
        message: reason,
    } = decision
    {
        if let Some(reason) = reason {
            message.push_str(": ");
            message.push_str(reason);
        }
        if config.runtime.reveal_rule_id {
            if let Some(rule_id) = rule_id {
                message.push_str(" [rule: ");
                message.push_str(rule_id);
                message.push(']');
            }
        }
    }
    if config.runtime.reveal_guard_name {
        message.push_str(" [shell-command-guard]");
    }
    eprintln!("{message}");
}
