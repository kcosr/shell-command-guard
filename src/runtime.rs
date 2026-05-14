use std::{env, os::unix::process::CommandExt, process::Command};

use crate::{
    config::Config,
    delegate::{decision_after_delegate, run_delegate},
    error::Result,
    invocation::Invocation,
    logging::log_decision,
    policy::{evaluate, Decision},
    resolve::{path_without_wrapper_dir, resolve_real_command},
};

pub fn run_wrapper(argv: Vec<String>) -> i32 {
    match run_wrapper_inner(argv) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("blocked by policy");
            let _ = error;
            126
        }
    }
}

fn run_wrapper_inner(argv: Vec<String>) -> Result<i32> {
    let config = Config::load_for_runtime()?;
    let guard_exe = env::current_exe()?;
    let mut invocation = Invocation::from_runtime_argv(argv)?;
    let real_command = resolve_real_command(&config, &invocation.original_command, &guard_exe)?;
    invocation.real_command = Some(real_command.clone());

    let mut decision = evaluate(&config, &invocation)?;
    if let Decision::Delegate {
        rule_id, delegate, ..
    } = &decision
    {
        match run_delegate(&config, &invocation, rule_id.as_deref(), delegate) {
            Ok(outcome) => decision = decision_after_delegate(&decision, outcome),
            Err(error) => {
                decision = Decision::Deny {
                    rule_id: rule_id.clone(),
                    message: None,
                };
                log_decision(&config, &invocation, &decision, Some(&error.to_string()));
                deny(&config, &decision);
                return Ok(config.runtime.deny_exit_code);
            }
        }
    }

    log_decision(&config, &invocation, &decision, None);
    match decision {
        Decision::Allow { .. } => {
            let mut command = Command::new(real_command);
            command.args(&invocation.original_args);
            command.env("PATH", path_without_wrapper_dir(&config));
            let error = command.exec();
            Err(error.into())
        }
        Decision::Deny { .. } => {
            deny(&config, &decision);
            Ok(config.runtime.deny_exit_code)
        }
        Decision::Delegate { .. } => unreachable!("delegate decision should be resolved"),
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
