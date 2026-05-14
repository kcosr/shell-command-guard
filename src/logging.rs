use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
};

use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{config::Config, invocation::Invocation, policy::Decision};

#[derive(Debug, Serialize)]
struct Event<'a> {
    timestamp: String,
    decision: &'a str,
    rule_id: Option<&'a str>,
    command: &'a str,
    args: &'a [String],
    cwd: String,
    real_command: Option<String>,
    delegate: Option<&'a str>,
    error: Option<&'a str>,
}

pub fn log_decision(
    config: &Config,
    invocation: &Invocation,
    decision: &Decision,
    error: Option<&str>,
    delegate: Option<&str>,
) {
    if !config.logging.enabled {
        return;
    }
    let is_allow = matches!(decision, Decision::Allow { .. });
    let is_deny = matches!(decision, Decision::Deny { .. });
    if (is_allow && !config.logging.log_allows) || (is_deny && !config.logging.log_denies) {
        return;
    }
    let Some(parent) = config.logging.path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&config.logging.path)
    else {
        return;
    };
    let event = Event {
        timestamp: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
        decision: decision.action_name(),
        rule_id: decision.rule_id(),
        command: &invocation.effective_command,
        args: &invocation.effective_args,
        cwd: invocation.cwd.to_string_lossy().into_owned(),
        real_command: invocation
            .real_command
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        delegate: delegate.or(match decision {
            Decision::Delegate { delegate, .. } => Some(delegate.as_str()),
            _ => None,
        }),
        error,
    };
    if let Ok(line) = serde_json::to_string(&event) {
        let _ = writeln!(file, "{line}");
    }
}
