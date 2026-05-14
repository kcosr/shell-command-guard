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
    kind: &'a str,
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
    write_event(
        config,
        invocation,
        "decision",
        decision.action_name(),
        decision.rule_id(),
        error,
        delegate,
    );
}

pub fn log_error(
    config: &Config,
    invocation: &Invocation,
    kind: &'static str,
    rule_id: Option<&str>,
    error: &str,
    delegate: Option<&str>,
) {
    write_event(
        config,
        invocation,
        kind,
        "error",
        rule_id,
        Some(error),
        delegate,
    );
}

fn write_event(
    config: &Config,
    invocation: &Invocation,
    kind: &'static str,
    decision: &'static str,
    rule_id: Option<&str>,
    error: Option<&str>,
    delegate: Option<&str>,
) {
    if !config.logging.enabled {
        return;
    }
    let is_allow = decision == "allow";
    let is_deny = decision == "deny";
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
        kind,
        decision,
        rule_id,
        command: &invocation.effective_command,
        args: &invocation.effective_args,
        cwd: invocation.cwd.to_string_lossy().into_owned(),
        real_command: invocation
            .real_command
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        delegate,
        error,
    };
    if let Ok(line) = serde_json::to_string(&event) {
        let _ = writeln!(file, "{line}");
    }
}
