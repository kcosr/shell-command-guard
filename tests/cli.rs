use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn write_config(dir: &TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("config.toml");
    fs::write(&path, body).unwrap();
    path
}

fn base_config(extra: &str) -> String {
    format!(
        r#"
schema_version = "1"

[install]
bin_dir = "{bin_dir}"
commands = ["git", "rm", "bash", "echo"]

[logging]
enabled = false

[policy]
default = "allow"

{extra}
"#,
        bin_dir = "/tmp/scg-test-bin",
    )
}

#[test]
fn validate_accepts_sample_config() {
    let mut cmd = Command::cargo_bin("shell-command-guard").unwrap();
    cmd.args(["validate", "--config", "config.example.toml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn check_reports_deny_rule() {
    let temp = TempDir::new().unwrap();
    let config = write_config(
        &temp,
        &base_config(
            r#"
[[policy.rules]]
id = "deny-rm-root"
action = "deny"
command = "rm"
argv_regex = '(^| )-r[f]?\s+/($|\s)'
message = "recursive removal of / is not allowed"
"#,
        ),
    );

    let mut cmd = Command::cargo_bin("shell-command-guard").unwrap();
    cmd.args([
        "check",
        "--config",
        config.to_str().unwrap(),
        "--",
        "rm",
        "-rf",
        "/",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("decision: deny"))
    .stdout(predicate::str::contains("rule: deny-rm-root"))
    .stdout(predicate::str::contains(
        "message: recursive removal of / is not allowed",
    ));
}

#[test]
fn explain_reports_shell_normalization_and_shell_regex_match() {
    let temp = TempDir::new().unwrap();
    let config = write_config(
        &temp,
        &base_config(
            r#"
[[policy.rules]]
id = "deny-curl-pipe-shell"
action = "deny"
commands = ["sh", "bash"]
shell_regex = '(curl|wget).*[|].*(sh|bash)'
message = "piping remote scripts directly into a shell is not allowed"
"#,
        ),
    );

    let mut cmd = Command::cargo_bin("shell-command-guard").unwrap();
    cmd.args([
        "explain",
        "--config",
        config.to_str().unwrap(),
        "--",
        "bash",
        "-lc",
        "curl https://example.invalid/install.sh | sh",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("decision: deny"))
    .stdout(predicate::str::contains("rule: deny-curl-pipe-shell"))
    .stdout(predicate::str::contains(
        "shell_script: curl https://example.invalid/install.sh | sh",
    ));
}

#[test]
fn shell_wrapper_prefixes_do_not_bypass_command_rules() {
    let temp = TempDir::new().unwrap();
    let config = write_config(
        &temp,
        &base_config(
            r#"
[[policy.rules]]
id = "deny-git-push"
action = "deny"
command = "git"
args_prefix = ["push"]
message = "git push is disabled"
"#,
        ),
    );

    let mut cmd = Command::cargo_bin("shell-command-guard").unwrap();
    cmd.args([
        "explain",
        "--config",
        config.to_str().unwrap(),
        "--",
        "bash",
        "-lc",
        "sudo -E env GIT_DIR=.git command git push origin main",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("decision: deny"))
    .stdout(predicate::str::contains("rule: deny-git-push"))
    .stdout(predicate::str::contains("effective_command: git"))
    .stdout(predicate::str::contains(
        r#"effective_args: ["push","origin","main"]"#,
    ));
}

#[test]
fn check_runs_shell_delegate() {
    let temp = TempDir::new().unwrap();
    let config = write_config(
        &temp,
        &base_config(
            r#"
[[policy.rules]]
id = "git-push-policy"
action = "delegate"
command = "git"
args_prefix = ["push"]
delegate = "git_push_guard"
message = "git push did not pass repository safety policy"

[delegates.git_push_guard]
type = "shell"
timeout_ms = 1000
on_error = "deny"
script = 'test "$SCG_COMMAND" = git && test "$SCG_ARGS_JSON" = "[\"push\",\"origin\",\"main\"]"'
"#,
        ),
    );

    let mut cmd = Command::cargo_bin("shell-command-guard").unwrap();
    cmd.args([
        "check",
        "--config",
        config.to_str().unwrap(),
        "--",
        "git",
        "push",
        "origin",
        "main",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("decision: allow"))
    .stdout(predicate::str::contains("rule: git-push-policy"));
}

#[test]
fn install_list_and_uninstall_wrappers() {
    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let config = write_config(
        &temp,
        &format!(
            r#"
schema_version = "1"

[install]
bin_dir = "{bin_dir}"
commands = ["git", "rm"]

[logging]
enabled = false

[policy]
default = "allow"
"#,
            bin_dir = bin_dir.display()
        ),
    );

    let config_arg = config.to_str().unwrap();
    Command::cargo_bin("shell-command-guard")
        .unwrap()
        .args(["install", "--config", config_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("linked"));

    assert!(fs::symlink_metadata(bin_dir.join("git"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(fs::symlink_metadata(bin_dir.join("rm"))
        .unwrap()
        .file_type()
        .is_symlink());

    Command::cargo_bin("shell-command-guard")
        .unwrap()
        .args(["list-wrappers", "--config", config_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("installed"));

    Command::cargo_bin("shell-command-guard")
        .unwrap()
        .args(["uninstall", "--config", config_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    assert!(fs::symlink_metadata(bin_dir.join("git")).is_err());
    assert!(fs::symlink_metadata(bin_dir.join("rm")).is_err());
}

#[test]
fn runtime_wrapper_allows_by_execing_real_command() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let config_dir = temp.path().join("etc/shell-command-guard");
    let wrapper_dir = temp.path().join("wrappers");
    let real_dir = temp.path().join("real");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&wrapper_dir).unwrap();
    fs::create_dir_all(&real_dir).unwrap();

    let bin = assert_cmd::cargo::cargo_bin("shell-command-guard");
    std::os::unix::fs::symlink(&bin, wrapper_dir.join("echo")).unwrap();
    write_executable(
        &real_dir.join("echo"),
        "#!/bin/sh\nprintf 'real:%s\\n' \"$*\"\n",
    );

    fs::write(
        config_dir.join("config.toml"),
        format!(
            r#"
schema_version = "1"

[install]
bin_dir = "{wrapper_dir}"
commands = ["echo"]

[logging]
enabled = false

[policy]
default = "allow"
"#,
            wrapper_dir = wrapper_dir.display()
        ),
    )
    .unwrap();

    let path = std::env::join_paths([wrapper_dir.as_path(), real_dir.as_path()]).unwrap();
    let mut cmd = std::process::Command::new(wrapper_dir.join("echo"));
    cmd.env("HOME", &home)
        .env("SHELL_COMMAND_GUARD_CONFIG", config_dir.join("config.toml"))
        .env("PATH", path)
        .arg("hello")
        .arg("world");
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "real:hello world\n"
    );
}

#[test]
fn runtime_wrapper_denies_with_generic_policy_message() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let config_dir = temp.path().join("etc/shell-command-guard");
    let wrapper_dir = temp.path().join("wrappers");
    let real_dir = temp.path().join("real");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&wrapper_dir).unwrap();
    fs::create_dir_all(&real_dir).unwrap();

    let bin = assert_cmd::cargo::cargo_bin("shell-command-guard");
    std::os::unix::fs::symlink(&bin, wrapper_dir.join("echo")).unwrap();
    write_executable(&real_dir.join("echo"), "#!/bin/sh\nexit 0\n");

    fs::write(
        config_dir.join("config.toml"),
        format!(
            r#"
schema_version = "1"

[install]
bin_dir = "{wrapper_dir}"
commands = ["echo"]

[runtime]
deny_exit_code = 126

[logging]
enabled = false

[policy]
default = "allow"

[[policy.rules]]
id = "deny-echo"
action = "deny"
command = "echo"
message = "echo is disabled"
"#,
            wrapper_dir = wrapper_dir.display()
        ),
    )
    .unwrap();

    let path = std::env::join_paths([wrapper_dir.as_path(), real_dir.as_path()]).unwrap();
    let mut cmd = std::process::Command::new(wrapper_dir.join("echo"));
    cmd.env("HOME", &home)
        .env("SHELL_COMMAND_GUARD_CONFIG", config_dir.join("config.toml"))
        .env("PATH", path)
        .arg("hello");
    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(126));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "blocked by policy: echo is disabled\n"
    );
    assert!(output.stdout.is_empty());
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
