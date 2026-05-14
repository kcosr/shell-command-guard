# shell-command-guard

`shell-command-guard` is a local command-interception utility for cooperative agent environments. It installs symlink wrappers for selected command names into a user-controlled bin directory, evaluates each invocation against a local TOML policy, and either silently execs the real command or blocks it with a generic denial message.

It is a best-effort guardrail, not a sandbox. A determined or tool-capable process can bypass it by calling the underlying executable directly, using absolute paths, changing `PATH`, copying binaries, or using an unwrapped interpreter.

## Features

- One shared Rust binary for all wrapped command names.
- Wrapper installation and removal through symlinks.
- Real command resolution that excludes the wrapper directory to avoid recursion.
- Local ordered policy rules with default `allow` or `deny`.
- Rule actions: `allow`, `deny`, `delegate`.
- Predicates for command names, argument prefixes, argv regex, shell script regex, command regex, and cwd regex.
- Best-effort shell normalization for `sh -c`, `bash -c`, and `bash -lc`.
- Lightweight wrapper-prefix normalization inside shell commands, including `sudo`, `env`, `command`, `exec`, `builtin`, `nohup`, `time`, and `nice`.
- Shell and exec delegates with timeout handling.
- Minimal runtime denial output and JSONL deny/allow logging.

## Build

```bash
cargo build --release
```

The binary is `target/release/shell-command-guard`.

## Install Binary

Install the compiled binary somewhere stable before creating command wrappers. For containers and host-level installs, use a system path:

```bash
sudo install -m 0755 target/release/shell-command-guard /usr/local/bin/shell-command-guard
```

In a container build running as root, the same install can usually be:

```bash
install -m 0755 target/release/shell-command-guard /usr/local/bin/shell-command-guard
```

A user-local install is also supported if you prefer not to write system paths:

```bash
mkdir -p ~/.local/bin
cp target/release/shell-command-guard ~/.local/bin/shell-command-guard
chmod 0755 ~/.local/bin/shell-command-guard
export PATH="$HOME/.local/bin:$PATH"
```

## Configuration

Default config path:

```text
/etc/shell-command-guard/config.toml
```

Start from the sample:

```bash
sudo mkdir -p /etc/shell-command-guard
sudo cp config.example.toml /etc/shell-command-guard/config.toml
shell-command-guard validate
```

Management commands resolve config as `--config`, then `SHELL_COMMAND_GUARD_CONFIG`, then the default path.

Runtime wrapper mode prefers the default system config path. If `/etc/shell-command-guard/config.toml` is absent, it may use `SHELL_COMMAND_GUARD_CONFIG`; this is useful for tests, containers, and mounted config files. If the default system config exists, `SHELL_COMMAND_GUARD_CONFIG` is intentionally ignored in wrapper mode unless that trusted config sets:

```toml
[runtime]
allow_env_config_override = true
```

## Install Wrappers

Configure commands and bin directory:

```toml
[install]
bin_dir = "/usr/local/bin"
commands = ["git", "rm", "curl", "wget", "bash", "sh"]
```

Install:

```bash
shell-command-guard install
shell-command-guard list-wrappers
```

Then put the wrapper directory first in `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Each wrapper is a symlink:

```text
/usr/local/bin/git -> /usr/local/bin/shell-command-guard
```

The guard determines the requested command from `argv[0]`.

Smoke-test policy evaluation before relying on wrappers:

```bash
shell-command-guard check -- rm -rf /
shell-command-guard explain -- bash -lc "sudo -E env GIT_DIR=.git command git push origin main"
```

## CLI

```text
shell-command-guard install [--config PATH] [--bin-dir PATH] [--dry-run] [--force]
shell-command-guard uninstall [--config PATH] [--bin-dir PATH] [--dry-run]
shell-command-guard validate [--config PATH]
shell-command-guard check [--config PATH] -- <command> [args...]
shell-command-guard explain [--config PATH] -- <command> [args...]
shell-command-guard list-wrappers [--config PATH] [--bin-dir PATH]
```

`check` evaluates a sample command without executing it. `explain` adds normalized invocation details for debugging.

## Policy

Rules are evaluated in order. A rule matches only when all configured predicates match. `allow` and `deny` are terminal. `delegate` runs a configured delegate; exit code `0` allows and any non-zero code denies.

For direct commands and normalized shell commands, command predicates match the effective command. For rules that set `shell_regex`, command predicates match the original shell command (`sh` or `bash`) so outer-shell policies can be expressed directly.

Shell normalization also strips common execution wrappers before matching, so a rule for `command = "git"` still applies to simple forms such as:

```bash
bash -lc "sudo -E env GIT_DIR=.git command git push origin main"
```

`command -v git` and `command -V git` are treated as query forms, not wrapper execution.

```toml
[policy]
default = "allow"

[[policy.rules]]
id = "deny-rm-root"
action = "deny"
command = "rm"
argv_regex = '(^| )-r[f]?\s+/($|\s)'
message = "recursive removal of / is not allowed"
```

Runtime denial output is intentionally terse:

```text
blocked by policy: recursive removal of / is not allowed
```

## Delegates

Delegates run in the original current working directory and receive context through environment variables:

```text
SCG_COMMAND
SCG_ARGS_JSON
SCG_ARGV_JSON
SCG_ARGV_STRING
SCG_CWD
SCG_RULE_ID
SCG_ORIGINAL_COMMAND
SCG_ORIGINAL_ARGV_JSON
SCG_SHELL_SCRIPT
SCG_REAL_COMMAND
```

Shell delegate:

```toml
[[policy.rules]]
id = "git-push-policy"
action = "delegate"
command = "git"
args_prefix = ["push"]
delegate = "git_push_guard"
message = "git push did not pass repository safety policy"

[delegates.git_push_guard]
type = "shell"
timeout_ms = 2000
on_error = "deny"
script = '''
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
case "$branch" in
  main|master) exit 1 ;;
esac
exit 0
'''
```

Exec delegate:

```toml
[delegates.custom_git_policy]
type = "exec"
command = "/etc/shell-command-guard/delegates/git-policy"
args = ["--protected", "main", "--protected", "master"]
timeout_ms = 2000
on_error = "deny"
```

## Real Command Resolution

By default, the guard searches `PATH` after removing the wrapper bin directory. Explicit paths are supported for predictable deployments:

```toml
[commands.git]
real_path = "/usr/bin/git"
```

Resolution refuses to execute a path that points back to the guard binary.

## Logging

Default logging records denials only:

```toml
[logging]
enabled = true
path = "/var/log/shell-command-guard/events.log"
log_allows = false
log_denies = true
```

Events are JSON Lines and include an event `kind`, decision, rule id, command, args, cwd, real command path, delegate name, and errors when available. Runtime failures use `decision = "error"` with a specific `kind` such as `resolve_error`, `delegate_error`, or `exec_error` so policy denials can be counted separately from operational failures.

Log files are created with mode `0600` when the guard creates them. Events can still contain sensitive command arguments, paths, and environment-derived context, so choose the log path and retention policy accordingly.

## Development

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

## Project Structure

- `src/main.rs` - process entry point.
- `src/cli.rs` - management commands and wrapper-mode dispatch.
- `src/config.rs` - TOML config loading, defaults, validation, and path expansion.
- `src/invocation.rs` - runtime argv capture, shell normalization, and wrapper-prefix normalization.
- `src/policy.rs` - ordered rule evaluation and policy decisions.
- `src/delegate.rs` - shell/exec delegate execution, timeout handling, and context environment.
- `src/resolve.rs` - real command resolution while excluding wrapper directories.
- `src/runtime.rs` - wrapper-mode allow/deny/delegate execution flow.
- `src/install.rs` - symlink install, uninstall, and wrapper listing.
- `src/logging.rs` - JSONL decision logging.
- `tests/cli.rs` - CLI and runtime-wrapper integration tests.

## Release Process

Releases use the same lightweight Node script convention as the sibling Rust projects:

```bash
node scripts/release.mjs patch
node scripts/release.mjs minor
node scripts/release.mjs major
```

The script requires a clean worktree, bumps `Cargo.toml` and `Cargo.lock`, promotes `## [Unreleased]` in `CHANGELOG.md` to a dated release section, commits, tags, pushes, creates a GitHub prerelease from the changelog notes, then opens a fresh `## [Unreleased]` section.

## Security Notes

This tool is designed for cooperative or semi-cooperative local workflows. It is best effort and screens commands that flow through its wrappers; it does not make execution mandatory. An agent or process can still call the underlying executable directly, for example `/usr/bin/git`, if the environment allows it.

It also does not prevent `PATH` manipulation, copied binaries, unwrapped interpreters, complex shell constructs, or config tampering when filesystem permissions allow it. For stronger isolation, combine it with container, VM, or OS-level restrictions.
