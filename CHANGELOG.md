# Changelog

## [Unreleased]

### Changed

- Changed default runtime config path to `/etc/shell-command-guard/config.toml`.
- Changed sample wrapper install directory to `/usr/local/bin` for container and system installs.
- Changed default log path to `/var/log/shell-command-guard/events.log`.
- Clarified runtime config precedence so `SHELL_COMMAND_GUARD_CONFIG` is used only when the default system config is absent or trusted config enables env override.
- Improved runtime error reporting for non-policy failures instead of labeling every failure as a policy block.
- Compiled policy regexes once per loaded config instead of recompiling during each rule predicate check.
- Tightened command-name validation for configured wrapper and rule command names.
- Preserved delegate names in decision logs and created log files with mode `0600`.
- Added distinct JSONL log event kinds for resolve, delegate, and exec runtime errors.
- Preserved rule and delegate context on resolve and exec error log events.
- Documented that deny events omit `real_command` because policy is evaluated before command resolution.
- Release automation now creates normal GitHub releases.
- Documented release download/install guidance and Linux x86_64 archive
  packaging, with source builds moved to the development workflow.

## [0.1.0] - 2026-05-14

### Added

- Initial Rust implementation.
- Added wrapper install/uninstall/list commands.
- Added local TOML config loading and validation.
- Added ordered policy evaluation with `allow`, `deny`, and `delegate`.
- Added command, command-list, command-regex, args-prefix, argv-regex, shell-regex, and cwd-regex predicates.
- Added shell and exec delegates with timeout handling and context environment variables.
- Added best-effort shell normalization for `sh -c`, `bash -c`, and `bash -lc`.
- Added shell wrapper-prefix normalization for common bypass-like forms such as `sudo git`, `env VAR=value git`, and `command git`.
- Added JSONL logging for allow/deny decisions.
- Added sample config, CLI docs, and test coverage.
