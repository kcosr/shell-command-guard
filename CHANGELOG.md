# Changelog

## [Unreleased]

### Changed

- Changed default runtime config path to `/etc/shell-command-guard/config.toml`.
- Changed sample wrapper install directory to `/usr/local/bin` for container and system installs.
- Changed default log path to `/var/log/shell-command-guard/events.log`.
- Clarified runtime config precedence so `SHELL_COMMAND_GUARD_CONFIG` is used only when the default system config is absent or trusted config enables env override.

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
