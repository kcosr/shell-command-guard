# Changelog

## [Unreleased]

_No unreleased changes._

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
