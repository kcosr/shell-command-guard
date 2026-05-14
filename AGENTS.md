# Repository Conventions (shell-command-guard)

## What This Repo Is

`shell-command-guard` is a Rust command wrapper guard. It installs symlink wrappers for selected command names, evaluates local TOML policy rules, and either silently execs the real command or blocks it with minimal agent-facing output.

## Fast Bootstrap

1. Build: `cargo build`
2. Format: `cargo fmt`
3. Lint: `cargo clippy --all-targets -- -D warnings`
4. Test: `cargo test`
5. Release build: `cargo build --release`
6. Validate sample config: `cargo run -- validate --config config.example.toml`

## Source Map

- `src/main.rs` - process entry point.
- `src/cli.rs` - management commands and wrapper-mode dispatch.
- `src/config.rs` - TOML config structs, defaults, validation, and path expansion.
- `src/invocation.rs` - argv capture, shell normalization, and wrapper-prefix normalization.
- `src/policy.rs` - ordered policy evaluation.
- `src/delegate.rs` - shell/exec delegate execution with timeout and context env vars.
- `src/resolve.rs` - real-command lookup while excluding the wrapper directory.
- `src/runtime.rs` - runtime wrapper allow/deny/delegate flow.
- `src/install.rs` - symlink install, uninstall, and listing.
- `src/logging.rs` - JSONL decision logging.
- `tests/cli.rs` - integration coverage for CLI and symlink wrapper behavior.

## Working Rules

1. Prefer the current v1 config shape only; do not add compatibility aliases, bridge fields, or dual-shape parsers.
2. Runtime wrapper output must stay minimal. Detailed diagnostics belong in management commands or logs.
3. Runtime config precedence is intentionally conservative: use `/etc/shell-command-guard/config.toml` when present; only use `SHELL_COMMAND_GUARD_CONFIG` when the default is absent or the trusted config enables `runtime.allow_env_config_override`.
4. Tests must be deterministic and offline.
5. For behavior changes, add or update tests and update `README.md`.
6. Run `cargo fmt --check`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo build --release` before considering broad changes complete.

## Commands You'll Use Often

- Build: `cargo build`
- Test: `cargo test`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt`
- Validate sample config: `cargo run -- validate --config config.example.toml`
- Check a command: `cargo run -- check --config config.example.toml -- rm -rf /`
- Explain matching: `cargo run -- explain --config config.example.toml -- bash -lc "sudo git push"`
- Release build: `cargo build --release`

## Changelog

Location: `CHANGELOG.md` (root)

### Format

Use these sections under `## [Unreleased]`:
- `### Breaking Changes` - config or behavior changes requiring migration
- `### Added` - New features
- `### Changed` - Changes to existing functionality
- `### Fixed` - Bug fixes
- `### Removed` - Removed features

### Rules

- New entries always go under `## [Unreleased]`.
- Append to existing subsections; do not create duplicates.
- Do not modify already-released version sections unless correcting a clear typo.
- User-facing changes should have concise changelog entries.

## Releasing

Use `scripts/release.mjs` as the release entrypoint:

```bash
node scripts/release.mjs patch
node scripts/release.mjs minor
node scripts/release.mjs major
```

The script verifies a clean worktree, bumps `Cargo.toml` and `Cargo.lock`, updates `CHANGELOG.md`, commits, tags, pushes, creates a GitHub prerelease, then opens a fresh `## [Unreleased]` section.
