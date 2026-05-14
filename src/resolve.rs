use std::{
    env,
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::{
    config::{expand_tilde_path, Config},
    error::{GuardError, Result},
};

pub fn resolve_real_command(config: &Config, command: &str, guard_exe: &Path) -> Result<PathBuf> {
    if let Some(command_config) = config.commands.get(command) {
        if let Some(real_path) = &command_config.real_path {
            return ensure_not_guard(expand_tilde_path(real_path), guard_exe);
        }
    }

    let path = env::var_os("PATH").unwrap_or_default();
    let wrapper_dir = canonical_or_self(&config.install.bin_dir);
    for dir in env::split_paths(&path) {
        if same_path(&dir, &wrapper_dir) {
            continue;
        }
        let candidate = dir.join(command);
        if is_executable_file(&candidate) {
            return ensure_not_guard(candidate, guard_exe);
        }
    }
    Err(GuardError::CommandNotFound(command.to_string()))
}

pub fn path_without_wrapper_dir(config: &Config) -> OsString {
    let current = env::var_os("PATH").unwrap_or_default();
    let wrapper_dir = canonical_or_self(&config.install.bin_dir);
    let paths = env::split_paths(&current).filter(|dir| !same_path(dir, &wrapper_dir));
    env::join_paths(paths).unwrap_or(current)
}

fn ensure_not_guard(candidate: PathBuf, guard_exe: &Path) -> Result<PathBuf> {
    let candidate_canonical = canonical_or_self(&candidate);
    let guard_canonical = canonical_or_self(guard_exe);
    if same_path(&candidate_canonical, &guard_canonical) {
        return Err(GuardError::RecursiveCommand(candidate));
    }
    Ok(candidate)
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

fn same_path(left: &Path, right: &Path) -> bool {
    canonical_or_self(left) == canonical_or_self(right)
}

fn canonical_or_self(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs};

    use tempfile::TempDir;

    use crate::config::{InstallConfig, LoggingConfig, PolicyConfig, RuntimeConfig};

    use super::*;

    #[test]
    fn excludes_wrapper_dir_when_resolving() {
        let temp = TempDir::new().unwrap();
        let wrapper_dir = temp.path().join("wrapper");
        let real_dir = temp.path().join("real");
        fs::create_dir_all(&wrapper_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        let guard = wrapper_dir.join("shell-command-guard");
        let wrapper = wrapper_dir.join("git");
        let real = real_dir.join("git");
        fs::write(&guard, "#!/bin/sh\n").unwrap();
        fs::write(&wrapper, "#!/bin/sh\n").unwrap();
        fs::write(&real, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();

        let old_path = env::var_os("PATH");
        env::set_var("PATH", env::join_paths([&wrapper_dir, &real_dir]).unwrap());
        let config = Config {
            schema_version: "1".into(),
            install: InstallConfig {
                bin_dir: wrapper_dir,
                commands: vec!["git".into()],
            },
            runtime: RuntimeConfig::default(),
            logging: LoggingConfig::default(),
            policy: PolicyConfig::default(),
            delegates: HashMap::new(),
            commands: HashMap::new(),
        };

        let resolved = resolve_real_command(&config, "git", &guard).unwrap();
        assert_eq!(resolved, real);
        if let Some(path) = old_path {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }
}
