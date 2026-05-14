use std::{
    fs,
    os::unix::fs as unix_fs,
    path::{Path, PathBuf},
};

use crate::{
    config::Config,
    error::{GuardError, Result},
    fs_util::canonical_or_self,
};

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub bin_dir: Option<PathBuf>,
    pub dry_run: bool,
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct UninstallOptions {
    pub bin_dir: Option<PathBuf>,
    pub dry_run: bool,
}

pub fn install_wrappers(
    config: &Config,
    guard_exe: &Path,
    options: &InstallOptions,
) -> Result<Vec<String>> {
    let bin_dir = options
        .bin_dir
        .as_deref()
        .unwrap_or(&config.install.bin_dir)
        .to_path_buf();
    let mut actions = Vec::new();
    if !options.dry_run {
        fs::create_dir_all(&bin_dir).map_err(|source| GuardError::Io {
            path: bin_dir.clone(),
            source,
        })?;
    }

    for command in &config.install.commands {
        let link = bin_dir.join(command);
        if options.dry_run {
            actions.push(format!(
                "would link {} -> {}",
                link.display(),
                guard_exe.display()
            ));
            continue;
        }
        if link.exists() || fs::symlink_metadata(&link).is_ok() {
            if link_points_to(&link, guard_exe) {
                actions.push(format!("exists {}", link.display()));
                continue;
            }
            if !options.force {
                return Err(GuardError::InvalidConfig(format!(
                    "{} already exists and is not a shell-command-guard wrapper",
                    link.display()
                )));
            }
            let metadata = fs::symlink_metadata(&link).map_err(|source| GuardError::Io {
                path: link.clone(),
                source,
            })?;
            if !metadata.file_type().is_symlink() {
                return Err(GuardError::InvalidConfig(format!(
                    "--force refuses to replace non-symlink {}",
                    link.display()
                )));
            }
            fs::remove_file(&link).map_err(|source| GuardError::Io {
                path: link.clone(),
                source,
            })?;
        }
        unix_fs::symlink(guard_exe, &link).map_err(|source| GuardError::Io {
            path: link.clone(),
            source,
        })?;
        actions.push(format!(
            "linked {} -> {}",
            link.display(),
            guard_exe.display()
        ));
    }
    Ok(actions)
}

pub fn uninstall_wrappers(
    config: &Config,
    guard_exe: &Path,
    options: &UninstallOptions,
) -> Result<Vec<String>> {
    let bin_dir = options
        .bin_dir
        .as_deref()
        .unwrap_or(&config.install.bin_dir)
        .to_path_buf();
    let mut actions = Vec::new();
    for command in &config.install.commands {
        let link = bin_dir.join(command);
        if !link.exists() && fs::symlink_metadata(&link).is_err() {
            continue;
        }
        if !link_points_to(&link, guard_exe) {
            actions.push(format!("skipped {}", link.display()));
            continue;
        }
        if options.dry_run {
            actions.push(format!("would remove {}", link.display()));
            continue;
        }
        fs::remove_file(&link).map_err(|source| GuardError::Io {
            path: link.clone(),
            source,
        })?;
        actions.push(format!("removed {}", link.display()));
    }
    Ok(actions)
}

pub fn list_wrappers(config: &Config, guard_exe: &Path, bin_dir: Option<&Path>) -> Vec<String> {
    let bin_dir = bin_dir.unwrap_or(&config.install.bin_dir);
    config
        .install
        .commands
        .iter()
        .map(|command| {
            let link = bin_dir.join(command);
            let status = if link_points_to(&link, guard_exe) {
                "installed"
            } else if fs::symlink_metadata(&link).is_ok() {
                "present-other"
            } else {
                "missing"
            };
            format!("{status}\t{}", link.display())
        })
        .collect()
}

fn link_points_to(link: &Path, target: &Path) -> bool {
    let Ok(actual) = fs::read_link(link) else {
        return false;
    };
    canonical_or_self(&actual) == canonical_or_self(target)
}
