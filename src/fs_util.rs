use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn canonical_or_self(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
