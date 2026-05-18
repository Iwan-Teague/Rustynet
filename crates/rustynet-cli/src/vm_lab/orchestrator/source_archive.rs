#![allow(dead_code)]
use std::path::{Path, PathBuf};

use crate::vm_lab::orchestrator::error::AdapterError;

/// A local tarball of the working tree to be shipped to remote nodes.
/// Constructed once at the start of an orchestration run.
#[derive(Debug, Clone)]
pub struct SourceArchive {
    pub path: PathBuf,
}

impl SourceArchive {
    /// Wrap an existing archive. Returns `Err` if the path does not exist.
    pub fn from_existing(path: PathBuf) -> Result<Self, AdapterError> {
        if !path.exists() {
            return Err(AdapterError::InvalidPath {
                path,
                reason: "source archive path does not exist".to_owned(),
            });
        }
        Ok(SourceArchive { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
