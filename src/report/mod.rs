pub mod html;
pub mod json;

pub use html::*;
pub use json::*;

use crate::core::StageError;
use crate::manifest::Manifest;
use std::fs;
use std::path::{Path, PathBuf};

pub fn load_scan_manifest(
    scan_id_or_path: &str,
    search_dirs: &[&Path],
) -> Result<Manifest, StageError> {
    let direct_path = PathBuf::from(scan_id_or_path);
    if direct_path.exists() {
        let data = fs::read(&direct_path).map_err(|e| {
            StageError::Io(format!(
                "failed to read manifest file {}: {e}",
                direct_path.display()
            ))
        })?;
        return serde_json::from_slice(&data).map_err(|e| {
            StageError::Parse(format!(
                "failed to parse manifest JSON in {}: {e}",
                direct_path.display()
            ))
        });
    }

    for dir in search_dirs {
        let candidates = [
            dir.join(format!("{scan_id_or_path}-manifest.json")),
            dir.join(format!("{scan_id_or_path}.json")),
            dir.join(scan_id_or_path),
        ];

        for cand in candidates {
            if cand.exists() {
                let data = fs::read(&cand).map_err(|e| {
                    StageError::Io(format!(
                        "failed to read manifest file {}: {e}",
                        cand.display()
                    ))
                })?;
                return serde_json::from_slice(&data).map_err(|e| {
                    StageError::Parse(format!(
                        "failed to parse manifest JSON in {}: {e}",
                        cand.display()
                    ))
                });
            }
        }
    }

    Err(StageError::Io(format!(
        "could not find manifest for scan ID or path '{scan_id_or_path}'"
    )))
}
