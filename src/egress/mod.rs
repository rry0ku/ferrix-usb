pub mod metadata;
pub mod remnants;

pub use metadata::*;
pub use remnants::*;

use crate::core::{Finding, ScanContext, Stage, StageError};
use crate::disk::partition::parse_disk_layout;
use crate::fs::extract_filesystem_files;
use std::io::{Read, Seek, SeekFrom};

pub struct EgressScanStage {
    pub sector_size: u32,
    pub verify_wipe: bool,
}

impl Default for EgressScanStage {
    fn default() -> Self {
        Self {
            sector_size: 512,
            verify_wipe: false,
        }
    }
}

impl EgressScanStage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_verify_wipe(mut self, verify_wipe: bool) -> Self {
        self.verify_wipe = verify_wipe;
        self
    }

    pub fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = sector_size;
        self
    }
}

impl Stage for EgressScanStage {
    fn id(&self) -> &'static str {
        "egress_scan"
    }

    fn name(&self) -> &'static str {
        "Egress Media Remnants & Data Leakage Inspection"
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError> {
        let scan_path = ctx.snapshot_path.as_ref().unwrap_or(&ctx.target_path);
        let mut file = crate::disk::snapshot::open_device_or_file_with_retry(
            scan_path,
            std::time::Duration::from_secs(3),
        ).map_err(|e| {
            StageError::Io(format!(
                "failed to open scan target {}: {e}",
                scan_path.display()
            ))
        })?;

        let total_bytes = crate::disk::snapshot::get_device_or_file_size(&file, scan_path);

        let layout = parse_disk_layout(&mut file, total_bytes, self.sector_size)?;
        let mut findings = Vec::new();

        scan_unallocated_remnants(&mut file, &layout, self.sector_size, &mut findings)?;

        if self.verify_wipe {
            verify_wipe_pattern(&mut file, &layout, self.sector_size, &mut findings)?;
        }

        let discovered_files = extract_filesystem_files(&mut file, total_bytes, self.sector_size)?;

        for entry in discovered_files {
            if entry.is_dir {
                continue;
            }

            let filename = String::from_utf8_lossy(entry.path.as_bytes()).to_string();

            if let Some(offset) = entry.data_offset {
                if entry.size > 0 && file.seek(SeekFrom::Start(offset)).is_ok() {
                    let mut buf = vec![0u8; 1024 * 1024.min(entry.size as usize)];
                    if file.read_exact(&mut buf).is_ok() {
                        detect_metadata(&entry.path, &filename, &buf, &mut findings);
                    }
                }
            }
        }

        Ok(findings)
    }
}
