pub mod anomalies;
pub mod disposable;
pub mod partition;
pub mod snapshot;

pub use anomalies::*;
pub use disposable::*;
pub use partition::*;
pub use snapshot::*;

use crate::core::{Finding, ScanContext, Stage, StageError};

pub struct PartitionScanStage {
    pub sector_size: u32,
}

impl Default for PartitionScanStage {
    fn default() -> Self {
        Self { sector_size: 512 }
    }
}

impl PartitionScanStage {
    pub fn new(sector_size: u32) -> Self {
        Self { sector_size }
    }
}

impl Stage for PartitionScanStage {
    fn id(&self) -> &'static str {
        "partition_scan"
    }

    fn name(&self) -> &'static str {
        "Partition Table & Anomaly Inspection"
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError> {
        let scan_path = ctx.snapshot_path.as_ref().unwrap_or(&ctx.target_path);
        let mut file = open_device_or_file_with_retry(scan_path, std::time::Duration::from_secs(3))
            .map_err(|e| {
                StageError::Io(format!(
                    "failed to open scan target {}: {e}",
                    scan_path.display()
                ))
            })?;

        let total_bytes = crate::disk::snapshot::get_device_or_file_size(&file, scan_path);

        ctx.event_sink.emit(crate::core::ScanEvent::Progress {
            stage_id: self.id().to_string(),
            current: 1,
            total: Some(2),
            message: Some("Parsing MBR/GPT partition tables...".to_string()),
        });

        let layout = parse_disk_layout(&mut file, total_bytes, self.sector_size)?;

        ctx.event_sink.emit(crate::core::ScanEvent::Progress {
            stage_id: self.id().to_string(),
            current: 2,
            total: Some(2),
            message: Some(format!(
                "Found {} partition(s); checking layout anomalies...",
                layout.partitions.len()
            )),
        });

        let findings = check_partition_anomalies(&layout, &mut file);

        Ok(findings)
    }
}
