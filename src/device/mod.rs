pub mod anomalies;
pub mod auth;
pub mod descriptors;

pub use anomalies::*;
pub use auth::*;
pub use descriptors::*;

use crate::core::{Finding, ScanContext, Stage, StageError};
use crate::policy::Policy;
use std::fs;

pub struct DeviceScanStage {
    pub policy: Policy,
}

impl Default for DeviceScanStage {
    fn default() -> Self {
        Self {
            policy: Policy::strict_default(),
        }
    }
}

impl DeviceScanStage {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }
}

impl Stage for DeviceScanStage {
    fn id(&self) -> &'static str {
        "device_scan"
    }

    fn name(&self) -> &'static str {
        "USB Device Descriptors & BadUSB Inspection"
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError> {
        let mock_candidates = [
            ctx.target_path.with_extension("usb.json"),
            std::path::PathBuf::from(format!("{}.usb.json", ctx.target_path.display())),
        ];
        for companion_mock in &mock_candidates {
            if companion_mock.exists() {
                let data = fs::read(companion_mock).map_err(|e| {
                    StageError::Io(format!(
                        "failed to read mock USB descriptor {}: {e}",
                        companion_mock.display()
                    ))
                })?;
                let usb_dev: UsbDevice = serde_json::from_slice(&data).map_err(|e| {
                    StageError::Parse(format!(
                        "failed to parse mock USB descriptor in {}: {e}",
                        companion_mock.display()
                    ))
                })?;
                return Ok(check_device_anomalies(&usb_dev, &self.policy));
            }
        }

        if let Some(sysfs_path) = find_usb_device_sysfs_for_block_device(&ctx.target_path) {
            let usb_dev = read_usb_device_from_sysfs(&sysfs_path)?;
            return Ok(check_device_anomalies(&usb_dev, &self.policy));
        }

        Ok(Vec::new())
    }
}
