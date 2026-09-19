use crate::core::StageError;
use std::fs;
use std::path::Path;

pub fn authorize_device(sysfs_path: &Path) -> Result<(), StageError> {
    let auth_file = sysfs_path.join("authorized");
    if auth_file.exists() {
        fs::write(&auth_file, b"1").map_err(|e| {
            StageError::Io(format!(
                "failed to authorize device at {}: {e}",
                auth_file.display()
            ))
        })?;
    }
    Ok(())
}

pub fn set_block_device_readonly(device_path: &Path) -> Result<(), StageError> {
    if let Some(dev_name) = device_path.file_name().and_then(|s| s.to_str()) {
        let sys_ro = Path::new("/sys/block").join(dev_name).join("ro");
        if sys_ro.exists() {
            fs::write(&sys_ro, b"1").map_err(|e| {
                StageError::Io(format!(
                    "failed to set block device read-only via {}: {e}",
                    sys_ro.display()
                ))
            })?;
        }
    }
    Ok(())
}
