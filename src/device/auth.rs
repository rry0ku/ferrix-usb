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

pub fn check_device_mounts(device_path: &Path) -> Vec<(String, String)> {
    let dev_str = device_path.to_string_lossy();
    let mut mounts = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(dev), Some(mp)) = (parts.next(), parts.next()) {
                if dev == dev_str
                    || dev.starts_with(&format!("{dev_str}p"))
                    || (dev.starts_with(&*dev_str)
                        && dev.len() > dev_str.len()
                        && dev[dev_str.len()..].chars().all(|c| c.is_ascii_digit()))
                {
                    mounts.push((dev.to_string(), mp.to_string()));
                }
            }
        }
    }
    mounts
}

pub fn unmount_device_partitions(device_path: &Path) -> Result<Vec<String>, StageError> {
    let mounts = check_device_mounts(device_path);
    let mut unmounted = Vec::new();
    for (dev, mp) in mounts {
        let status = std::process::Command::new("umount")
            .arg(&mp)
            .status()
            .map_err(|e| StageError::Io(format!("failed to execute umount {mp}: {e}")))?;
        if status.success() {
            unmounted.push(mp);
        } else {
            return Err(StageError::Io(format!("failed to unmount {dev} from {mp}")));
        }
    }
    Ok(unmounted)
}
