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

fn is_matching_device(dev: &str, target_dev: &str) -> bool {
    if dev.is_empty() || target_dev.is_empty() {
        return false;
    }
    if dev == target_dev {
        return true;
    }
    if let Some(rest) = dev.strip_prefix(&format!("{target_dev}p")) {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    if target_dev
        .chars()
        .last()
        .map(|c| c.is_ascii_alphabetic())
        .unwrap_or(false)
    {
        if let Some(rest) = dev.strip_prefix(target_dev) {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

pub fn is_system_mount_point(mp: &str) -> bool {
    mp == "/"
        || mp == "/boot"
        || mp.starts_with("/boot/")
        || mp == "/etc"
        || mp.starts_with("/etc/")
        || mp == "/usr"
        || mp.starts_with("/usr/")
        || mp == "/var"
        || mp.starts_with("/var/")
        || mp == "/home"
        || mp.starts_with("/home/")
        || mp == "/root"
        || mp.starts_with("/root/")
}

pub fn is_system_device(device_path: &Path) -> bool {
    let dev_str = device_path.to_string_lossy();
    if dev_str.is_empty() {
        return false;
    }
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let mut parts = line.split(' ');
            if let (Some(dev), Some(mp)) = (parts.next(), parts.next()) {
                if is_matching_device(dev, &dev_str) && is_system_mount_point(mp) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn check_device_mounts(device_path: &Path) -> Vec<(String, String)> {
    let dev_str = device_path.to_string_lossy();
    if dev_str.is_empty() {
        return Vec::new();
    }
    let mut mounts = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let mut parts = line.split(' ');
            if let (Some(dev), Some(mp)) = (parts.next(), parts.next()) {
                if is_matching_device(dev, &dev_str) {
                    mounts.push((dev.to_string(), mp.to_string()));
                }
            }
        }
    }
    mounts
}

pub fn unmount_device_partitions(device_path: &Path) -> Result<Vec<String>, StageError> {
    if is_system_device(device_path) {
        return Err(StageError::Io(
            "Refusing to unmount host system drive (contains root '/' or essential system mount points)"
                .to_string(),
        ));
    }
    let mounts = check_device_mounts(device_path);
    let mut unmounted = Vec::new();
    for (dev, mp) in mounts {
        if is_system_mount_point(&mp) {
            return Err(StageError::Io(format!(
                "Refusing to unmount protected system mount point '{mp}'"
            )));
        }
        if mp.is_empty() || mp.contains('\0') || mp.starts_with('-') {
            return Err(StageError::Io(format!(
                "Refusing to unmount invalid or suspicious mount point '{mp}'"
            )));
        }
        let status = std::process::Command::new("umount")
            .arg("--")
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
