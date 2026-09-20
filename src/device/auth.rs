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
    if is_system_device(device_path) || (device_path.exists() && !is_external_device(device_path)) {
        return Err(StageError::Io(format!(
            "Refusing to modify read-only state of host system or non-external drive '{}'",
            device_path.display()
        )));
    }
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

pub fn set_block_device_readwrite(device_path: &Path) -> Result<(), StageError> {
    if is_system_device(device_path) || (device_path.exists() && !is_external_device(device_path)) {
        return Err(StageError::Io(format!(
            "Refusing to modify read-write state of host system or non-external drive '{}'",
            device_path.display()
        )));
    }
    if let Some(dev_name) = device_path.file_name().and_then(|s| s.to_str()) {
        let sys_ro = Path::new("/sys/block").join(dev_name).join("ro");
        if sys_ro.exists() {
            fs::write(&sys_ro, b"0").map_err(|e| {
                StageError::Io(format!(
                    "failed to set block device read-write via {}: {e}",
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
    if let Some(rest) = target_dev.strip_prefix(&format!("{dev}p")) {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    if dev
        .chars()
        .last()
        .map(|c| c.is_ascii_alphabetic())
        .unwrap_or(false)
    {
        if let Some(rest) = target_dev.strip_prefix(dev) {
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
    if let Ok(content) = fs::read_to_string("/proc/swaps") {
        for line in content.lines().skip(1) {
            let mut parts = line.split_whitespace();
            if let Some(dev) = parts.next() {
                if is_matching_device(dev, &dev_str) {
                    return true;
                }
            }
        }
    }
    if let Some(dev_name) = device_path.file_name().and_then(|s| s.to_str()) {
        let sys_block = Path::new("/sys/block").join(dev_name);
        if let Ok(entries) = fs::read_dir(&sys_block) {
            for entry_res in entries.flatten() {
                let p = entry_res.path();
                if p.join("holders").is_dir() {
                    if let Ok(holders) = fs::read_dir(p.join("holders")) {
                        for holder_res in holders.flatten() {
                            let holder_name = holder_res.file_name().to_string_lossy().to_string();
                            let holder_dev = format!("/dev/{holder_name}");
                            if is_system_device(Path::new(&holder_dev)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

pub fn is_external_device(device_path: &Path) -> bool {
    let dev_str = device_path.to_string_lossy();
    if dev_str.is_empty() {
        return false;
    }
    if is_system_device(device_path) {
        return false;
    }
    if device_path.is_file() {
        let ext = device_path.extension().and_then(|s| s.to_str()).unwrap_or("");
        return ext == "raw" || ext == "img" || dev_str.ends_with(".raw") || dev_str.ends_with(".img");
    }
    let dev_name = match device_path.file_name().and_then(|s| s.to_str()) {
        Some(n) => n,
        None => return false,
    };
    if dev_name.starts_with("loop")
        || dev_name.starts_with("ram")
        || dev_name.starts_with("dm-")
        || dev_name.starts_with("md")
        || dev_name.starts_with("sr")
    {
        return false;
    }
    let sys_class = Path::new("/sys/class/block").join(dev_name);
    if let Ok(canonical) = fs::canonicalize(&sys_class) {
        let path_str = canonical.to_string_lossy();
        if path_str.contains("/usb") {
            return true;
        }
    }
    if crate::device::find_usb_device_sysfs_for_block_device(device_path).is_some() {
        return true;
    }
    let sys_block = Path::new("/sys/block").join(dev_name);
    let removable = fs::read_to_string(sys_block.join("removable"))
        .or_else(|_| fs::read_to_string(sys_class.join("removable")))
        .or_else(|_| fs::read_to_string(sys_class.join("../removable")))
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    if removable {
        return true;
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
    if device_path.exists() && !is_external_device(device_path) {
        return Err(StageError::Io(format!(
            "Refusing to unmount non-external drive '{}'",
            device_path.display()
        )));
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

pub fn mount_external_device(
    device_path: &Path,
    mountpoint: Option<&Path>,
    rw: bool,
) -> Result<std::path::PathBuf, StageError> {
    let dev_str = device_path.to_string_lossy();
    if dev_str.is_empty() {
        return Err(StageError::Io("Device path cannot be empty".to_string()));
    }
    if !device_path.exists() {
        return Err(StageError::Io(format!(
            "Device '{}' does not exist",
            device_path.display()
        )));
    }
    if is_system_device(device_path) || !is_external_device(device_path) {
        return Err(StageError::Io(format!(
            "SECURITY ERROR: Refusing to mount host system or internal drive '{}'",
            device_path.display()
        )));
    }

    let dev_name = device_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("usb");

    let target_dir = if let Some(mp) = mountpoint {
        mp.to_path_buf()
    } else if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty()
            && sudo_user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            std::path::PathBuf::from(format!("/media/{sudo_user}/{dev_name}"))
        } else {
            std::path::PathBuf::from(format!("/mnt/{dev_name}"))
        }
    } else if let Ok(user) = std::env::var("USER") {
        if !user.is_empty()
            && user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            std::path::PathBuf::from(format!("/media/{user}/{dev_name}"))
        } else {
            std::path::PathBuf::from(format!("/mnt/{dev_name}"))
        }
    } else {
        std::path::PathBuf::from(format!("/mnt/{dev_name}"))
    };

    let target_str = target_dir.to_string_lossy();
    if is_system_mount_point(&target_str) {
        return Err(StageError::Io(format!(
            "Refusing to mount over protected system mount point '{}'",
            target_dir.display()
        )));
    }

    fs::create_dir_all(&target_dir).map_err(|e| {
        StageError::Io(format!(
            "Failed to create mount directory '{}': {e}",
            target_dir.display()
        ))
    })?;

    let opts = if rw {
        "rw,nodev,nosuid"
    } else {
        "ro,nodev,nosuid,noexec"
    };

    let status = std::process::Command::new("mount")
        .args(["-o", opts, "--", &dev_str, &target_str])
        .status()
        .map_err(|e| StageError::Io(format!("Failed to execute mount command: {e}")))?;

    if status.success() {
        Ok(target_dir)
    } else {
        Err(StageError::Io(format!(
            "mount command failed with status {:?}",
            status.code()
        )))
    }
}
