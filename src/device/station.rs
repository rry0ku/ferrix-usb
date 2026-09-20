use std::fs;
use std::path::{Path, PathBuf};

pub struct StationProtectionGuard {
    pub saved_authorized_defaults: Vec<(PathBuf, String)>,
    pub stopped_udisks2: bool,
    pub restored_gnome_automount: Option<bool>,
}

impl StationProtectionGuard {
    pub fn is_root() -> bool {
        nix::unistd::Uid::effective().is_root()
    }

    pub fn enable() -> Self {
        if !Self::is_root() {
            return Self {
                saved_authorized_defaults: Vec::new(),
                stopped_udisks2: false,
                restored_gnome_automount: None,
            };
        }

        let mut saved_defaults = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
            for entry_res in entries {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("usb") {
                    let auth_def = entry.path().join("authorized_default");
                    if auth_def.exists() {
                        if let Ok(current_val) = fs::read_to_string(&auth_def) {
                            let trimmed = current_val.trim().to_string();
                            if fs::write(&auth_def, b"0\n").is_ok() {
                                saved_defaults.push((auth_def, trimmed));
                            }
                        }
                    }
                }
            }
        }

        let mut stopped_udisks2 = false;
        let is_active = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "udisks2"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if is_active {
            if let Ok(status) = std::process::Command::new("systemctl")
                .args(["stop", "udisks2"])
                .status()
            {
                if status.success() {
                    stopped_udisks2 = true;
                }
            }
        }

        let mut restored_gnome_automount = None;
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if !sudo_user.is_empty() {
                let check_gnome = std::process::Command::new("sudo")
                    .args([
                        "-u",
                        &sudo_user,
                        "gsettings",
                        "get",
                        "org.gnome.desktop.media-handling",
                        "automount",
                    ])
                    .output();
                if let Ok(out) = check_gnome {
                    let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if val == "true" {
                        let _ = std::process::Command::new("sudo")
                            .args([
                                "-u",
                                &sudo_user,
                                "gsettings",
                                "set",
                                "org.gnome.desktop.media-handling",
                                "automount",
                                "false",
                            ])
                            .status();
                        let _ = std::process::Command::new("sudo")
                            .args([
                                "-u",
                                &sudo_user,
                                "gsettings",
                                "set",
                                "org.gnome.desktop.media-handling",
                                "automount-open",
                                "false",
                            ])
                            .status();
                        restored_gnome_automount = Some(true);
                    }
                }
            }
        }

        Self {
            saved_authorized_defaults: saved_defaults,
            stopped_udisks2,
            restored_gnome_automount,
        }
    }

    pub fn restore(&mut self) {
        for (path, val) in &self.saved_authorized_defaults {
            let _ = fs::write(path, format!("{val}\n"));
        }
        self.saved_authorized_defaults.clear();

        if self.stopped_udisks2 {
            let _ = std::process::Command::new("systemctl")
                .args(["start", "udisks2"])
                .status();
            self.stopped_udisks2 = false;
        }

        if self.restored_gnome_automount == Some(true) {
            if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                if !sudo_user.is_empty() {
                    let _ = std::process::Command::new("sudo")
                        .args([
                            "-u",
                            &sudo_user,
                            "gsettings",
                            "set",
                            "org.gnome.desktop.media-handling",
                            "automount",
                            "true",
                        ])
                        .status();
                    let _ = std::process::Command::new("sudo")
                        .args([
                            "-u",
                            &sudo_user,
                            "gsettings",
                            "set",
                            "org.gnome.desktop.media-handling",
                            "automount-open",
                            "true",
                        ])
                        .status();
                }
            }
            self.restored_gnome_automount = None;
        }
    }
}

impl Drop for StationProtectionGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

pub fn find_block_device_for_usb_sysfs(sysfs_path: &Path) -> Option<PathBuf> {
    let canonical_sysfs = fs::canonicalize(sysfs_path).ok()?;
    if let Ok(entries) = fs::read_dir("/sys/class/block") {
        for entry_res in entries {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Ok(canonical_block) = fs::canonicalize(entry.path()) {
                if canonical_block.starts_with(&canonical_sysfs) {
                    let dev_name = entry.file_name().to_string_lossy().to_string();
                    let dev_path = PathBuf::from(format!("/dev/{dev_name}"));
                    if dev_path.exists() {
                        return Some(dev_path);
                    }
                }
            }
        }
    }
    None
}
