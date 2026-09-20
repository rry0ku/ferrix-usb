use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

fn is_valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && !user.starts_with('-')
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn user_dbus_bus_address(user: &str) -> Option<String> {
    let uid = nix::unistd::User::from_name(user).ok().flatten()?.uid;
    let bus_path = PathBuf::from(format!("/run/user/{uid}/bus"));
    if bus_path.exists() {
        Some(format!("unix:path={}", bus_path.display()))
    } else {
        None
    }
}

fn user_home_dir(user: &str) -> Option<PathBuf> {
    nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.dir)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoredSetting {
    GSettings {
        schema: String,
        key: String,
        original_value: String,
    },
    Xfconf {
        channel: String,
        property: String,
        original_value: String,
    },
    ConfigFile {
        path: PathBuf,
        original_content: Option<String>,
    },
}

pub fn set_kde_automount_disabled(content: &str) -> Option<String> {
    let group = "[Module-device_automounter]";
    let key_val = "autoload=false";
    if content.contains(group) {
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        let mut in_group = false;
        let mut set = false;
        for line in &mut lines {
            if line.trim().starts_with('[') {
                if in_group && !set {
                    break;
                }
                in_group = line.trim() == group;
            } else if in_group && line.trim().starts_with("autoload=") {
                if line.trim() == key_val {
                    return None;
                }
                *line = key_val.to_string();
                set = true;
            }
        }
        if !set {
            if let Some(pos) = lines.iter().position(|l| l.trim() == group) {
                lines.insert(pos + 1, key_val.to_string());
            }
        }
        Some(lines.join("\n") + "\n")
    } else {
        Some(format!("{content}\n{group}\n{key_val}\n"))
    }
}

pub fn set_lxqt_automount_disabled(content: &str) -> Option<String> {
    let group = "[Volume]";
    let keys = [
        "AutoMount=false",
        "AutoMountDevices=false",
        "AutoMountRemovable=false",
    ];
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut in_group = false;
    let mut found_keys = std::collections::HashSet::new();

    for line in &mut lines {
        if line.trim().starts_with('[') {
            in_group = line.trim().eq_ignore_ascii_case(group);
        } else if in_group {
            for &k in &keys {
                let prefix = k.split('=').next().unwrap();
                if line.trim().starts_with(prefix) {
                    *line = k.to_string();
                    found_keys.insert(prefix);
                }
            }
        }
    }

    if in_group || lines.iter().any(|l| l.trim().eq_ignore_ascii_case(group)) {
        if let Some(pos) = lines
            .iter()
            .position(|l| l.trim().eq_ignore_ascii_case(group))
        {
            for &k in &keys {
                let prefix = k.split('=').next().unwrap();
                if !found_keys.contains(prefix) {
                    lines.insert(pos + 1, k.to_string());
                }
            }
        }
    } else {
        lines.push(group.to_string());
        for &k in &keys {
            lines.push(k.to_string());
        }
    }
    Some(lines.join("\n") + "\n")
}

pub fn set_lxde_automount_disabled(content: &str) -> Option<String> {
    let group = "[volume]";
    let keys = ["mount_on_startup=0", "mount_removable=0"];
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut in_group = false;
    let mut found_keys = std::collections::HashSet::new();

    for line in &mut lines {
        if line.trim().starts_with('[') {
            in_group = line.trim().eq_ignore_ascii_case(group);
        } else if in_group {
            for &k in &keys {
                let prefix = k.split('=').next().unwrap();
                if line.trim().starts_with(prefix) {
                    *line = k.to_string();
                    found_keys.insert(prefix);
                }
            }
        }
    }

    if in_group || lines.iter().any(|l| l.trim().eq_ignore_ascii_case(group)) {
        if let Some(pos) = lines
            .iter()
            .position(|l| l.trim().eq_ignore_ascii_case(group))
        {
            for &k in &keys {
                let prefix = k.split('=').next().unwrap();
                if !found_keys.contains(prefix) {
                    lines.insert(pos + 1, k.to_string());
                }
            }
        }
    } else {
        lines.push(group.to_string());
        for &k in &keys {
            lines.push(k.to_string());
        }
    }
    Some(lines.join("\n") + "\n")
}

fn disable_gsettings_automount(
    sudo_user: &str,
    bus_addr: Option<&str>,
    restored: &mut Vec<RestoredSetting>,
) {
    let schemas = [
        "org.gnome.desktop.media-handling",
        "org.cinnamon.desktop.media-handling",
        "org.mate.media-handling",
    ];
    let keys = ["automount", "automount-open"];

    for schema in schemas {
        for key in keys {
            let mut check_cmd = std::process::Command::new("sudo");
            check_cmd
                .args(["-u", sudo_user, "--", "gsettings", "get", schema, key])
                .stderr(Stdio::null());
            if let Some(bus) = bus_addr {
                check_cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
            }

            if let Ok(out) = check_cmd.output() {
                let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if val == "true" {
                    let mut set_cmd = std::process::Command::new("sudo");
                    set_cmd
                        .args([
                            "-u",
                            sudo_user,
                            "--",
                            "gsettings",
                            "set",
                            schema,
                            key,
                            "false",
                        ])
                        .stderr(Stdio::null());
                    if let Some(bus) = bus_addr {
                        set_cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
                    }
                    if let Ok(status) = set_cmd.status() {
                        if status.success() {
                            restored.push(RestoredSetting::GSettings {
                                schema: schema.to_string(),
                                key: key.to_string(),
                                original_value: val,
                            });
                        }
                    }
                }
            }
        }
    }
}

fn disable_xfce_automount(
    sudo_user: &str,
    bus_addr: Option<&str>,
    restored: &mut Vec<RestoredSetting>,
) {
    let channel = "thunar-volman";
    let properties = ["/automount-media/enabled", "/automount-drives/enabled"];

    for prop in properties {
        let mut check_cmd = std::process::Command::new("sudo");
        check_cmd
            .args([
                "-u",
                sudo_user,
                "--",
                "xfconf-query",
                "-c",
                channel,
                "-p",
                prop,
            ])
            .stderr(Stdio::null());
        if let Some(bus) = bus_addr {
            check_cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
        }

        if let Ok(out) = check_cmd.output() {
            let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if val == "true" {
                let mut set_cmd = std::process::Command::new("sudo");
                set_cmd
                    .args([
                        "-u",
                        sudo_user,
                        "--",
                        "xfconf-query",
                        "-c",
                        channel,
                        "-p",
                        prop,
                        "-s",
                        "false",
                    ])
                    .stderr(Stdio::null());
                if let Some(bus) = bus_addr {
                    set_cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
                }
                if let Ok(status) = set_cmd.status() {
                    if status.success() {
                        restored.push(RestoredSetting::Xfconf {
                            channel: channel.to_string(),
                            property: prop.to_string(),
                            original_value: val,
                        });
                    }
                }
            }
        }
    }
}

fn disable_file_based_automount(home_dir: &Path, restored: &mut Vec<RestoredSetting>) {
    let kde_files = [
        home_dir.join(".config/kded5rc"),
        home_dir.join(".config/kded6rc"),
    ];
    for f in kde_files {
        if f.exists() {
            if let Ok(content) = fs::read_to_string(&f) {
                if let Some(new_content) = set_kde_automount_disabled(&content) {
                    if new_content != content && fs::write(&f, &new_content).is_ok() {
                        restored.push(RestoredSetting::ConfigFile {
                            path: f,
                            original_content: Some(content),
                        });
                    }
                }
            }
        }
    }

    let lxqt_files = [
        home_dir.join(".config/pcmanfm-qt/default/settings.conf"),
        home_dir.join(".config/pcmanfm-qt/lxqt/settings.conf"),
    ];
    for f in lxqt_files {
        if f.exists() {
            if let Ok(content) = fs::read_to_string(&f) {
                if let Some(new_content) = set_lxqt_automount_disabled(&content) {
                    if new_content != content && fs::write(&f, &new_content).is_ok() {
                        restored.push(RestoredSetting::ConfigFile {
                            path: f,
                            original_content: Some(content),
                        });
                    }
                }
            }
        }
    }

    let lxde_files = [
        home_dir.join(".config/pcmanfm/default/pcmanfm.conf"),
        home_dir.join(".config/pcmanfm/LXDE/pcmanfm.conf"),
    ];
    for f in lxde_files {
        if f.exists() {
            if let Ok(content) = fs::read_to_string(&f) {
                if let Some(new_content) = set_lxde_automount_disabled(&content) {
                    if new_content != content && fs::write(&f, &new_content).is_ok() {
                        restored.push(RestoredSetting::ConfigFile {
                            path: f,
                            original_content: Some(content),
                        });
                    }
                }
            }
        }
    }
}

pub struct StationProtectionGuard {
    pub saved_authorized_defaults: Vec<(PathBuf, String)>,
    pub stopped_services: Vec<String>,
    pub masked_services: Vec<String>,
    pub created_udev_rule: bool,
    pub restored_settings: Vec<RestoredSetting>,
}

impl StationProtectionGuard {
    pub fn is_root() -> bool {
        nix::unistd::Uid::effective().is_root()
    }

    pub fn enable() -> Self {
        if !Self::is_root() {
            return Self {
                saved_authorized_defaults: Vec::new(),
                stopped_services: Vec::new(),
                masked_services: Vec::new(),
                created_udev_rule: false,
                restored_settings: Vec::new(),
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

        let mut created_udev_rule = false;
        let udev_rule_dir = Path::new("/run/udev/rules.d");
        if fs::create_dir_all(udev_rule_dir).is_ok() {
            let udev_rule_file = udev_rule_dir.join("99-ferrix-no-automount.rules");
            let rule_content =
                b"SUBSYSTEM==\"block\", ENV{UDISKS_AUTO}=\"0\", ENV{UDISKS_IGNORE}=\"1\"\n";
            if fs::write(&udev_rule_file, rule_content).is_ok() {
                created_udev_rule = true;
                let _ = std::process::Command::new("udevadm")
                    .args(["control", "--reload"])
                    .stderr(Stdio::null())
                    .status();
            }
        }

        let mut stopped_services = Vec::new();
        let mut masked_services = Vec::new();
        for svc in ["udisks2", "autofs"] {
            let is_active = std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", svc])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if is_active {
                let mask_res = std::process::Command::new("systemctl")
                    .args(["mask", "--runtime", svc])
                    .stderr(Stdio::null())
                    .status();
                if let Ok(m) = mask_res {
                    if m.success() {
                        masked_services.push(svc.to_string());
                    }
                }

                if let Ok(status) = std::process::Command::new("systemctl")
                    .args(["stop", svc])
                    .stderr(Stdio::null())
                    .status()
                {
                    if status.success() {
                        stopped_services.push(svc.to_string());
                    }
                }
            }
        }

        let mut restored_settings = Vec::new();
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if is_valid_username(&sudo_user) {
                let bus_addr = user_dbus_bus_address(&sudo_user);
                disable_gsettings_automount(
                    &sudo_user,
                    bus_addr.as_deref(),
                    &mut restored_settings,
                );
                disable_xfce_automount(&sudo_user, bus_addr.as_deref(), &mut restored_settings);

                if let Some(home) = user_home_dir(&sudo_user) {
                    disable_file_based_automount(&home, &mut restored_settings);
                }
            }
        }

        Self {
            saved_authorized_defaults: saved_defaults,
            stopped_services,
            masked_services,
            created_udev_rule,
            restored_settings,
        }
    }

    pub fn restore(&mut self) {
        for (path, val) in &self.saved_authorized_defaults {
            let _ = fs::write(path, format!("{val}\n"));
        }
        self.saved_authorized_defaults.clear();

        if self.created_udev_rule {
            let udev_rule_file = Path::new("/run/udev/rules.d/99-ferrix-no-automount.rules");
            let _ = fs::remove_file(udev_rule_file);
            let _ = std::process::Command::new("udevadm")
                .args(["control", "--reload"])
                .stderr(Stdio::null())
                .status();
            self.created_udev_rule = false;
        }

        for svc in self.masked_services.drain(..) {
            let _ = std::process::Command::new("systemctl")
                .args(["unmask", "--runtime", &svc])
                .stderr(Stdio::null())
                .status();
        }

        for svc in self.stopped_services.drain(..) {
            let _ = std::process::Command::new("systemctl")
                .args(["start", &svc])
                .stderr(Stdio::null())
                .status();
        }

        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if is_valid_username(&sudo_user) {
                let bus_addr = user_dbus_bus_address(&sudo_user);
                for setting in self.restored_settings.drain(..) {
                    match setting {
                        RestoredSetting::GSettings {
                            schema,
                            key,
                            original_value,
                        } => {
                            let mut set_cmd = std::process::Command::new("sudo");
                            set_cmd
                                .args([
                                    "-u",
                                    &sudo_user,
                                    "--",
                                    "gsettings",
                                    "set",
                                    &schema,
                                    &key,
                                    &original_value,
                                ])
                                .stderr(Stdio::null());
                            if let Some(ref bus) = bus_addr {
                                set_cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
                            }
                            let _ = set_cmd.status();
                        }
                        RestoredSetting::Xfconf {
                            channel,
                            property,
                            original_value,
                        } => {
                            let mut set_cmd = std::process::Command::new("sudo");
                            set_cmd
                                .args([
                                    "-u",
                                    &sudo_user,
                                    "--",
                                    "xfconf-query",
                                    "-c",
                                    &channel,
                                    "-p",
                                    &property,
                                    "-s",
                                    &original_value,
                                ])
                                .stderr(Stdio::null());
                            if let Some(ref bus) = bus_addr {
                                set_cmd.env("DBUS_SESSION_BUS_ADDRESS", bus);
                            }
                            let _ = set_cmd.status();
                        }
                        RestoredSetting::ConfigFile {
                            path,
                            original_content,
                        } => {
                            if let Some(content) = original_content {
                                let _ = fs::write(&path, content);
                            } else {
                                let _ = fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
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
