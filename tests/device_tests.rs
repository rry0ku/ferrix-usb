use ferrix_usb::core::{ScanContext, Severity, Stage};
use ferrix_usb::device::{
    check_device_anomalies, DeviceScanStage, UsbDevice, UsbInterface, USB_CLASS_HID,
    USB_CLASS_MASS_STORAGE,
};
use ferrix_usb::policy::{DeviceFilter, Policy};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_badusb_composite_device_detection() {
    let dev = UsbDevice {
        vendor_id: "0781".to_string(),
        product_id: "5581".to_string(),
        serial: Some("12345678".to_string()),
        manufacturer: Some("SanDisk".to_string()),
        product_name: Some("Ultra".to_string()),
        interfaces: vec![
            UsbInterface {
                interface_number: 0,
                interface_class: USB_CLASS_MASS_STORAGE,
                interface_subclass: 0x06,
                interface_protocol: 0x50,
            },
            UsbInterface {
                interface_number: 1,
                interface_class: USB_CLASS_HID,
                interface_subclass: 0x01,
                interface_protocol: 0x01,
            },
        ],
        authorized: true,
        sysfs_path: PathBuf::from("/sys/bus/usb/devices/1-1"),
    };

    let policy = Policy::strict_default();
    let findings = check_device_anomalies(&dev, &policy);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "FX-DEV-001");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_clean_storage_device() {
    let dev = UsbDevice {
        vendor_id: "0781".to_string(),
        product_id: "5581".to_string(),
        serial: Some("12345678".to_string()),
        manufacturer: Some("SanDisk".to_string()),
        product_name: Some("Ultra".to_string()),
        interfaces: vec![UsbInterface {
            interface_number: 0,
            interface_class: USB_CLASS_MASS_STORAGE,
            interface_subclass: 0x06,
            interface_protocol: 0x50,
        }],
        authorized: true,
        sysfs_path: PathBuf::from("/sys/bus/usb/devices/1-1"),
    };

    let policy = Policy::strict_default();
    let findings = check_device_anomalies(&dev, &policy);

    assert!(findings.is_empty());
}

#[test]
fn test_descriptor_anomalies() {
    let dev = UsbDevice {
        vendor_id: "0781".to_string(),
        product_id: "5581".to_string(),
        serial: None,
        manufacturer: None,
        product_name: None,
        interfaces: vec![],
        authorized: false,
        sysfs_path: PathBuf::from("/sys/bus/usb/devices/1-1"),
    };

    let policy = Policy::strict_default();
    let findings = check_device_anomalies(&dev, &policy);

    assert!(findings.iter().any(|f| f.id == "FX-DEV-002"));
    assert!(findings
        .iter()
        .any(|f| f.id == "FX-DEV-002" && f.severity == Severity::High));
}

#[test]
fn test_device_policy_allowlist() {
    let dev = UsbDevice {
        vendor_id: "9999".to_string(),
        product_id: "8888".to_string(),
        serial: Some("SECRET".to_string()),
        manufacturer: None,
        product_name: None,
        interfaces: vec![UsbInterface {
            interface_number: 0,
            interface_class: USB_CLASS_MASS_STORAGE,
            interface_subclass: 0x06,
            interface_protocol: 0x50,
        }],
        authorized: true,
        sysfs_path: PathBuf::from("/sys/bus/usb/devices/1-1"),
    };

    let mut policy = Policy::strict_default();
    policy.allowed_devices = vec![DeviceFilter {
        vendor: "0781".to_string(),
        product: "5581".to_string(),
        serial: None,
    }];

    let findings = check_device_anomalies(&dev, &policy);

    assert!(findings.iter().any(|f| f.id == "FX-DEV-003"));
    assert_eq!(
        findings
            .iter()
            .find(|f| f.id == "FX-DEV-003")
            .unwrap()
            .severity,
        Severity::High
    );
}

#[test]
fn test_device_stage_with_mock_file() {
    let raw_file = std::env::temp_dir().join("test_usb.raw");
    fs::write(&raw_file, vec![0u8; 1024]).unwrap();

    let dev = UsbDevice {
        vendor_id: "0781".to_string(),
        product_id: "5581".to_string(),
        serial: Some("XYZ123".to_string()),
        manufacturer: Some("TestVendor".to_string()),
        product_name: Some("TestDrive".to_string()),
        interfaces: vec![
            UsbInterface {
                interface_number: 0,
                interface_class: USB_CLASS_MASS_STORAGE,
                interface_subclass: 0x06,
                interface_protocol: 0x50,
            },
            UsbInterface {
                interface_number: 1,
                interface_class: USB_CLASS_HID,
                interface_subclass: 0x01,
                interface_protocol: 0x01,
            },
        ],
        authorized: false,
        sysfs_path: PathBuf::from("/sys/bus/usb/devices/1-1"),
    };

    let mock_json = serde_json::to_string(&dev).unwrap();
    let mock_path = std::env::temp_dir().join("test_usb.raw.usb.json");
    fs::write(&mock_path, mock_json).unwrap();

    let stage = DeviceScanStage::default();
    let ctx = ScanContext::new(raw_file.clone());
    let findings = stage.run(&ctx).unwrap();

    let _ = fs::remove_file(raw_file);
    let _ = fs::remove_file(mock_path);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "FX-DEV-001");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_system_device_and_mount_point_checks() {
    use ferrix_usb::device::{is_system_device, is_system_mount_point, unmount_device_partitions};
    use std::path::Path;

    assert!(is_system_mount_point("/"));
    assert!(is_system_mount_point("/boot"));
    assert!(is_system_mount_point("/boot/efi"));
    assert!(is_system_mount_point("/etc"));
    assert!(is_system_mount_point("/usr"));
    assert!(is_system_mount_point("/var"));
    assert!(is_system_mount_point("/home"));
    assert!(is_system_mount_point("/root"));
    assert!(!is_system_mount_point("/media/usb"));
    assert!(!is_system_mount_point("/mnt/external"));
    assert!(!is_system_mount_point("/run/media/dex/drive"));

    assert!(!is_system_device(Path::new(
        "/dev/nonexistent_dummy_device_99999"
    )));
    assert!(!is_system_device(Path::new("")));

    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let mut parts = line.split(' ');
            if let (Some(dev), Some(mp)) = (parts.next(), parts.next()) {
                if is_system_mount_point(mp) && dev.starts_with("/dev/") {
                    assert!(is_system_device(Path::new(dev)));
                    assert!(unmount_device_partitions(Path::new(dev)).is_err());
                    break;
                }
            }
        }
    }
}

#[test]
fn test_unmount_invalid_device_rejected() {
    use ferrix_usb::device::unmount_device_partitions;
    use std::path::Path;

    let res = unmount_device_partitions(Path::new("/dev/nonexistent_device_test_12345"));
    assert!(res.is_ok());
    assert!(res.unwrap().is_empty());
}

#[test]
fn test_kde_automount_disable_modifier() {
    use ferrix_usb::device::set_kde_automount_disabled;

    let existing_active = "[Module-device_automounter]\nautoload=true\n";
    let modified = set_kde_automount_disabled(existing_active).unwrap();
    assert!(modified.contains("autoload=false"));
    assert!(!modified.contains("autoload=true"));

    let already_disabled = "[Module-device_automounter]\nautoload=false\n";
    let res = set_kde_automount_disabled(already_disabled);
    assert!(res.is_none());

    let empty = "[General]\nfoo=bar\n";
    let modified_empty = set_kde_automount_disabled(empty).unwrap();
    assert!(modified_empty.contains("[Module-device_automounter]"));
    assert!(modified_empty.contains("autoload=false"));
}

#[test]
fn test_lxqt_and_lxde_automount_disable_modifiers() {
    use ferrix_usb::device::{set_lxde_automount_disabled, set_lxqt_automount_disabled};

    let lxqt_active = "[Volume]\nAutoMount=true\nAutoMountDevices=true\n";
    let lxqt_mod = set_lxqt_automount_disabled(lxqt_active).unwrap();
    assert!(lxqt_mod.contains("AutoMount=false"));
    assert!(lxqt_mod.contains("AutoMountDevices=false"));
    assert!(lxqt_mod.contains("AutoMountRemovable=false"));

    let lxde_active = "[volume]\nmount_on_startup=1\nmount_removable=1\n";
    let lxde_mod = set_lxde_automount_disabled(lxde_active).unwrap();
    assert!(lxde_mod.contains("mount_on_startup=0"));
    assert!(lxde_mod.contains("mount_removable=0"));
}

#[test]
fn test_station_protection_guard_non_root() {
    use ferrix_usb::device::StationProtectionGuard;

    let mut guard = StationProtectionGuard::enable();
    if !StationProtectionGuard::is_root() {
        assert!(guard.saved_authorized_defaults.is_empty());
        assert!(guard.stopped_services.is_empty());
        assert!(guard.masked_services.is_empty());
        assert!(!guard.created_udev_rule);
        assert!(guard.restored_settings.is_empty());
    }
    guard.restore();
}

#[test]
fn test_is_external_device_semantics() {
    use ferrix_usb::device::is_external_device;
    use std::path::Path;

    assert!(!is_external_device(Path::new("")));
    assert!(!is_external_device(Path::new("/dev/loop0")));
    assert!(!is_external_device(Path::new("/dev/ram0")));
    assert!(!is_external_device(Path::new("/dev/dm-0")));
    assert!(!is_external_device(Path::new("/dev/md0")));
    assert!(!is_external_device(Path::new("/dev/sr0")));

    let temp_img = std::env::temp_dir().join("test_ext_drive.raw");
    std::fs::write(&temp_img, vec![0u8; 512]).unwrap();
    assert!(is_external_device(&temp_img));
    let _ = std::fs::remove_file(temp_img);

    let temp_file = std::env::temp_dir().join("test_other.txt");
    std::fs::write(&temp_file, b"test").unwrap();
    assert!(!is_external_device(&temp_file));
    let _ = std::fs::remove_file(temp_file);
}

#[test]
fn test_cleanup_lingering_station_lockdown_safe() {
    use ferrix_usb::device::cleanup_lingering_station_lockdown;

    cleanup_lingering_station_lockdown();
}

#[test]
fn test_mount_external_device_security_checks() {
    use ferrix_usb::device::mount_external_device;
    use std::path::Path;

    let res = mount_external_device(Path::new(""), None, false);
    assert!(res.is_err());

    let res_nonexistent =
        mount_external_device(Path::new("/dev/nonexistent_device_test_12345"), None, false);
    assert!(res_nonexistent.is_err());

    let res_loop = mount_external_device(Path::new("/dev/loop0"), None, false);
    assert!(res_loop.is_err());

    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let mut parts = line.split(' ');
            if let (Some(dev), Some(mp)) = (parts.next(), parts.next()) {
                if mp == "/" && dev.starts_with("/dev/") {
                    let res_root = mount_external_device(Path::new(dev), None, false);
                    assert!(res_root.is_err());
                    break;
                }
            }
        }
    }
}

#[test]
fn test_restore_all_system_automount_defaults_safe() {
    use ferrix_usb::device::restore_all_system_automount_defaults;

    restore_all_system_automount_defaults();
}

#[test]
fn test_get_available_disk_space_and_resolve_dir() {
    use ferrix_usb::disk::{get_available_disk_space, resolve_snapshot_directory};
    use std::path::Path;

    let space = get_available_disk_space(Path::new("/tmp")).unwrap();
    assert!(space > 0);

    let resolved = resolve_snapshot_directory(1024 * 1024, None).unwrap();
    assert!(resolved.exists());

    let impossible_space = u64::MAX / 2;
    let err = resolve_snapshot_directory(impossible_space, None);
    assert!(err.is_err());
}

#[test]
fn test_create_snapshot_partial_file_cleanup_on_error() {
    use ferrix_usb::core::{EventSink, ScanEvent};
    use ferrix_usb::disk::create_snapshot;
    use std::sync::mpsc::channel;

    let (tx, _rx) = channel::<ScanEvent>();
    let sink = EventSink::new(tx);

    let non_existent_source = std::env::temp_dir().join("non_existent_source_for_test.raw");
    let dest_file = std::env::temp_dir().join("test_cleanup_guard.img");

    let res = create_snapshot(&non_existent_source, &dest_file, &sink);
    assert!(res.is_err());
    assert!(!dest_file.exists());
}

#[test]
fn test_read_block_device_identity_non_existent() {
    use ferrix_usb::device::{read_block_device_identity, read_block_device_serial};
    use std::path::Path;

    let res = read_block_device_serial(Path::new("/dev/non_existent_device_xyz"));
    assert!(res.is_none());

    let (v, m, s) = read_block_device_identity(Path::new("/dev/non_existent_device_xyz"));
    assert!(v.is_empty());
    assert!(m.is_empty());
    assert!(s.is_empty());
}

#[test]
fn test_read_block_device_identity_sda_if_present() {
    use ferrix_usb::device::{read_block_device_identity, read_block_device_serial};
    use std::path::Path;

    let sda = Path::new("/dev/sda");
    if Path::new("/sys/block/sda").exists() {
        let (v, m, s) = read_block_device_identity(sda);
        assert_eq!(v, "HP");
        assert_eq!(m, "USB Flash Drive");
        assert_eq!(s, "0708426326974660");
        assert_eq!(
            read_block_device_serial(sda).as_deref(),
            Some("0708426326974660")
        );
    }
}

#[test]
fn test_create_snapshot_pipelined_integrity() {
    use ferrix_usb::core::{EventSink, ScanEvent};
    use ferrix_usb::disk::snapshot::{create_snapshot, hash_device_or_image};
    use std::fs;
    use std::sync::mpsc::channel;

    let temp_dir = std::env::temp_dir().join(format!("test_pipe_snap_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    let src_path = temp_dir.join("source.raw");
    let dst_path = temp_dir.join("dest.img");

    let test_data = vec![0xA5u8; 5 * 1024 * 1024 + 12345];
    fs::write(&src_path, &test_data).unwrap();

    let (tx, _rx) = channel::<ScanEvent>();
    let sink = EventSink::new(tx);

    let snapshot = create_snapshot(&src_path, &dst_path, &sink).unwrap();
    assert_eq!(snapshot.size_bytes, test_data.len() as u64);
    assert_eq!(snapshot.path, dst_path);

    let (src_hash, src_len) = hash_device_or_image(&src_path).unwrap();
    let (dst_hash, dst_len) = hash_device_or_image(&dst_path).unwrap();

    assert_eq!(src_len, test_data.len() as u64);
    assert_eq!(dst_len, test_data.len() as u64);
    assert_eq!(src_hash, dst_hash);
    assert_eq!(snapshot.device_hash, src_hash);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&dst_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o400);
    }

    let _ = fs::remove_file(&src_path);
    let _ = fs::remove_file(&dst_path);
    let _ = fs::remove_dir_all(&temp_dir);
}
