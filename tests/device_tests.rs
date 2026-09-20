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
