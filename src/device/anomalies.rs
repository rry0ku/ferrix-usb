use crate::core::{Confidence, Finding, Location, Severity};
use crate::device::descriptors::{UsbDevice, USB_CLASS_HID, USB_CLASS_MASS_STORAGE};
use crate::policy::Policy;

pub fn check_device_anomalies(device: &UsbDevice, policy: &Policy) -> Vec<Finding> {
    let mut findings = Vec::new();

    let has_storage = device
        .interfaces
        .iter()
        .any(|iface| iface.interface_class == USB_CLASS_MASS_STORAGE);

    let has_hid = device
        .interfaces
        .iter()
        .any(|iface| iface.interface_class == USB_CLASS_HID);

    if has_storage && has_hid {
        findings.push(Finding {
            id: "FX-DEV-001".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            stage: "device_scan".to_string(),
            location: Location::Device,
            reason:
                "composite device with storage and HID keyboard/mouse detected (BadUSB pattern)"
                    .to_string(),
            evidence:
                "device exposes mass storage (class 0x08) and HID (class 0x03) simultaneously"
                    .to_string(),
        });
    }

    if device.interfaces.is_empty() {
        findings.push(Finding {
            id: "FX-DEV-002".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "device_scan".to_string(),
            location: Location::Device,
            reason: "USB device has no active interfaces".to_string(),
            evidence: "zero USB interfaces found in device descriptor".to_string(),
        });
    }

    if device.vendor_id.len() != 4 || device.product_id.len() != 4 {
        findings.push(Finding {
            id: "FX-DEV-002".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "device_scan".to_string(),
            location: Location::Device,
            reason: "invalid USB vendor or product ID format".to_string(),
            evidence: format!(
                "vendor_id='{}', product_id='{}'",
                device.vendor_id, device.product_id
            ),
        });
    }

    if !policy.allowed_devices.is_empty() {
        let is_allowed = policy.allowed_devices.iter().any(|d| {
            let vendor_match = d.vendor.eq_ignore_ascii_case(&device.vendor_id);
            let product_match = d.product.eq_ignore_ascii_case(&device.product_id);
            let serial_match = match (&d.serial, &device.serial) {
                (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
                (Some(_), None) => false,
                (None, _) => true,
            };
            vendor_match && product_match && serial_match
        });

        if !is_allowed {
            findings.push(Finding {
                id: "FX-DEV-003".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "device_scan".to_string(),
                location: Location::Device,
                reason: "USB device not permitted by policy".to_string(),
                evidence: format!(
                    "device vendor='{}' product='{}' serial='{:?}' is not in allowed_devices",
                    device.vendor_id, device.product_id, device.serial
                ),
            });
        }
    }

    findings
}
