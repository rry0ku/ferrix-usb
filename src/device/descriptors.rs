use crate::core::StageError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_CLASS_MASS_STORAGE: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbInterface {
    pub interface_number: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbDevice {
    pub vendor_id: String,
    pub product_id: String,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub interfaces: Vec<UsbInterface>,
    pub authorized: bool,
    pub sysfs_path: PathBuf,
}

pub fn parse_hex_u8(s: &str) -> Option<u8> {
    let trimmed = s.trim().trim_start_matches("0x");
    u8::from_str_radix(trimmed, 16).ok()
}

pub fn read_sysfs_string(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn read_usb_device_from_sysfs(sysfs_path: &Path) -> Result<UsbDevice, StageError> {
    let vendor_id = read_sysfs_string(&sysfs_path.join("idVendor"))
        .ok_or_else(|| StageError::Parse("missing idVendor in sysfs".to_string()))?;

    let product_id = read_sysfs_string(&sysfs_path.join("idProduct"))
        .ok_or_else(|| StageError::Parse("missing idProduct in sysfs".to_string()))?;

    let serial = read_sysfs_string(&sysfs_path.join("serial"));
    let manufacturer = read_sysfs_string(&sysfs_path.join("manufacturer"));
    let product_name = read_sysfs_string(&sysfs_path.join("product"));

    let authorized = read_sysfs_string(&sysfs_path.join("authorized"))
        .map(|s| s == "1")
        .unwrap_or(false);

    let mut interfaces = Vec::new();

    if let Ok(entries) = fs::read_dir(sysfs_path) {
        for entry_res in entries {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let p = entry.path();
            if p.is_dir() {
                let class_file = p.join("bInterfaceClass");
                if class_file.exists() {
                    let class_str = read_sysfs_string(&class_file).unwrap_or_default();
                    let subclass_str =
                        read_sysfs_string(&p.join("bInterfaceSubClass")).unwrap_or_default();
                    let protocol_str =
                        read_sysfs_string(&p.join("bInterfaceProtocol")).unwrap_or_default();
                    let num_str =
                        read_sysfs_string(&p.join("bInterfaceNumber")).unwrap_or_default();

                    let interface_class = parse_hex_u8(&class_str).unwrap_or(0);
                    let interface_subclass = parse_hex_u8(&subclass_str).unwrap_or(0);
                    let interface_protocol = parse_hex_u8(&protocol_str).unwrap_or(0);
                    let interface_number = parse_hex_u8(&num_str).unwrap_or(0);

                    interfaces.push(UsbInterface {
                        interface_number,
                        interface_class,
                        interface_subclass,
                        interface_protocol,
                    });
                }
            }
        }
    }

    Ok(UsbDevice {
        vendor_id,
        product_id,
        serial,
        manufacturer,
        product_name,
        interfaces,
        authorized,
        sysfs_path: sysfs_path.to_path_buf(),
    })
}

pub fn find_usb_device_sysfs_for_block_device(block_dev: &Path) -> Option<PathBuf> {
    let dev_name = block_dev.file_name()?.to_str()?;
    let sys_block = Path::new("/sys/class/block").join(dev_name);
    let canonical = fs::canonicalize(sys_block).ok()?;

    let mut current = canonical.parent();
    while let Some(dir) = current {
        if dir.join("idVendor").exists() && dir.join("idProduct").exists() {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}
