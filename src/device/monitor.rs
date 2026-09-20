use crate::core::StageError;
use crate::device::descriptors::{read_usb_device_from_sysfs, UsbDevice};

#[derive(Debug, Clone)]
pub struct DeviceMonitor {
    pub initial_device: UsbDevice,
}

impl DeviceMonitor {
    pub fn new(initial_device: UsbDevice) -> Self {
        Self { initial_device }
    }

    pub fn verify_device_unchanged(&self) -> Result<(), StageError> {
        let current =
            read_usb_device_from_sysfs(&self.initial_device.sysfs_path).map_err(|_| {
                StageError::Internal("Device disconnected! Inspection aborted.".to_string())
            })?;

        if current.vendor_id != self.initial_device.vendor_id
            || current.product_id != self.initial_device.product_id
            || current.serial != self.initial_device.serial
            || current.interfaces != self.initial_device.interfaces
        {
            return Err(StageError::Internal(
                "Device identity changed! Inspection aborted.".to_string(),
            ));
        }

        Ok(())
    }
}
