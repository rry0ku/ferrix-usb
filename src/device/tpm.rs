use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmStatus {
    pub present: bool,
    pub device_node: Option<String>,
    pub hardware_id: Option<String>,
}

pub fn query_tpm_status() -> TpmStatus {
    let tpm_nodes = ["/dev/tpmrm0", "/dev/tpm0"];
    for node in tpm_nodes {
        if Path::new(node).exists() {
            let hw_id = fs::read_to_string("/sys/class/tpm/tpm0/device/description")
                .ok()
                .or_else(|| fs::read_to_string("/sys/class/tpm/tpm0/device/id").ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "TPM2.0-Generic".to_string());

            return TpmStatus {
                present: true,
                device_node: Some(node.to_string()),
                hardware_id: Some(hw_id),
            };
        }
    }

    TpmStatus {
        present: false,
        device_node: None,
        hardware_id: None,
    }
}
