use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictAction {
    Pass,
    Quarantine,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFilter {
    pub vendor: String,
    pub product: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivePolicy {
    pub max_depth: usize,
    pub max_expansion_ratio: u64,
}

impl Default for ArchivePolicy {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_expansion_ratio: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub allowed_filesystems: Vec<String>,
    pub max_partitions: usize,
    pub max_file_size_mb: u64,
    pub allowed_devices: Vec<DeviceFilter>,
    pub allowed_types: Vec<String>,
    pub archives: ArchivePolicy,
    pub on_high: VerdictAction,
    pub on_critical: VerdictAction,
}

impl Policy {
    pub fn strict_default() -> Self {
        Self {
            name: "strict-default".to_string(),
            allowed_filesystems: vec!["fat32".to_string(), "exfat".to_string()],
            max_partitions: 1,
            max_file_size_mb: 512,
            allowed_devices: Vec::new(),
            allowed_types: vec![
                "pdf".to_string(),
                "txt".to_string(),
                "png".to_string(),
                "jpg".to_string(),
                "docx".to_string(),
            ],
            archives: ArchivePolicy::default(),
            on_high: VerdictAction::Quarantine,
            on_critical: VerdictAction::Fail,
        }
    }

    pub fn compute_hash(&self) -> String {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        blake3::hash(serialized.as_bytes()).to_hex().to_string()
    }
}
