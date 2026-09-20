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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivePolicy {
    pub max_depth: usize,
    pub max_expansion_ratio: u64,
    pub allow_symlinks: bool,
    pub max_uncompressed_size_mb: u64,
}

impl Default for ArchivePolicy {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_expansion_ratio: 100,
            allow_symlinks: false,
            max_uncompressed_size_mb: 1024,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficePolicy {
    pub allow_macros: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfPolicy {
    pub allow_javascript: bool,
    pub allow_launch_actions: bool,
    pub allow_embedded_files: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilenamePolicy {
    pub allow_unicode: bool,
    pub check_double_extensions: bool,
}

impl Default for FilenamePolicy {
    fn default() -> Self {
        Self {
            allow_unicode: true,
            check_double_extensions: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    pub check_unallocated_remnants: bool,
    pub check_metadata: bool,
    pub require_wipe_verification: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            check_unallocated_remnants: true,
            check_metadata: true,
            require_wipe_verification: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClamAvPolicy {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarvePolicy {
    pub enabled: bool,
    pub max_carved_files: usize,
}

impl Default for CarvePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_carved_files: 100,
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
    pub denied_devices: Vec<DeviceFilter>,
    pub allowed_types: Vec<String>,
    pub allow_os_artifacts: bool,
    pub known_good_hashes: Vec<String>,
    pub yara_rules: Vec<String>,
    pub clamav: ClamAvPolicy,
    pub carve: CarvePolicy,
    pub archives: ArchivePolicy,
    pub office: OfficePolicy,
    pub pdf: PdfPolicy,
    pub filenames: FilenamePolicy,
    pub egress: EgressPolicy,
    pub on_medium: VerdictAction,
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
            denied_devices: Vec::new(),
            allowed_types: vec![
                "*".to_string(),
                "document".to_string(),
                "image".to_string(),
                "audio".to_string(),
                "video".to_string(),
                "archive".to_string(),
                "text".to_string(),
                "data".to_string(),
            ],
            allow_os_artifacts: true,
            known_good_hashes: Vec::new(),
            yara_rules: Vec::new(),
            clamav: ClamAvPolicy::default(),
            carve: CarvePolicy::default(),
            archives: ArchivePolicy::default(),
            office: OfficePolicy::default(),
            pdf: PdfPolicy::default(),
            filenames: FilenamePolicy::default(),
            egress: EgressPolicy::default(),
            on_medium: VerdictAction::Pass,
            on_high: VerdictAction::Quarantine,
            on_critical: VerdictAction::Fail,
        }
    }

    pub fn compute_hash(&self) -> String {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        blake3::hash(serialized.as_bytes()).to_hex().to_string()
    }
}
