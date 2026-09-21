pub mod keygen;
pub mod verify_report;

pub use keygen::*;
pub use verify_report::*;

use crate::core::{MediaPath, StageError, StageResult, Verdict};
use crate::disk::partition::{parse_disk_layout, DiskLayout};
use crate::disk::snapshot::hash_device_or_image;
use crate::fs::{extract_filesystem_files, DiscoveredFile};
use crate::policy::verify::verify_ed25519_signature;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifestEntry {
    pub path: MediaPath,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMismatch {
    pub component: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub valid: bool,
    pub mismatches: Vec<VerificationMismatch>,
    pub manifest_station_id: String,
    pub manifest_verdict: Verdict,
}

fn default_sector_size() -> u32 {
    512
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub station_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default = "default_sector_size")]
    pub sector_size: u32,
    pub device_identity: Option<DeviceIdentity>,
    pub device_size_bytes: u64,
    pub device_hash: String,
    pub partition_layout_hash: String,
    pub files: Vec<FileManifestEntry>,
    pub policy_hash: String,
    pub stages_required: Vec<String>,
    pub stages_completed: Vec<StageResult>,
    pub verdict: Verdict,
    pub signature: Option<String>,
}

impl Manifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StageError> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(|e| {
            StageError::Internal(format!("failed to serialize manifest for signing: {e}"))
        })
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), StageError> {
        let bytes = self.canonical_bytes()?;
        let sig = key.sign(&bytes);
        self.signature = Some(hex_encode(&sig.to_bytes()));
        Ok(())
    }

    pub fn verify_signature(&self, pubkey: &VerifyingKey) -> Result<(), StageError> {
        let sig_str = self
            .signature
            .as_ref()
            .ok_or_else(|| StageError::Parse("manifest signature is missing".to_string()))?;

        let sig_bytes = hex_decode(sig_str.as_bytes())?;
        let canonical = self.canonical_bytes()?;

        verify_ed25519_signature(&canonical, &sig_bytes, pubkey.as_bytes())
    }

    pub fn verify_against_media(
        &self,
        device_path: &Path,
        pubkey: &VerifyingKey,
    ) -> Result<VerificationReport, StageError> {
        self.verify_against_media_with_nonce_log(device_path, pubkey, None)
    }

    pub fn verify_against_media_with_nonce_log(
        &self,
        device_path: &Path,
        pubkey: &VerifyingKey,
        nonce_log_path: Option<&Path>,
    ) -> Result<VerificationReport, StageError> {
        let mut mismatches = Vec::new();

        if let Err(e) = self.verify_signature(pubkey) {
            mismatches.push(VerificationMismatch {
                component: "signature".to_string(),
                expected: "valid Ed25519 signature".to_string(),
                actual: format!("{e}"),
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.expires_at > 0 && now > self.expires_at {
            mismatches.push(VerificationMismatch {
                component: "expiration".to_string(),
                expected: format!("manifest valid until timestamp {}", self.expires_at),
                actual: format!("current timestamp {now} is expired"),
            });
        }

        if self.issued_at > now.saturating_add(300) {
            mismatches.push(VerificationMismatch {
                component: "issued_at".to_string(),
                expected: format!("manifest issued in past (<= {now})"),
                actual: format!("manifest issued in future ({})", self.issued_at),
            });
        }

        if self.expires_at > 0 && self.expires_at < self.issued_at {
            mismatches.push(VerificationMismatch {
                component: "validity_window".to_string(),
                expected: "expires_at >= issued_at".to_string(),
                actual: format!(
                    "expires_at {} is before issued_at {}",
                    self.expires_at, self.issued_at
                ),
            });
        }

        if let Some(log_path) = nonce_log_path {
            if log_path.exists() {
                if let Ok(content) = std::fs::read_to_string(log_path) {
                    if content.lines().any(|l| l.trim() == self.nonce.trim()) {
                        mismatches.push(VerificationMismatch {
                            component: "nonce_replay".to_string(),
                            expected: "unique unused manifest nonce".to_string(),
                            actual: format!(
                                "nonce '{}' already accepted in previous verification",
                                self.nonce
                            ),
                        });
                    }
                }
            }
        }

        let (current_device_hash, current_size) = hash_device_or_image(device_path)?;

        if current_size != self.device_size_bytes {
            mismatches.push(VerificationMismatch {
                component: "device_size".to_string(),
                expected: self.device_size_bytes.to_string(),
                actual: current_size.to_string(),
            });
        }

        if current_device_hash != self.device_hash {
            mismatches.push(VerificationMismatch {
                component: "device_hash".to_string(),
                expected: self.device_hash.clone(),
                actual: current_device_hash,
            });
        }

        let mut file = File::open(device_path).map_err(|e| {
            StageError::Io(format!(
                "failed to open media {}: {e}",
                device_path.display()
            ))
        })?;

        let eff_sector = if self.sector_size == 0 {
            512
        } else {
            self.sector_size
        };

        let layout = parse_disk_layout(&mut file, current_size, eff_sector)?;
        let current_layout_hash = compute_layout_hash(&layout);

        if current_layout_hash != self.partition_layout_hash {
            mismatches.push(VerificationMismatch {
                component: "partition_layout_hash".to_string(),
                expected: self.partition_layout_hash.clone(),
                actual: current_layout_hash,
            });
        }

        let discovered = extract_filesystem_files(&mut file, current_size, eff_sector)?;
        let current_files = hash_discovered_files(&mut file, &discovered)?;

        if current_files.len() != self.files.len() {
            mismatches.push(VerificationMismatch {
                component: "file_count".to_string(),
                expected: self.files.len().to_string(),
                actual: current_files.len().to_string(),
            });
        }

        for expected_file in &self.files {
            match current_files.iter().find(|f| f.path == expected_file.path) {
                Some(actual_file) => {
                    if actual_file.hash != expected_file.hash
                        || actual_file.size != expected_file.size
                    {
                        mismatches.push(VerificationMismatch {
                            component: format!("file:{}", expected_file.path),
                            expected: format!(
                                "hash:{} size:{}",
                                expected_file.hash, expected_file.size
                            ),
                            actual: format!("hash:{} size:{}", actual_file.hash, actual_file.size),
                        });
                    }
                }
                None => {
                    mismatches.push(VerificationMismatch {
                        component: format!("file:{}", expected_file.path),
                        expected: "present on media".to_string(),
                        actual: "missing from media".to_string(),
                    });
                }
            }
        }

        for current_file in &current_files {
            if !self.files.iter().any(|f| f.path == current_file.path) {
                mismatches.push(VerificationMismatch {
                    component: format!("file:{}", current_file.path),
                    expected: "not in manifest".to_string(),
                    actual: "unexpected extra file on media".to_string(),
                });
            }
        }

        if mismatches.is_empty() {
            if let Some(log_path) = nonce_log_path {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                {
                    let _ = writeln!(f, "{}", self.nonce.trim());
                }
            }
        }

        Ok(VerificationReport {
            valid: mismatches.is_empty(),
            mismatches,
            manifest_station_id: self.station_id.clone(),
            manifest_verdict: self.verdict,
        })
    }
}

pub fn check_and_record_nonce(nonce: &str, log_path: &Path) -> Result<bool, StageError> {
    if log_path.exists() {
        let content = std::fs::read_to_string(log_path)
            .map_err(|e| StageError::Io(format!("failed to read nonce replay log: {e}")))?;
        for line in content.lines() {
            if line.trim() == nonce.trim() {
                return Ok(false);
            }
        }
    }

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| StageError::Io(format!("failed to open nonce replay log: {e}")))?;

    writeln!(file, "{}", nonce.trim())
        .map_err(|e| StageError::Io(format!("failed to append to nonce replay log: {e}")))?;

    Ok(true)
}

pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut bytes).is_ok() {
            return hex_encode(&bytes);
        }
    }
    #[cfg(unix)]
    {
        let res = unsafe {
            libc::getrandom(
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                0,
            )
        };
        if res == bytes.len() as isize {
            return hex_encode(&bytes);
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let tid = nix::unistd::gettid().as_raw();
    let hash = blake3::hash(format!("{now}:{pid}:{tid}").as_bytes());
    hash.to_hex()[..32].to_string()
}

pub fn compute_layout_hash(layout: &DiskLayout) -> String {
    let serialized = serde_json::to_string(layout).unwrap_or_default();
    blake3::hash(serialized.as_bytes()).to_hex().to_string()
}

pub fn hash_discovered_files<R: Read + Seek>(
    file: &mut R,
    discovered: &[DiscoveredFile],
) -> Result<Vec<FileManifestEntry>, StageError> {
    let mut entries = Vec::new();

    for entry in discovered {
        if entry.is_dir {
            continue;
        }

        let hash = if entry.size == 0 {
            blake3::hash(b"").to_hex().to_string()
        } else if let Some(offset) = entry.data_offset {
            file.seek(SeekFrom::Start(offset)).map_err(|e| {
                StageError::Io(format!(
                    "failed to seek to file offset 0x{offset:x} for {}: {e}",
                    entry.path
                ))
            })?;

            let mut hasher = blake3::Hasher::new();
            let mut remaining = entry.size;
            let mut buf = vec![0u8; 64 * 1024];

            while remaining > 0 {
                let to_read = (remaining as usize).min(buf.len());
                let bytes_read = file.read(&mut buf[..to_read]).map_err(|e| {
                    StageError::Io(format!("failed to read file data for {}: {e}", entry.path))
                })?;

                if bytes_read == 0 {
                    break;
                }

                hasher.update(&buf[..bytes_read]);
                remaining = remaining.saturating_sub(bytes_read as u64);
            }

            hasher.finalize().to_hex().to_string()
        } else {
            blake3::hash(b"").to_hex().to_string()
        };

        entries.push(FileManifestEntry {
            path: entry.path.clone(),
            size: entry.size,
            hash,
        });
    }

    Ok(entries)
}
