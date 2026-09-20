pub mod model;
pub mod parser;
pub mod verify;

pub use model::*;
pub use parser::*;
pub use verify::*;

use crate::core::{
    Confidence, Finding, Location, ScanContext, Severity, Stage, StageError, StageResult,
    StageStatus, Verdict,
};
use crate::disk::partition::parse_disk_layout;
use crate::fs::{
    extract_filesystem_files, parse_exfat_boot_sector, parse_ext_superblock, parse_fat_boot_sector,
    parse_ntfs_boot_sector,
};
use crate::scan::magic::{detect_content_type, DetectedType, RiskClass};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub fn find_station_pubkey(policy_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = policy_path {
        if let Some(parent) = p.parent() {
            let local_pub = parent.join("station.pub");
            if local_pub.exists() {
                return Some(local_pub);
            }
        }
    }
    let cwd_pub = PathBuf::from("station.pub");
    if cwd_pub.exists() {
        return Some(cwd_pub);
    }
    let etc_pub = PathBuf::from("/etc/ferrix/station.pub");
    if etc_pub.exists() {
        return Some(etc_pub);
    }
    None
}

pub fn load_policy(
    policy_path: Option<&Path>,
    pubkey_path: Option<&Path>,
) -> (Policy, Option<String>) {
    let path = match policy_path {
        Some(p) => p,
        None => return (Policy::strict_default(), None),
    };

    if !path.exists() {
        return (
            Policy::strict_default(),
            Some(format!(
                "Warning: policy file '{}' does not exist. Using strict built-in default.",
                path.display()
            )),
        );
    }

    let key_path = match pubkey_path {
        Some(k) => {
            if k.exists() {
                Some(k.to_path_buf())
            } else {
                None
            }
        }
        None => find_station_pubkey(Some(path)),
    };

    let resolved_key = match key_path {
        Some(k) => k,
        None => {
            return (
                Policy::strict_default(),
                Some(format!(
                    "Warning: station public key not found for policy '{}'. Refusing unsigned policy and using strict built-in default.",
                    path.display()
                )),
            );
        }
    };

    let verified_bytes = match verify_policy_file(path, &resolved_key) {
        Ok(b) => b,
        Err(e) => {
            return (
                Policy::strict_default(),
                Some(format!(
                    "Warning: policy signature verification failed for '{}': {e}. Refusing policy and using strict built-in default.",
                    path.display()
                )),
            );
        }
    };

    let policy_str = match std::str::from_utf8(&verified_bytes) {
        Ok(s) => s,
        Err(e) => {
            return (
                Policy::strict_default(),
                Some(format!(
                    "Warning: policy file '{}' is not valid UTF-8: {e}. Using strict built-in default.",
                    path.display()
                )),
            );
        }
    };

    match parse_policy_str(policy_str) {
        Ok(pol) => (pol, None),
        Err(e) => (
            Policy::strict_default(),
            Some(format!(
                "Warning: failed to parse policy file '{}': {e}. Using strict built-in default.",
                path.display()
            )),
        ),
    }
}

pub fn is_fs_allowed(fs_name: &str, allowed: &[String]) -> bool {
    let fs_lower = fs_name.to_lowercase();
    for a in allowed {
        let a_lower = a.to_lowercase();
        if fs_lower == a_lower {
            return true;
        }
        if fs_lower.starts_with("fat") && a_lower == "fat" {
            return true;
        }
        if fs_lower == "fat32" && (a_lower == "fat" || a_lower == "fat32") {
            return true;
        }
        if (fs_lower == "fat16" || fs_lower == "fat12")
            && (a_lower == "fat" || a_lower == "fat16" || a_lower == "fat12")
        {
            return true;
        }
        if fs_lower == "exfat" && a_lower == "exfat" {
            return true;
        }
        if fs_lower == "ntfs" && a_lower == "ntfs" {
            return true;
        }
        if (fs_lower == "ext4" || fs_lower == "ext") && (a_lower == "ext4" || a_lower == "ext") {
            return true;
        }
    }
    false
}

pub fn is_os_artifact_path(path: &str) -> bool {
    let clean = path.trim_start_matches('/').trim_start_matches('\\');
    let segments: Vec<&str> = clean.split(['/', '\\']).collect();
    for seg in &segments {
        let s = seg.to_ascii_lowercase();
        if s == "system volume information"
            || s == "$recycle.bin"
            || s == "recycler"
            || s == ".trashes"
            || s == ".fseventsd"
            || s == ".spotlight-v100"
            || s == ".temporaryitems"
            || s == ".ds_store"
            || s == "lost+found"
            || s == "desktop.ini"
            || s == "thumbs.db"
        {
            return true;
        }
    }
    false
}

pub fn is_type_allowed(detected: DetectedType, filename: &str, allowed_types: &[String]) -> bool {
    let lower_filename = filename.to_lowercase();
    let ext = lower_filename.rsplit('.').next().unwrap_or("");
    let expected_class = crate::scan::magic::expected_risk_class_from_extension(ext);
    let is_exec =
        detected.risk_class() == RiskClass::Executable || expected_class == RiskClass::Executable;

    if allowed_types.is_empty() {
        return !is_exec;
    }

    for allowed in allowed_types {
        let a = allowed.to_lowercase();
        if (a == "*" || a == "all" || a == "any" || a == "non-executable") && !is_exec {
            return true;
        }
        if a == "document"
            && !is_exec
            && (detected.risk_class() == RiskClass::Document
                || expected_class == RiskClass::Document)
        {
            return true;
        }
        if a == "image"
            && !is_exec
            && (detected.risk_class() == RiskClass::Image || expected_class == RiskClass::Image)
        {
            return true;
        }
        if a == "audio"
            && !is_exec
            && (detected.risk_class() == RiskClass::Audio || expected_class == RiskClass::Audio)
        {
            return true;
        }
        if a == "video"
            && !is_exec
            && (detected.risk_class() == RiskClass::Video || expected_class == RiskClass::Video)
        {
            return true;
        }
        if a == "media"
            && !is_exec
            && (detected.risk_class() == RiskClass::Audio
                || detected.risk_class() == RiskClass::Video
                || expected_class == RiskClass::Audio
                || expected_class == RiskClass::Video)
        {
            return true;
        }
        if a == "archive"
            && !is_exec
            && (detected.risk_class() == RiskClass::Archive || expected_class == RiskClass::Archive)
        {
            return true;
        }
        if a == "text"
            && !is_exec
            && (detected.risk_class() == RiskClass::Text || expected_class == RiskClass::Text)
        {
            return true;
        }
        if a == "data"
            && !is_exec
            && (detected.risk_class() == RiskClass::Data || expected_class == RiskClass::Data)
        {
            return true;
        }
        match detected {
            DetectedType::Pdf if a == "pdf" => return true,
            DetectedType::PlainText => {
                if a == "txt" || a == "text" {
                    return true;
                }
                if !ext.is_empty() && a == ext {
                    return true;
                }
            }
            DetectedType::Png if a == "png" => return true,
            DetectedType::Jpeg if a == "jpg" || a == "jpeg" => return true,
            DetectedType::Gif if a == "gif" => return true,
            DetectedType::Bmp if a == "bmp" => return true,
            DetectedType::Webp if a == "webp" => return true,
            DetectedType::Svg if a == "svg" => return true,
            DetectedType::Mp3 if a == "mp3" => return true,
            DetectedType::Flac if a == "flac" => return true,
            DetectedType::Wav if a == "wav" => return true,
            DetectedType::Ogg if a == "ogg" => return true,
            DetectedType::Mp4 if a == "mp4" || a == "m4a" => return true,
            DetectedType::Mkv if a == "mkv" || a == "webm" => return true,
            DetectedType::Avi if a == "avi" => return true,
            DetectedType::ZipOrOffice => {
                if a == "zip" {
                    return true;
                }
                if !ext.is_empty() && a == ext {
                    return true;
                }
            }
            DetectedType::SevenZip if a == "7z" => return true,
            DetectedType::Gzip if a == "gz" || a == "gzip" => return true,
            DetectedType::Tar if a == "tar" => return true,
            DetectedType::Bzip2 if a == "bz2" || a == "bzip2" => return true,
            DetectedType::Xz if a == "xz" => return true,
            DetectedType::Rar if a == "rar" => return true,
            DetectedType::Sqlite if a == "sqlite" || a == "db" => return true,
            DetectedType::Pe if a == "exe" || a == "pe" => return true,
            DetectedType::Elf if a == "elf" => return true,
            DetectedType::MachO if a == "macho" => return true,
            DetectedType::ShellScript if a == "sh" || a == "shell" => return true,
            DetectedType::WindowsScript if a == "bat" || a == "cmd" || a == "ps1" || a == "vbs" => {
                return true
            }
            DetectedType::Unknown => {
                if a == "unknown" || a == "bin" || a == "raw" {
                    return true;
                }
                if !ext.is_empty() && a == ext && !is_exec {
                    return true;
                }
            }
            _ => {}
        }
        if !ext.is_empty() && a == ext && !is_exec {
            return true;
        }
    }
    false
}

pub fn resolve_verdict_with_policy(
    required_stages: &[&str],
    completed_stages: &[StageResult],
    findings: &[Finding],
    policy: &Policy,
) -> Verdict {
    for required in required_stages {
        match completed_stages.iter().find(|s| s.stage_id == *required) {
            Some(res) => {
                if res.status != StageStatus::Ok {
                    return match policy.on_high {
                        VerdictAction::Fail => Verdict::Fail,
                        VerdictAction::Quarantine => Verdict::Quarantine,
                        VerdictAction::Pass => Verdict::Pass,
                    };
                }
            }
            None => {
                return match policy.on_high {
                    VerdictAction::Fail => Verdict::Fail,
                    VerdictAction::Quarantine => Verdict::Quarantine,
                    VerdictAction::Pass => Verdict::Pass,
                };
            }
        }
    }

    for stage in completed_stages {
        if stage.status != StageStatus::Ok {
            return match policy.on_high {
                VerdictAction::Fail => Verdict::Fail,
                VerdictAction::Quarantine => Verdict::Quarantine,
                VerdictAction::Pass => Verdict::Pass,
            };
        }
    }

    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return match policy.on_critical {
            VerdictAction::Fail => Verdict::Fail,
            VerdictAction::Quarantine => Verdict::Quarantine,
            VerdictAction::Pass => Verdict::Pass,
        };
    }

    if findings.iter().any(|f| f.severity == Severity::High) {
        return match policy.on_high {
            VerdictAction::Fail => Verdict::Fail,
            VerdictAction::Quarantine => Verdict::Quarantine,
            VerdictAction::Pass => Verdict::Pass,
        };
    }

    if findings.iter().any(|f| f.severity == Severity::Medium) {
        return match policy.on_medium {
            VerdictAction::Fail => Verdict::Fail,
            VerdictAction::Quarantine => Verdict::Quarantine,
            VerdictAction::Pass => Verdict::Pass,
        };
    }

    Verdict::Pass
}

pub struct PolicyScanStage {
    pub policy: Policy,
    pub sector_size: u32,
}

impl PolicyScanStage {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            sector_size: 512,
        }
    }

    pub fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = sector_size;
        self
    }
}

impl Default for PolicyScanStage {
    fn default() -> Self {
        Self::new(Policy::strict_default())
    }
}

impl Stage for PolicyScanStage {
    fn id(&self) -> &'static str {
        "policy_scan"
    }

    fn name(&self) -> &'static str {
        "Default-Deny Policy Compliance Inspection"
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError> {
        let scan_path = ctx.snapshot_path.as_ref().unwrap_or(&ctx.target_path);
        let mut file = File::open(scan_path).map_err(|e| {
            StageError::Io(format!(
                "failed to open scan target {}: {e}",
                scan_path.display()
            ))
        })?;

        let mut total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
        if total_bytes == 0 {
            if let Ok(end_pos) = file.seek(SeekFrom::End(0)) {
                total_bytes = end_pos;
                let _ = file.seek(SeekFrom::Start(0));
            }
        }

        ctx.event_sink.emit(crate::core::ScanEvent::Progress {
            stage_id: self.id().to_string(),
            current: 1,
            total: Some(3),
            message: Some("Checking partition counts and filesystem allowlists...".to_string()),
        });

        let layout = parse_disk_layout(&mut file, total_bytes, self.sector_size)?;
        let mut findings = Vec::new();

        if layout.partitions.len() > self.policy.max_partitions {
            findings.push(Finding {
                id: "FX-POL-001".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "policy_scan".to_string(),
                location: Location::Device,
                reason: "partition count exceeds policy limit".to_string(),
                evidence: format!(
                    "found {} partitions, policy allows at most {}",
                    layout.partitions.len(),
                    self.policy.max_partitions
                ),
            });
        }

        let partition_targets: Vec<(u32, u64, u64)> = if layout.partitions.is_empty() {
            vec![(0, 0, total_bytes / self.sector_size as u64)]
        } else {
            layout
                .partitions
                .iter()
                .map(|p| (p.index, p.start_lba, p.total_sectors))
                .collect()
        };

        for (part_index, start_lba, _total_sectors) in partition_targets {
            let part_offset = start_lba.saturating_mul(self.sector_size as u64);

            if file.seek(SeekFrom::Start(part_offset)).is_err() {
                continue;
            }

            let mut sector0 = vec![0u8; 512];
            if file.read_exact(&mut sector0).is_err() {
                continue;
            }

            let mut detected_fs = Vec::new();

            if let Ok(fat) = parse_fat_boot_sector(&sector0) {
                detected_fs.push(match fat.fat_type {
                    crate::fs::FatType::Fat12 => "FAT12",
                    crate::fs::FatType::Fat16 => "FAT16",
                    crate::fs::FatType::Fat32 => "FAT32",
                });
            }

            if parse_exfat_boot_sector(&sector0).is_ok() {
                detected_fs.push("exFAT");
            }

            if parse_ntfs_boot_sector(&sector0).is_ok() {
                detected_fs.push("NTFS");
            }

            let ext_offset = part_offset.saturating_add(1024);
            if file.seek(SeekFrom::Start(ext_offset)).is_ok() {
                let mut ext_buf = vec![0u8; 1024];
                if file.read_exact(&mut ext_buf).is_ok() && parse_ext_superblock(&ext_buf).is_ok() {
                    detected_fs.push("ext4");
                }
            }

            for fs_name in detected_fs {
                if !is_fs_allowed(fs_name, &self.policy.allowed_filesystems) {
                    findings.push(Finding {
                        id: "FX-POL-002".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "policy_scan".to_string(),
                        location: Location::Partition(part_index),
                        reason: "disallowed filesystem detected".to_string(),
                        evidence: format!(
                            "detected filesystem '{fs_name}' is not in policy allowed_filesystems: {:?}",
                            self.policy.allowed_filesystems
                        ),
                    });
                }
            }
        }

        ctx.event_sink.emit(crate::core::ScanEvent::Progress {
            stage_id: self.id().to_string(),
            current: 2,
            total: Some(3),
            message: Some("Validating files against type & size policy...".to_string()),
        });

        let discovered_files = extract_filesystem_files(&mut file, total_bytes, self.sector_size)?;
        let max_bytes = self.policy.max_file_size_mb.saturating_mul(1024 * 1024);

        for entry in discovered_files {
            if entry.is_dir {
                continue;
            }

            let filename = String::from_utf8_lossy(entry.path.as_bytes()).to_string();

            if entry.size > max_bytes {
                findings.push(Finding {
                    id: "FX-POL-003".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "policy_scan".to_string(),
                    location: Location::Path(entry.path.clone()),
                    reason: "file size exceeds policy limit".to_string(),
                    evidence: format!(
                        "file size {} bytes exceeds policy limit {} MB ({} bytes)",
                        entry.size, self.policy.max_file_size_mb, max_bytes
                    ),
                });
            }

            let mut header_buf = vec![0u8; 4096.min(entry.size as usize)];
            let has_content = if let Some(offset) = entry.data_offset {
                if entry.size > 0 && file.seek(SeekFrom::Start(offset)).is_ok() {
                    file.read_exact(&mut header_buf).is_ok()
                } else {
                    false
                }
            } else {
                false
            };

            let detected = if has_content {
                detect_content_type(&header_buf)
            } else {
                DetectedType::PlainText
            };

            let is_os_artifact = self.policy.allow_os_artifacts && is_os_artifact_path(&filename);
            let is_anomalous_exec = matches!(
                detected,
                DetectedType::Pe
                    | DetectedType::Elf
                    | DetectedType::MachO
                    | DetectedType::ShellScript
                    | DetectedType::WindowsScript
            );

            let is_known_good = if !self.policy.known_good_hashes.is_empty() && entry.size > 0 {
                if let Some(offset) = entry.data_offset {
                    if file.seek(SeekFrom::Start(offset)).is_ok() {
                        let mut hasher = blake3::Hasher::new();
                        let mut remaining = entry.size;
                        let mut chunk = vec![0u8; 64 * 1024];
                        let mut ok = true;
                        while remaining > 0 {
                            let to_read = (remaining as usize).min(chunk.len());
                            if file.read_exact(&mut chunk[..to_read]).is_ok() {
                                hasher.update(&chunk[..to_read]);
                                remaining -= to_read as u64;
                            } else {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            let hash_hex = hasher.finalize().to_hex().to_string();
                            self.policy
                                .known_good_hashes
                                .iter()
                                .any(|h| h.eq_ignore_ascii_case(&hash_hex))
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if is_os_artifact && is_anomalous_exec {
                findings.push(Finding {
                    id: "FX-POL-004".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "policy_scan".to_string(),
                    location: Location::Path(entry.path.clone()),
                    reason: "executable or script hidden inside OS artifact directory".to_string(),
                    evidence: format!(
                        "OS artifact '{}' contains anomalous executable content of type '{}'",
                        filename,
                        detected.name()
                    ),
                });
            } else if !is_os_artifact
                && !is_known_good
                && !is_type_allowed(detected, &filename, &self.policy.allowed_types)
            {
                findings.push(Finding {
                    id: "FX-POL-004".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "policy_scan".to_string(),
                    location: Location::Path(entry.path.clone()),
                    reason: "disallowed file content type detected".to_string(),
                    evidence: format!(
                        "detected content type '{}' is not in policy allowed_types: {:?}",
                        detected.name(),
                        self.policy.allowed_types
                    ),
                });
            }
        }

        Ok(findings)
    }
}
