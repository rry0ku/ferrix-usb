use crate::core::{Confidence, Finding, Location, Severity};

pub fn check_fs_size_mismatch(
    partition_index: u32,
    fs_name: &str,
    fs_sectors: u64,
    partition_sectors: u64,
    findings: &mut Vec<Finding>,
) {
    if partition_sectors == 0 {
        return;
    }

    if fs_sectors > partition_sectors {
        findings.push(Finding {
            id: "FX-FS-001".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "filesystem_scan".to_string(),
            location: Location::Partition(partition_index),
            reason: format!("{fs_name} filesystem exceeds partition boundary"),
            evidence: format!(
                "filesystem claims {fs_sectors} sectors, but partition only contains {partition_sectors} sectors"
            ),
        });
    } else if partition_sectors.saturating_sub(fs_sectors) > (partition_sectors / 10) {
        findings.push(Finding {
            id: "FX-FS-001".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            stage: "filesystem_scan".to_string(),
            location: Location::Partition(partition_index),
            reason: format!("{fs_name} filesystem significantly smaller than partition"),
            evidence: format!(
                "filesystem claims {fs_sectors} sectors, leaving substantial unallocated space in partition ({partition_sectors} sectors)"
            ),
        });
    }
}

pub fn check_boot_sector_inconsistency(
    partition_index: u32,
    fs_name: &str,
    issue: &str,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding {
        id: "FX-FS-002".to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        stage: "filesystem_scan".to_string(),
        location: Location::Partition(partition_index),
        reason: format!("inconsistent {fs_name} boot sector structure"),
        evidence: issue.to_string(),
    });
}

pub fn check_backup_boot_sector_mismatch(
    partition_index: u32,
    fs_name: &str,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding {
        id: "FX-FS-002".to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        stage: "filesystem_scan".to_string(),
        location: Location::Partition(partition_index),
        reason: format!("primary and backup {fs_name} boot sector mismatch"),
        evidence: format!(
            "primary {fs_name} boot sector differs from secondary/backup boot sector"
        ),
    });
}

pub fn check_duplicate_entries(
    partition_index: u32,
    duplicates: &[String],
    findings: &mut Vec<Finding>,
) {
    for name in duplicates {
        findings.push(Finding {
            id: "FX-FS-003".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "filesystem_scan".to_string(),
            location: Location::Partition(partition_index),
            reason: "duplicate or conflicting directory entry detected".to_string(),
            evidence: format!("directory contains conflicting duplicate entry for '{name}'"),
        });
    }
}

pub fn check_polyglot_signatures(
    partition_index: u32,
    detected_filesystems: &[&str],
    findings: &mut Vec<Finding>,
) {
    if detected_filesystems.len() > 1 {
        let joined = detected_filesystems.join(", ");
        findings.push(Finding {
            id: "FX-FS-004".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "filesystem_scan".to_string(),
            location: Location::Partition(partition_index),
            reason: "multiple valid filesystem signatures in single partition (polyglot)"
                .to_string(),
            evidence: format!("partition contains valid signatures for: {joined}"),
        });
    }
}

pub fn check_unsupported_filesystem(
    partition_index: u32,
    fs_name: &str,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding {
        id: "FX-FS-005".to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        stage: "filesystem_scan".to_string(),
        location: Location::Partition(partition_index),
        reason: format!("unsupported file layer extraction for {fs_name} filesystem"),
        evidence: format!(
            "partition contains {fs_name} filesystem which cannot be safely inspected at file layer without mounting"
        ),
    });
}
