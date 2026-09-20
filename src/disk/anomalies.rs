use crate::core::{Confidence, Finding, Location, Severity};
use crate::disk::partition::{DiskLayout, PartitionTableType};
use std::io::{Read, Seek, SeekFrom};

pub fn check_partition_anomalies<R: Read + Seek>(
    layout: &DiskLayout,
    reader: &mut R,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_overlapping_partitions(layout, &mut findings);
    check_out_of_bounds_partitions(layout, &mut findings);
    check_mbr_gpt_agreement(layout, &mut findings);
    check_gpt_backup_integrity(layout, &mut findings);
    check_hidden_partition_types(layout, &mut findings);
    check_unallocated_data(layout, reader, &mut findings);

    findings
}

fn check_overlapping_partitions(layout: &DiskLayout, findings: &mut Vec<Finding>) {
    let partitions = &layout.partitions;
    for i in 0..partitions.len() {
        for j in (i + 1)..partitions.len() {
            let p1 = &partitions[i];
            let p2 = &partitions[j];

            let is_p1_ext = matches!(p1.type_byte, Some(0x05 | 0x0F | 0x85));
            let is_p2_ext = matches!(p2.type_byte, Some(0x05 | 0x0F | 0x85));
            if (is_p1_ext && p2.start_lba >= p1.start_lba && p2.end_lba <= p1.end_lba)
                || (is_p2_ext && p1.start_lba >= p2.start_lba && p1.end_lba <= p2.end_lba)
            {
                continue;
            }

            if p1.start_lba <= p2.end_lba && p2.start_lba <= p1.end_lba {
                findings.push(Finding {
                    id: "FX-PART-001".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "partition_scan".to_string(),
                    location: Location::Partition(p1.index),
                    reason: "overlapping partitions detected".to_string(),
                    evidence: format!(
                        "partition {} (LBA {}-{}) overlaps with partition {} (LBA {}-{})",
                        p1.index, p1.start_lba, p1.end_lba, p2.index, p2.start_lba, p2.end_lba
                    ),
                });
            }
        }
    }
}

fn check_out_of_bounds_partitions(layout: &DiskLayout, findings: &mut Vec<Finding>) {
    for p in &layout.partitions {
        if p.start_lba >= layout.total_sectors
            || p.end_lba >= layout.total_sectors
            || p.start_lba > p.end_lba
            || p.total_sectors == 0
        {
            findings.push(Finding {
                id: "FX-PART-002".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "partition_scan".to_string(),
                location: Location::Partition(p.index),
                reason: "partition extends beyond device boundary or has invalid range".to_string(),
                evidence: format!(
                    "partition {} range {}-{} (sectors: {}) invalid for total device sectors {}",
                    p.index, p.start_lba, p.end_lba, p.total_sectors, layout.total_sectors
                ),
            });
        }
    }
}

fn check_mbr_gpt_agreement(layout: &DiskLayout, findings: &mut Vec<Finding>) {
    if layout.table_type == PartitionTableType::Gpt && !layout.has_protective_mbr {
        findings.push(Finding {
            id: "FX-PART-003".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Device,
            reason: "protective MBR missing for GPT disk".to_string(),
            evidence: "GPT structures found but LBA 0 lacks protective MBR (type 0xEE)".to_string(),
        });
    } else if layout.table_type == PartitionTableType::Hybrid {
        findings.push(Finding {
            id: "FX-PART-003".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Device,
            reason: "hybrid MBR / GPT disagreement detected".to_string(),
            evidence: "GPT disk contains conflicting active MBR partition records".to_string(),
        });
    } else if layout.has_protective_mbr && !layout.primary_gpt_valid && !layout.backup_gpt_valid {
        findings.push(Finding {
            id: "FX-PART-003".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Device,
            reason: "protective MBR present but GPT is invalid or missing".to_string(),
            evidence: "LBA 0 contains protective MBR (type 0xEE) but neither primary nor backup GPT is valid".to_string(),
        });
    }
}

fn check_gpt_backup_integrity(layout: &DiskLayout, findings: &mut Vec<Finding>) {
    if layout.primary_gpt_valid && !layout.backup_gpt_valid {
        findings.push(Finding {
            id: "FX-PART-004".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Device,
            reason: "backup GPT header or table is corrupted or missing".to_string(),
            evidence: "primary GPT valid but secondary GPT at end of disk failed verification"
                .to_string(),
        });
    } else if !layout.primary_gpt_valid && layout.backup_gpt_valid {
        findings.push(Finding {
            id: "FX-PART-004".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Device,
            reason: "primary GPT header is corrupted or missing".to_string(),
            evidence: "primary GPT failed verification; only secondary GPT is valid".to_string(),
        });
    } else if layout.gpt_differs_from_backup {
        findings.push(Finding {
            id: "FX-PART-004".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Device,
            reason: "primary and backup GPT partition entries differ".to_string(),
            evidence: "primary GPT partition table does not match secondary GPT partition table"
                .to_string(),
        });
    } else if layout.backup_gpt_lba_mismatch {
        findings.push(Finding {
            id: "FX-PART-004".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "partition_scan".to_string(),
            location: Location::Device,
            reason: "primary GPT points to unexpected backup LBA".to_string(),
            evidence: "backup LBA in primary GPT header does not match end of device".to_string(),
        });
    }
}

fn check_hidden_partition_types(layout: &DiskLayout, findings: &mut Vec<Finding>) {
    for p in &layout.partitions {
        if let Some(t) = p.type_byte {
            let is_hidden = matches!(t, 0x11 | 0x14 | 0x16 | 0x17 | 0x1B | 0x1C | 0x1E | 0x27);
            if is_hidden {
                findings.push(Finding {
                    id: "FX-PART-006".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                    stage: "partition_scan".to_string(),
                    location: Location::Partition(p.index),
                    reason: "hidden or recovery partition type detected".to_string(),
                    evidence: format!("partition {} uses hidden type 0x{:02x}", p.index, t),
                });
            }
        }
    }
}

fn check_unallocated_data<R: Read + Seek>(
    layout: &DiskLayout,
    reader: &mut R,
    findings: &mut Vec<Finding>,
) {
    if layout.partitions.is_empty() {
        return;
    }

    let mut sorted_partitions = layout.partitions.clone();
    sorted_partitions.sort_by_key(|p| p.start_lba);

    let start_threshold = match layout.table_type {
        PartitionTableType::Gpt | PartitionTableType::Hybrid => 34,
        _ => 1,
    };

    let end_threshold = match layout.table_type {
        PartitionTableType::Gpt | PartitionTableType::Hybrid => {
            layout.total_sectors.saturating_sub(34)
        }
        _ => layout.total_sectors.saturating_sub(1),
    };

    let mut gaps = Vec::new();
    let mut current_pos = start_threshold;

    for p in &sorted_partitions {
        if p.start_lba > p.end_lba || p.total_sectors == 0 {
            continue;
        }
        if p.start_lba > current_pos {
            let gap_end = p.start_lba.saturating_sub(1).min(end_threshold);
            if current_pos <= gap_end {
                gaps.push((current_pos, gap_end));
            }
        }
        current_pos = current_pos.max(p.end_lba.saturating_add(1));
    }

    if current_pos <= end_threshold {
        gaps.push((current_pos, end_threshold));
    }

    let sector_size = layout.sector_size as usize;
    let mut sector_buf = vec![0u8; sector_size];

    for (gap_start, gap_end) in gaps {
        let total_gap_sectors = gap_end.saturating_sub(gap_start).saturating_add(1);

        let mut sample_ranges = Vec::new();
        if total_gap_sectors <= 1024 {
            sample_ranges.push(0..total_gap_sectors);
        } else {
            sample_ranges.push(0..128);
            sample_ranges.push(total_gap_sectors.saturating_sub(128)..total_gap_sectors);
        }

        let mut found_non_zero = false;
        for range in sample_ranges {
            if found_non_zero {
                break;
            }
            for s in range {
                let lba = gap_start + s;
                let offset = lba.saturating_mul(layout.sector_size as u64);

                if reader.seek(SeekFrom::Start(offset)).is_err() {
                    break;
                }

                if reader.read_exact(&mut sector_buf).is_err() {
                    break;
                }

                if sector_buf.iter().any(|&b| b != 0) {
                    findings.push(Finding {
                        id: "FX-PART-005".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        stage: "partition_scan".to_string(),
                        location: Location::ByteOffset(offset),
                        reason: "non-zero data detected in unallocated gap".to_string(),
                        evidence: format!(
                            "unallocated space at LBA {}-{} contains non-zero data at LBA {}",
                            gap_start, gap_end, lba
                        ),
                    });
                    found_non_zero = true;
                    break;
                }
            }
        }
    }
}
