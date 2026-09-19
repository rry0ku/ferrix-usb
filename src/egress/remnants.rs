use crate::core::{Confidence, Finding, Location, Severity, StageError};
use crate::disk::partition::{DiskLayout, PartitionTableType};
use std::io::{Read, Seek, SeekFrom};

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn find_unallocated_gaps(layout: &DiskLayout) -> Vec<(u64, u64)> {
    if layout.partitions.is_empty() {
        if layout.total_sectors > 1 {
            return vec![(1, layout.total_sectors.saturating_sub(1))];
        }
        return Vec::new();
    }

    let mut sorted = layout.partitions.clone();
    sorted.sort_by_key(|p| p.start_lba);

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

    for p in &sorted {
        if p.start_lba > p.end_lba || p.total_sectors == 0 {
            continue;
        }
        if p.start_lba > current_pos {
            let gap_end = p.start_lba.saturating_sub(1).min(end_threshold);
            if gap_end >= current_pos {
                gaps.push((current_pos, gap_end));
            }
        }
        current_pos = p.end_lba.saturating_add(1).max(current_pos);
    }

    if current_pos <= end_threshold {
        gaps.push((current_pos, end_threshold));
    }

    gaps
}

pub fn scan_unallocated_remnants<R: Read + Seek>(
    reader: &mut R,
    layout: &DiskLayout,
    sector_size: u32,
    findings: &mut Vec<Finding>,
) -> Result<(), StageError> {
    let gaps = find_unallocated_gaps(layout);

    for (gap_start, gap_end) in gaps {
        let gap_sectors = gap_end.saturating_sub(gap_start).saturating_add(1);
        let gap_offset = gap_start.saturating_mul(sector_size as u64);
        let gap_bytes = gap_sectors.saturating_mul(sector_size as u64);

        if reader.seek(SeekFrom::Start(gap_offset)).is_err() {
            continue;
        }

        let mut remaining = gap_bytes;
        let mut chunk_buf = vec![0u8; 64 * 1024];
        let mut current_chunk_offset = gap_offset;

        while remaining > 0 {
            let to_read = (remaining as usize).min(chunk_buf.len());
            let bytes_read = reader
                .read(&mut chunk_buf[..to_read])
                .map_err(|e| StageError::Io(format!("failed to read unallocated gap: {e}")))?;

            if bytes_read == 0 {
                break;
            }

            let slice = &chunk_buf[..bytes_read];
            check_slice_for_remnants(slice, current_chunk_offset, sector_size, findings);

            remaining = remaining.saturating_sub(bytes_read as u64);
            current_chunk_offset = current_chunk_offset.saturating_add(bytes_read as u64);
        }
    }

    Ok(())
}

fn check_slice_for_remnants(
    slice: &[u8],
    base_offset: u64,
    sector_size: u32,
    findings: &mut Vec<Finding>,
) {
    let signatures: &[(&[u8], &str)] = &[
        (b"\x7fELF", "Linux ELF Executable"),
        (b"MZ", "Windows PE Executable"),
        (b"%PDF-", "PDF Document"),
        (b"PK\x03\x04", "ZIP or Office Archive"),
        (b"\xff\xd8\xff", "JPEG Image"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image"),
        (b"SQLite format 3\x00", "SQLite Database"),
        (b"-----BEGIN ", "Cryptographic Key or Certificate"),
    ];

    for i in (0..slice.len()).step_by(512) {
        let sub = &slice[i..];
        for &(sig, name) in signatures {
            if sub.starts_with(sig) {
                let offset = base_offset.saturating_add(i as u64);
                let lba = offset / sector_size as u64;
                findings.push(Finding {
                    id: "FX-EGR-001".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "egress_scan".to_string(),
                    location: Location::ByteOffset(offset),
                    reason: "deleted file remnant detected in unallocated space".to_string(),
                    evidence: format!(
                        "detected signature for '{name}' at byte offset 0x{offset:x} (LBA {lba})"
                    ),
                });
                break;
            }
        }
    }
}

pub fn verify_wipe_pattern<R: Read + Seek>(
    reader: &mut R,
    layout: &DiskLayout,
    sector_size: u32,
    findings: &mut Vec<Finding>,
) -> Result<(), StageError> {
    let gaps = find_unallocated_gaps(layout);

    for (gap_start, gap_end) in gaps {
        let gap_sectors = gap_end.saturating_sub(gap_start).saturating_add(1);
        let gap_offset = gap_start.saturating_mul(sector_size as u64);
        let gap_bytes = gap_sectors.saturating_mul(sector_size as u64);

        if reader.seek(SeekFrom::Start(gap_offset)).is_err() {
            continue;
        }

        let mut remaining = gap_bytes;
        let mut chunk_buf = vec![0u8; 64 * 1024];
        let mut current_chunk_offset = gap_offset;

        while remaining > 0 {
            let to_read = (remaining as usize).min(chunk_buf.len());
            let bytes_read = reader.read(&mut chunk_buf[..to_read]).map_err(|e| {
                StageError::Io(format!("failed to read for wipe verification: {e}"))
            })?;

            if bytes_read == 0 {
                break;
            }

            let slice = &chunk_buf[..bytes_read];
            let is_zeroed = slice.iter().all(|&b| b == 0);

            if !is_zeroed {
                let entropy = shannon_entropy(slice);
                if entropy < 7.5 {
                    let lba = current_chunk_offset / sector_size as u64;
                    findings.push(Finding {
                        id: "FX-EGR-002".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "egress_scan".to_string(),
                        location: Location::ByteOffset(current_chunk_offset),
                        reason: "unwiped or dirty block detected in unallocated space".to_string(),
                        evidence: format!(
                            "block at offset 0x{current_chunk_offset:x} (LBA {lba}) contains non-zero, non-random data (entropy: {entropy:.2})"
                        ),
                    });
                    break;
                }
            }

            remaining = remaining.saturating_sub(bytes_read as u64);
            current_chunk_offset = current_chunk_offset.saturating_add(bytes_read as u64);
        }
    }

    Ok(())
}
