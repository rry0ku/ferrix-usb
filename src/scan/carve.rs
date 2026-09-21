use crate::core::{Confidence, Finding, Location, Severity, StageError};
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedFile {
    pub file_type: String,
    pub start_offset: u64,
    pub estimated_size: u64,
    pub hash: String,
}

pub fn carve_files_from_reader<R: Read + Seek>(
    reader: &mut R,
    start_offset: u64,
    length: u64,
    max_carved_files: usize,
    sector_size: u32,
    findings: &mut Vec<Finding>,
) -> Result<Vec<CarvedFile>, StageError> {
    if length == 0 || max_carved_files == 0 {
        return Ok(Vec::new());
    }

    let eff_sector = if sector_size == 0 {
        512
    } else {
        sector_size as u64
    };
    let mut carved = Vec::new();
    let mut current_offset = start_offset;
    let end_offset = start_offset.saturating_add(length);

    let mut chunk_buf = vec![0u8; 128 * 1024];

    while current_offset < end_offset && carved.len() < max_carved_files {
        if reader.seek(SeekFrom::Start(current_offset)).is_err() {
            break;
        }

        let to_read = ((end_offset - current_offset) as usize).min(chunk_buf.len());
        let bytes_read = reader
            .read(&mut chunk_buf[..to_read])
            .map_err(|e| StageError::Io(format!("failed to read disk during file carving: {e}")))?;

        if bytes_read == 0 {
            break;
        }

        let slice = &chunk_buf[..bytes_read];
        let mut i = 0;

        let mut slice_advanced_offset = None;

        while i + 16 <= slice.len() && carved.len() < max_carved_files {
            let candidate = &slice[i..];
            let abs_offset = current_offset.saturating_add(i as u64);

            if let Some((ftype, est_size, is_exec)) = detect_carved_header(candidate) {
                let size_clamped = est_size.min(end_offset.saturating_sub(abs_offset));
                let hash = compute_carved_hash(reader, abs_offset, size_clamped);

                let sev = if is_exec {
                    Severity::High
                } else {
                    Severity::Medium
                };

                findings.push(Finding {
                    id: "FX-CARVE-001".to_string(),
                    severity: sev,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::ByteOffset(abs_offset),
                    reason: format!("carved {ftype} file detected in raw or unallocated space"),
                    evidence: format!(
                        "carved {ftype} at offset 0x{abs_offset:x} (estimated size: {size_clamped} bytes, BLAKE3: {hash})"
                    ),
                });

                carved.push(CarvedFile {
                    file_type: ftype,
                    start_offset: abs_offset,
                    estimated_size: size_clamped,
                    hash,
                });

                let skip_blocks = ((size_clamped.saturating_add(eff_sector - 1)) / eff_sector)
                    .saturating_mul(eff_sector);
                let step = skip_blocks.max(eff_sector);
                let next_abs_offset = abs_offset.saturating_add(step);

                if next_abs_offset < current_offset.saturating_add(bytes_read as u64) {
                    i = (next_abs_offset - current_offset) as usize;
                    continue;
                } else {
                    slice_advanced_offset = Some(next_abs_offset);
                    break;
                }
            }

            i += eff_sector as usize;
        }

        if let Some(next_offset) = slice_advanced_offset {
            current_offset = next_offset;
        } else {
            current_offset = current_offset.saturating_add(bytes_read as u64);
        }
    }

    Ok(carved)
}

pub fn carve_unallocated_space<R: Read + Seek>(
    reader: &mut R,
    ranges: &[(u64, u64)],
    max_carved_files: usize,
    sector_size: u32,
    findings: &mut Vec<Finding>,
) -> Result<Vec<CarvedFile>, StageError> {
    let mut total_carved = Vec::new();
    for &(start_offset, length) in ranges {
        if total_carved.len() >= max_carved_files {
            break;
        }
        let remaining = max_carved_files.saturating_sub(total_carved.len());
        let carved = carve_files_from_reader(
            reader,
            start_offset,
            length,
            remaining,
            sector_size,
            findings,
        )?;
        total_carved.extend(carved);
    }
    Ok(total_carved)
}

pub fn detect_carved_header(slice: &[u8]) -> Option<(String, u64, bool)> {
    if slice.starts_with(b"\x7fELF") && slice.len() >= 16 {
        let class = slice[4];
        let data = slice[5];
        let version = slice[6];
        let osabi = slice[7];
        if (class == 1 || class == 2) && (data == 1 || data == 2) && version == 1 && osabi <= 18 {
            let size = estimate_elf_size(slice);
            return Some(("ELF Executable".to_string(), size, true));
        }
    }
    if slice.starts_with(b"MZ") && slice.len() >= 0x40 {
        let pe_offset =
            u32::from_le_bytes([slice[0x3c], slice[0x3d], slice[0x3e], slice[0x3f]]) as usize;
        if (0x40..=0x1000).contains(&pe_offset)
            && pe_offset + 24 <= slice.len()
            && &slice[pe_offset..pe_offset + 4] == b"PE\0\0"
        {
            let machine = u16::from_le_bytes([slice[pe_offset + 4], slice[pe_offset + 5]]);
            let num_sections = u16::from_le_bytes([slice[pe_offset + 6], slice[pe_offset + 7]]);
            let is_valid_machine = matches!(
                machine,
                0x014c | 0x8664 | 0xaa64 | 0x01c0 | 0x01c4 | 0x0200 | 0x5032 | 0x5064
            );
            if is_valid_machine && num_sections > 0 && num_sections <= 96 {
                let size = estimate_pe_size(slice, pe_offset);
                return Some(("Windows PE Executable".to_string(), size, true));
            }
        }
    }
    if (slice.starts_with(b"%PDF-1.") || slice.starts_with(b"%PDF-2."))
        && slice.windows(5).any(|w| w == b"%%EOF")
    {
        let size = estimate_pdf_size(slice);
        return Some(("PDF Document".to_string(), size, false));
    }
    if slice.starts_with(b"\x89PNG\r\n\x1a\n") && slice.len() >= 16 && &slice[12..16] == b"IHDR" {
        let size = estimate_png_size(slice);
        return Some(("PNG Image".to_string(), size, false));
    }
    if slice.starts_with(b"\xff\xd8\xff") && slice.len() >= 4 {
        let marker = slice[3];
        if matches!(marker, 0xe0..=0xef | 0xdb | 0xc0 | 0xc2) {
            let size = estimate_jpeg_size(slice);
            return Some(("JPEG Image".to_string(), size, false));
        }
    }
    if slice.starts_with(b"PK\x03\x04") && slice.len() >= 30 {
        let version_needed = u16::from_le_bytes([slice[4], slice[5]]);
        if version_needed <= 63 {
            let size = estimate_zip_size(slice);
            return Some(("ZIP Archive".to_string(), size, false));
        }
    }
    if slice.starts_with(b"\x1f\x8b\x08") && slice.len() >= 10 {
        let size = estimate_gzip_size(slice);
        return Some(("GZIP Archive".to_string(), size, false));
    }
    if slice.starts_with(b"SQLite format 3\0") && slice.len() >= 100 {
        let size = estimate_sqlite_size(slice);
        return Some(("SQLite Database".to_string(), size, false));
    }
    None
}

fn estimate_elf_size(slice: &[u8]) -> u64 {
    if slice.len() >= 64 {
        let is_64 = slice[4] == 2;
        if is_64 {
            let shoff = u64::from_le_bytes([
                slice[40], slice[41], slice[42], slice[43], slice[44], slice[45], slice[46],
                slice[47],
            ]);
            let shentsize = u16::from_le_bytes([slice[58], slice[59]]) as u64;
            let shnum = u16::from_le_bytes([slice[60], slice[61]]) as u64;
            if shoff > 0 && shentsize > 0 && shnum > 0 {
                return shoff.saturating_add(shentsize.saturating_mul(shnum));
            }
        }
    }
    4096
}

fn estimate_pe_size(slice: &[u8], pe_offset: usize) -> u64 {
    if pe_offset + 0x60 <= slice.len() {
        let opt_header = pe_offset + 24;
        let size_of_image = u32::from_le_bytes([
            slice[opt_header + 56],
            slice[opt_header + 57],
            slice[opt_header + 58],
            slice[opt_header + 59],
        ]) as u64;
        if size_of_image > 0 && size_of_image < (100 * 1024 * 1024) {
            return size_of_image;
        }
    }
    4096
}

fn estimate_png_size(slice: &[u8]) -> u64 {
    if let Some(pos) = slice.windows(8).position(|w| w == b"IEND\xae\x42\x60\x82") {
        return (pos + 8) as u64;
    }
    4096
}

fn estimate_jpeg_size(slice: &[u8]) -> u64 {
    if let Some(pos) = slice.windows(2).position(|w| w == [0xFF, 0xD9]) {
        return (pos + 2) as u64;
    }
    4096
}

fn estimate_pdf_size(slice: &[u8]) -> u64 {
    if let Some(pos) = slice.windows(5).rposition(|w| w == b"%%EOF") {
        return (pos + 5) as u64;
    }
    4096
}

fn estimate_zip_size(slice: &[u8]) -> u64 {
    if let Some(pos) = slice
        .windows(4)
        .rposition(|w| w == [0x50, 0x4B, 0x05, 0x06])
    {
        if pos + 22 <= slice.len() {
            let comment_len = u16::from_le_bytes([slice[pos + 20], slice[pos + 21]]) as usize;
            return (pos + 22 + comment_len) as u64;
        }
    }
    4096
}

fn estimate_gzip_size(slice: &[u8]) -> u64 {
    if slice.len() >= 10 {
        return slice.len() as u64;
    }
    4096
}

fn estimate_sqlite_size(slice: &[u8]) -> u64 {
    if slice.len() >= 32 {
        let raw_page_size = u16::from_be_bytes([slice[16], slice[17]]);
        let page_size = if raw_page_size == 1 {
            65536u64
        } else {
            raw_page_size as u64
        };
        let page_count = u32::from_be_bytes([slice[28], slice[29], slice[30], slice[31]]) as u64;
        if page_size > 0 && page_count > 0 {
            return page_size.saturating_mul(page_count);
        }
    }
    4096
}

fn compute_carved_hash<R: Read + Seek>(reader: &mut R, offset: u64, size: u64) -> String {
    if reader.seek(SeekFrom::Start(offset)).is_err() {
        return String::new();
    }
    let mut hasher = blake3::Hasher::new();
    let mut remaining = size;
    let mut buf = vec![0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        match reader.read(&mut buf[..to_read]) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                remaining = remaining.saturating_sub(n as u64);
            }
            Err(_) => break,
        }
    }

    hasher.finalize().to_hex().to_string()
}
