use crate::core::{Confidence, Finding, Location, MediaPath, Severity};

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let max_search = data.len().min(65535 + 22);
    let start = data.len() - max_search;
    for i in (start..=data.len() - 22).rev() {
        if data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x05 && data[i + 3] == 0x06 {
            let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            if i + 22 + comment_len <= data.len() {
                return Some(i);
            }
        }
    }
    None
}

pub fn inspect_zip_archive(data: &[u8], media_path: &MediaPath, findings: &mut Vec<Finding>) {
    let mut total_uncompressed_bytes = 0u64;

    if let Some(eocd_idx) = find_eocd(data) {
        let cd_size = u32::from_le_bytes([
            data[eocd_idx + 12],
            data[eocd_idx + 13],
            data[eocd_idx + 14],
            data[eocd_idx + 15],
        ]) as usize;
        let cd_offset = u32::from_le_bytes([
            data[eocd_idx + 16],
            data[eocd_idx + 17],
            data[eocd_idx + 18],
            data[eocd_idx + 19],
        ]) as usize;

        if cd_offset + cd_size > data.len() || cd_offset > eocd_idx {
            findings.push(Finding {
                id: "FX-FILE-006".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "file_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: "corrupted or crafted archive central directory offset".to_string(),
                evidence: format!(
                    "central directory offset {cd_offset} size {cd_size} exceeds archive boundary"
                ),
            });
        } else {
            let mut curr = cd_offset;
            while curr + 46 <= cd_offset + cd_size && curr + 46 <= data.len() {
                let magic = u32::from_le_bytes([
                    data[curr],
                    data[curr + 1],
                    data[curr + 2],
                    data[curr + 3],
                ]);
                if magic != 0x02014B50 {
                    break;
                }

                let version_made_by = u16::from_le_bytes([data[curr + 4], data[curr + 5]]);
                let comp_size = u32::from_le_bytes([
                    data[curr + 20],
                    data[curr + 21],
                    data[curr + 22],
                    data[curr + 23],
                ]) as u64;
                let uncomp_size = u32::from_le_bytes([
                    data[curr + 24],
                    data[curr + 25],
                    data[curr + 26],
                    data[curr + 27],
                ]) as u64;
                let name_len = u16::from_le_bytes([data[curr + 28], data[curr + 29]]) as usize;
                let extra_len = u16::from_le_bytes([data[curr + 30], data[curr + 31]]) as usize;
                let comment_len = u16::from_le_bytes([data[curr + 32], data[curr + 33]]) as usize;
                let external_attr = u32::from_le_bytes([
                    data[curr + 38],
                    data[curr + 39],
                    data[curr + 40],
                    data[curr + 41],
                ]);
                let local_header_offset = u32::from_le_bytes([
                    data[curr + 42],
                    data[curr + 43],
                    data[curr + 44],
                    data[curr + 45],
                ]) as usize;

                let name_start = curr + 46;
                let name_end = name_start.saturating_add(name_len);

                if name_end <= data.len() {
                    let entry_name =
                        String::from_utf8_lossy(&data[name_start..name_end]).to_string();

                    if entry_name.contains("..")
                        || entry_name.starts_with('/')
                        || entry_name.starts_with('\\')
                    {
                        findings.push(Finding {
                            id: "FX-FILE-006".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            stage: "file_scan".to_string(),
                            location: Location::Path(media_path.clone()),
                            reason: "archive contains path traversal attempt in central directory"
                                .to_string(),
                            evidence: format!(
                                "central directory entry '{entry_name}' attempts to escape target directory"
                            ),
                        });
                    }

                    let lower = entry_name.to_lowercase();
                    if lower.contains("vbaproject.bin")
                        || lower.contains("vba/")
                        || lower.contains("macros")
                    {
                        findings.push(Finding {
                            id: "FX-FILE-007".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            stage: "file_scan".to_string(),
                            location: Location::Path(media_path.clone()),
                            reason: "embedded VBA macros detected in document/archive".to_string(),
                            evidence: format!(
                                "archive contains macro payload entry '{entry_name}'"
                            ),
                        });
                    }

                    let host_os = version_made_by >> 8;
                    if host_os == 3 && ((external_attr >> 16) & 0xF000) == 0xA000 {
                        findings.push(Finding {
                            id: "FX-FILE-006".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            stage: "file_scan".to_string(),
                            location: Location::Path(media_path.clone()),
                            reason: "archive contains symlink entry (symlink escape risk)"
                                .to_string(),
                            evidence: format!("entry '{entry_name}' is a symbolic link"),
                        });
                    }

                    if local_header_offset + 30 <= data.len() {
                        let lh_magic = u32::from_le_bytes([
                            data[local_header_offset],
                            data[local_header_offset + 1],
                            data[local_header_offset + 2],
                            data[local_header_offset + 3],
                        ]);
                        if lh_magic == 0x04034B50 {
                            let lh_name_len = u16::from_le_bytes([
                                data[local_header_offset + 26],
                                data[local_header_offset + 27],
                            ]) as usize;
                            let lh_name_end = local_header_offset + 30 + lh_name_len;
                            if lh_name_end <= data.len() {
                                let lh_name = String::from_utf8_lossy(
                                    &data[local_header_offset + 30..lh_name_end],
                                )
                                .to_string();
                                if lh_name != entry_name {
                                    findings.push(Finding {
                                        id: "FX-FILE-006".to_string(),
                                        severity: Severity::High,
                                        confidence: Confidence::High,
                                        stage: "file_scan".to_string(),
                                        location: Location::Path(media_path.clone()),
                                        reason:
                                            "archive entry mismatch between local header and central directory"
                                                .to_string(),
                                        evidence: format!(
                                            "local header name '{lh_name}' differs from central directory name '{entry_name}'"
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }

                if comp_size > 0
                    && uncomp_size > (comp_size.saturating_mul(100))
                    && uncomp_size > (10 * 1024 * 1024)
                {
                    findings.push(Finding {
                        id: "FX-FILE-006".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "file_scan".to_string(),
                        location: Location::Path(media_path.clone()),
                        reason: "abnormal compression expansion ratio (zip bomb)".to_string(),
                        evidence: format!(
                            "entry expands from {comp_size} bytes to {uncomp_size} bytes (ratio > 100:1)"
                        ),
                    });
                }

                total_uncompressed_bytes = total_uncompressed_bytes.saturating_add(uncomp_size);
                if total_uncompressed_bytes > (1024 * 1024 * 1024) {
                    findings.push(Finding {
                        id: "FX-FILE-006".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "file_scan".to_string(),
                        location: Location::Path(media_path.clone()),
                        reason: "archive uncompressed size exceeds safe limit".to_string(),
                        evidence: "total uncompressed archive size exceeds 1 GB".to_string(),
                    });
                    break;
                }

                curr = curr
                    .saturating_add(46)
                    .saturating_add(name_len)
                    .saturating_add(extra_len)
                    .saturating_add(comment_len);
            }
        }
    } else {
        let mut idx = 0;
        while idx + 30 <= data.len() {
            let magic =
                u32::from_le_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);

            if magic == 0x04034B50 {
                let flags = u16::from_le_bytes([data[idx + 6], data[idx + 7]]);
                let comp_size = u32::from_le_bytes([
                    data[idx + 18],
                    data[idx + 19],
                    data[idx + 20],
                    data[idx + 21],
                ]) as u64;
                let uncomp_size = u32::from_le_bytes([
                    data[idx + 22],
                    data[idx + 23],
                    data[idx + 24],
                    data[idx + 25],
                ]) as u64;
                let name_len = u16::from_le_bytes([data[idx + 26], data[idx + 27]]) as usize;
                let extra_len = u16::from_le_bytes([data[idx + 28], data[idx + 29]]) as usize;

                let name_start = idx + 30;
                let name_end = name_start.saturating_add(name_len);

                if name_end <= data.len() {
                    let entry_name =
                        String::from_utf8_lossy(&data[name_start..name_end]).to_string();

                    if entry_name.contains("..")
                        || entry_name.starts_with('/')
                        || entry_name.starts_with('\\')
                    {
                        findings.push(Finding {
                            id: "FX-FILE-006".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            stage: "file_scan".to_string(),
                            location: Location::Path(media_path.clone()),
                            reason: "archive contains path traversal attempt".to_string(),
                            evidence: format!(
                                "entry '{entry_name}' attempts to escape target directory"
                            ),
                        });
                    }

                    let lower = entry_name.to_lowercase();
                    if lower.contains("vbaproject.bin")
                        || lower.contains("vba/")
                        || lower.contains("macros")
                    {
                        findings.push(Finding {
                            id: "FX-FILE-007".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            stage: "file_scan".to_string(),
                            location: Location::Path(media_path.clone()),
                            reason: "embedded VBA macros detected in document/archive".to_string(),
                            evidence: format!(
                                "archive contains macro payload entry '{entry_name}'"
                            ),
                        });
                    }
                }

                if comp_size > 0
                    && uncomp_size > (comp_size.saturating_mul(100))
                    && uncomp_size > (10 * 1024 * 1024)
                {
                    findings.push(Finding {
                        id: "FX-FILE-006".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "file_scan".to_string(),
                        location: Location::Path(media_path.clone()),
                        reason: "abnormal compression expansion ratio (zip bomb)".to_string(),
                        evidence: format!(
                            "entry expands from {comp_size} bytes to {uncomp_size} bytes (ratio > 100:1)"
                        ),
                    });
                }

                total_uncompressed_bytes = total_uncompressed_bytes.saturating_add(uncomp_size);
                if total_uncompressed_bytes > (1024 * 1024 * 1024) {
                    findings.push(Finding {
                        id: "FX-FILE-006".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "file_scan".to_string(),
                        location: Location::Path(media_path.clone()),
                        reason: "archive uncompressed size exceeds safe limit".to_string(),
                        evidence: "total uncompressed archive size exceeds 1 GB".to_string(),
                    });
                    break;
                }

                let payload_start = name_end.saturating_add(extra_len);
                if (flags & 0x08) != 0 || comp_size == 0 {
                    if payload_start < data.len() {
                        let next = data[payload_start..].windows(4).position(|w| {
                            w == [0x50, 0x4B, 0x03, 0x04]
                                || w == [0x50, 0x4B, 0x01, 0x02]
                                || w == [0x50, 0x4B, 0x05, 0x06]
                        });
                        if let Some(pos) = next {
                            idx = payload_start + pos;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    idx = payload_start.saturating_add(comp_size as usize);
                }
            } else {
                idx += 1;
            }
        }
    }
}
