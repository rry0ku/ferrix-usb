use crate::core::{Confidence, Finding, Location, MediaPath, Severity};

pub fn inspect_zip_archive(data: &[u8], media_path: &MediaPath, findings: &mut Vec<Finding>) {
    let mut idx = 0;
    let mut total_uncompressed_bytes = 0u64;

    while idx + 30 <= data.len() {
        let magic = u32::from_le_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);

        if magic == 0x04034B50 {
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
                let entry_name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();

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
                        evidence: format!("archive contains macro payload entry '{entry_name}'"),
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

            idx = name_end
                .saturating_add(extra_len)
                .saturating_add(comp_size as usize);
        } else if magic == 0x02014B50 {
            let name_len = u16::from_le_bytes([data[idx + 28], data[idx + 29]]) as usize;
            let extra_len = u16::from_le_bytes([data[idx + 30], data[idx + 31]]) as usize;
            let comment_len = u16::from_le_bytes([data[idx + 32], data[idx + 33]]) as usize;

            let name_start = idx + 46;
            let name_end = name_start.saturating_add(name_len);

            if name_end <= data.len() {
                let entry_name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
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
                        evidence: format!("central directory entry '{entry_name}' escapes target"),
                    });
                }
            }

            idx = name_end
                .saturating_add(extra_len)
                .saturating_add(comment_len);
        } else {
            idx += 1;
        }
    }
}
