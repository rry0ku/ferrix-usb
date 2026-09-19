use crate::core::{Confidence, Finding, Location, MediaPath, Severity};
use std::collections::HashSet;

pub fn inspect_pdf_content(data: &[u8], media_path: &MediaPath, findings: &mut Vec<Finding>) {
    if data.len() < 4 || &data[0..4] != b"%PDF" {
        return;
    }

    let search_patterns: &[(&[u8], &str)] = &[
        (b"/JavaScript", "embedded JavaScript action detected in PDF"),
        (b"/JS", "embedded JS script detected in PDF"),
        (
            b"/Launch",
            "launch action detected in PDF (can execute commands)",
        ),
        (b"/EmbeddedFiles", "embedded files detected in PDF"),
        (b"/EmbeddedFile", "embedded file stream detected in PDF"),
    ];

    let mut detected_patterns = HashSet::new();

    for &(pattern, reason) in search_patterns {
        if data.windows(pattern.len()).any(|window| window == pattern) {
            detected_patterns.insert(pattern);
            findings.push(Finding {
                id: "FX-FILE-008".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "file_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: reason.to_string(),
                evidence: format!(
                    "PDF structure contains dangerous keyword '{}'",
                    String::from_utf8_lossy(pattern)
                ),
            });
        }
    }

    let mut idx = 0;
    while idx + 6 <= data.len() {
        if let Some(stream_pos) = data[idx..].windows(6).position(|w| w == b"stream") {
            let stream_start = idx + stream_pos;
            let mut payload_start = stream_start + 6;
            if payload_start < data.len() && data[payload_start] == b'\r' {
                payload_start += 1;
            }
            if payload_start < data.len() && data[payload_start] == b'\n' {
                payload_start += 1;
            }

            let search_window = &data[payload_start..];
            if let Some(end_pos) = search_window.windows(9).position(|w| w == b"endstream") {
                let mut payload_end = payload_start + end_pos;
                if payload_end > payload_start && data[payload_end - 1] == b'\n' {
                    payload_end -= 1;
                }
                if payload_end > payload_start && data[payload_end - 1] == b'\r' {
                    payload_end -= 1;
                }

                let stream_bytes = &data[payload_start..payload_end];
                let decompressed = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
                    stream_bytes,
                    16 * 1024 * 1024,
                )
                .or_else(|_| {
                    miniz_oxide::inflate::decompress_to_vec_with_limit(
                        stream_bytes,
                        16 * 1024 * 1024,
                    )
                });

                if let Ok(decomp) = decompressed {
                    for &(pattern, reason) in search_patterns {
                        if !detected_patterns.contains(pattern)
                            && decomp.windows(pattern.len()).any(|w| w == pattern)
                        {
                            detected_patterns.insert(pattern);
                            findings.push(Finding {
                                id: "FX-FILE-008".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                stage: "file_scan".to_string(),
                                location: Location::Path(media_path.clone()),
                                reason: reason.to_string(),
                                evidence: format!(
                                    "PDF compressed stream contains dangerous keyword '{}'",
                                    String::from_utf8_lossy(pattern)
                                ),
                            });
                        }
                    }
                }

                idx = payload_end + 9;
            } else {
                idx = stream_start + 6;
            }
        } else {
            break;
        }
    }
}
