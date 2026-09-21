use crate::core::{Confidence, Finding, Location, MediaPath, Severity};
use crate::policy::Policy;
use std::collections::HashSet;

pub fn inspect_pdf_content(data: &[u8], media_path: &MediaPath, findings: &mut Vec<Finding>) {
    inspect_pdf_content_with_policy(data, media_path, findings, &Policy::strict_default())
}

pub fn inspect_pdf_content_with_policy(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
) {
    if data.len() < 4 {
        return;
    }

    if !data.starts_with(b"%PDF") {
        findings.push(Finding {
            id: "FX-FILE-008".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "malformed PDF header".to_string(),
            evidence: "file does not start with standard %PDF magic header".to_string(),
        });
        return;
    }

    let mut search_patterns: Vec<(&[u8], &str)> = Vec::new();
    if !policy.pdf.allow_javascript {
        search_patterns.push((b"/JavaScript", "embedded JavaScript action detected in PDF"));
        search_patterns.push((b"/JS", "embedded JS script detected in PDF"));
    }
    if !policy.pdf.allow_launch_actions {
        search_patterns.push((
            b"/Launch",
            "launch action detected in PDF (can execute commands)",
        ));
    }
    if !policy.pdf.allow_embedded_files {
        search_patterns.push((b"/EmbeddedFiles", "embedded files detected in PDF"));
        search_patterns.push((b"/EmbeddedFile", "embedded file stream detected in PDF"));
    }

    search_patterns.push((b"/URI", "external hyperlink URI action detected in PDF"));
    search_patterns.push((
        b"/GoToR",
        "remote GoTo action detected in PDF (cross-document navigation)",
    ));
    search_patterns.push((
        b"/SubmitForm",
        "form submission action detected in PDF (data exfiltration risk)",
    ));

    let mut detected_patterns = HashSet::new();

    for &(pattern, reason) in &search_patterns {
        if matches_pdf_token(data, pattern) {
            detected_patterns.insert(pattern);
            let sev = if pattern == b"/URI" {
                Severity::Info
            } else if pattern == b"/GoToR" || pattern == b"/SubmitForm" {
                Severity::Low
            } else {
                Severity::High
            };
            findings.push(Finding {
                id: "FX-FILE-008".to_string(),
                severity: sev,
                confidence: Confidence::High,
                stage: "file_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: reason.to_string(),
                evidence: format!(
                    "PDF structure contains keyword '{}'",
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
                let stream_end_actual = payload_start + end_pos;
                let mut payload_end = stream_end_actual;
                if payload_end > payload_start && data[payload_end - 1] == b'\n' {
                    payload_end -= 1;
                }
                if payload_end > payload_start && data[payload_end - 1] == b'\r' {
                    payload_end -= 1;
                }

                let stream_bytes = &data[payload_start..payload_end];
                let is_potential_zlib =
                    stream_bytes.len() >= 2 && (stream_bytes[0] == 0x78 || stream_bytes[0] == 0x1F);
                let dict_window = if stream_start >= 256 {
                    &data[stream_start - 256..stream_start]
                } else {
                    &data[..stream_start]
                };
                let has_flate_dict = dict_window.windows(12).any(|w| w == b"/FlateDecode")
                    || dict_window.windows(3).any(|w| w == b"/Fl");

                if is_potential_zlib || has_flate_dict {
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
                        for &(pattern, reason) in &search_patterns {
                            if !detected_patterns.contains(pattern)
                                && matches_pdf_token(&decomp, pattern)
                            {
                                detected_patterns.insert(pattern);
                                let sev = if pattern == b"/URI" {
                                    Severity::Info
                                } else if pattern == b"/GoToR" || pattern == b"/SubmitForm" {
                                    Severity::Low
                                } else {
                                    Severity::High
                                };
                                findings.push(Finding {
                                    id: "FX-FILE-008".to_string(),
                                    severity: sev,
                                    confidence: Confidence::High,
                                    stage: "file_scan".to_string(),
                                    location: Location::Path(media_path.clone()),
                                    reason: reason.to_string(),
                                    evidence: format!(
                                        "PDF compressed stream contains keyword '{}'",
                                        String::from_utf8_lossy(pattern)
                                    ),
                                });
                            }
                        }
                    }
                }

                idx = stream_end_actual + 9;
                if detected_patterns.len() == search_patterns.len() {
                    break;
                }
            } else {
                findings.push(Finding {
                    id: "FX-FILE-008".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: "unclosed stream in PDF document".to_string(),
                    evidence: format!(
                        "stream at offset 0x{stream_start:x} has no matching endstream keyword"
                    ),
                });
                break;
            }
        } else {
            break;
        }
    }
}

fn normalize_pdf_name(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 2 < raw.len() {
            let h1 = raw[i + 1];
            let h2 = raw[i + 2];
            let n1 = match h1 {
                b'0'..=b'9' => Some(h1 - b'0'),
                b'a'..=b'f' => Some(h1 - b'a' + 10),
                b'A'..=b'F' => Some(h1 - b'A' + 10),
                _ => None,
            };
            let n2 = match h2 {
                b'0'..=b'9' => Some(h2 - b'0'),
                b'a'..=b'f' => Some(h2 - b'a' + 10),
                b'A'..=b'F' => Some(h2 - b'A' + 10),
                _ => None,
            };
            if let (Some(v1), Some(v2)) = (n1, n2) {
                out.push((v1 << 4) | v2);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

fn matches_pdf_token(data: &[u8], pattern: &[u8]) -> bool {
    let p_len = pattern.len();
    if p_len > data.len() {
        return false;
    }
    for (i, window) in data.windows(p_len).enumerate() {
        if window == pattern {
            let next_idx = i + p_len;
            let is_token_end = if next_idx < data.len() {
                let next_b = data[next_idx];
                next_b.is_ascii_whitespace()
                    || matches!(
                        next_b,
                        b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'{' | b'}' | 0
                    )
            } else {
                true
            };
            if is_token_end {
                return true;
            }
        }
    }

    let mut idx = 0;
    while idx < data.len() {
        if data[idx] == b'/' {
            let start = idx;
            let mut end = start + 1;
            while end < data.len() {
                let b = data[end];
                if b.is_ascii_whitespace()
                    || matches!(
                        b,
                        b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'{' | b'}' | 0
                    )
                {
                    break;
                }
                end += 1;
            }
            let raw_token = &data[start..end];
            let normalized = normalize_pdf_name(raw_token);
            if normalized == pattern {
                return true;
            }
            idx = end;
        } else {
            idx += 1;
        }
    }

    false
}
