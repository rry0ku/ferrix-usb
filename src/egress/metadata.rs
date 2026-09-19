use crate::core::{Confidence, Finding, Location, MediaPath, Severity};

pub fn detect_metadata(path: &MediaPath, filename: &str, data: &[u8], findings: &mut Vec<Finding>) {
    let lower_name = filename.to_lowercase();

    if data.starts_with(b"\xff\xd8")
        || lower_name.ends_with(".jpg")
        || lower_name.ends_with(".jpeg")
    {
        check_jpeg_exif(path, data, findings);
    }

    if data.starts_with(b"%PDF") || lower_name.ends_with(".pdf") {
        check_pdf_metadata(path, data, findings);
    }

    if data.starts_with(b"PK\x03\x04")
        || lower_name.ends_with(".docx")
        || lower_name.ends_with(".xlsx")
        || lower_name.ends_with(".pptx")
    {
        check_office_metadata(path, data, findings);
    }
}

fn check_jpeg_exif(path: &MediaPath, data: &[u8], findings: &mut Vec<Finding>) {
    let mut idx = 2;
    while idx + 4 <= data.len() {
        if data[idx] == 0xFF {
            let marker = data[idx + 1];
            if marker == 0xE1 {
                let seg_len = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
                let seg_end = idx + 2 + seg_len;
                if seg_end <= data.len() && idx + 10 <= data.len() {
                    let header = &data[idx + 4..idx + 10];
                    if header == b"Exif\x00\x00" {
                        findings.push(Finding {
                            id: "FX-EGR-003".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            stage: "egress_scan".to_string(),
                            location: Location::Path(path.clone()),
                            reason: "EXIF metadata detected in image".to_string(),
                            evidence:
                                "image contains EXIF metadata segment (potential camera/GPS leak)"
                                    .to_string(),
                        });
                        return;
                    }
                }
            } else if marker == 0xDA || marker == 0xD9 {
                break;
            } else {
                let seg_len = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
                idx = idx.saturating_add(2).saturating_add(seg_len);
                continue;
            }
        }
        idx += 1;
    }
}

fn check_pdf_metadata(path: &MediaPath, data: &[u8], findings: &mut Vec<Finding>) {
    let tags: &[(&[u8], &str)] = &[
        (b"/Author", "Author"),
        (b"/Creator", "Creator"),
        (b"/Producer", "Producer"),
        (b"/CreationDate", "CreationDate"),
        (b"/ModDate", "ModDate"),
    ];

    let mut found_tags = Vec::new();
    for &(tag, name) in tags {
        if find_subsequence(data, tag).is_some() {
            found_tags.push(name);
        }
    }

    if !found_tags.is_empty() {
        findings.push(Finding {
            id: "FX-EGR-003".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            stage: "egress_scan".to_string(),
            location: Location::Path(path.clone()),
            reason: "author/producer metadata detected in PDF document".to_string(),
            evidence: format!("PDF contains metadata tags: {}", found_tags.join(", ")),
        });
    }
}

fn check_office_metadata(path: &MediaPath, data: &[u8], findings: &mut Vec<Finding>) {
    let markers: &[(&[u8], &str)] = &[
        (b"<dc:creator>", "dc:creator"),
        (b"<cp:lastModifiedBy>", "lastModifiedBy"),
        (b"<Company>", "Company"),
        (b"<Manager>", "Manager"),
        (b"docProps/core.xml", "core.xml"),
        (b"docProps/app.xml", "app.xml"),
    ];

    let mut detected = Vec::new();
    for &(marker, name) in markers {
        if find_subsequence(data, marker).is_some() {
            detected.push(name);
        }
    }

    if detected
        .iter()
        .any(|&d| d == "dc:creator" || d == "lastModifiedBy" || d == "Company")
    {
        findings.push(Finding {
            id: "FX-EGR-003".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            stage: "egress_scan".to_string(),
            location: Location::Path(path.clone()),
            reason: "author/company metadata detected in Office document".to_string(),
            evidence: format!(
                "Office document contains metadata tags: {}",
                detected.join(", ")
            ),
        });
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn strip_metadata(filename: &str, data: &[u8]) -> Vec<u8> {
    let lower = filename.to_lowercase();
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        strip_jpeg_exif(data)
    } else if lower.ends_with(".pdf") {
        strip_pdf_metadata(data)
    } else {
        data.to_vec()
    }
}

fn strip_jpeg_exif(data: &[u8]) -> Vec<u8> {
    if data.len() < 4 || !data.starts_with(b"\xff\xd8") {
        return data.to_vec();
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..2]);

    let mut idx = 2;
    while idx + 4 <= data.len() {
        if data[idx] == 0xFF {
            let marker = data[idx + 1];
            if marker == 0xE1 {
                let seg_len = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
                idx = idx.saturating_add(2).saturating_add(seg_len);
                continue;
            } else if marker == 0xDA || marker == 0xD9 {
                out.extend_from_slice(&data[idx..]);
                break;
            } else {
                let seg_len = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
                let end = (idx + 2 + seg_len).min(data.len());
                out.extend_from_slice(&data[idx..end]);
                idx = end;
                continue;
            }
        }
        out.push(data[idx]);
        idx += 1;
    }

    out
}

fn strip_pdf_metadata(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let tags: &[&[u8]] = &[
        b"/Author",
        b"/Creator",
        b"/Producer",
        b"/CreationDate",
        b"/ModDate",
    ];

    for &tag in tags {
        let mut search_start = 0;
        while let Some(pos) = find_subsequence(&out[search_start..], tag) {
            let abs_pos = search_start + pos;
            let mut end_pos = abs_pos + tag.len();
            while end_pos < out.len()
                && out[end_pos] != b'\n'
                && out[end_pos] != b'\r'
                && out[end_pos] != b'/'
            {
                end_pos += 1;
            }
            for b in &mut out[abs_pos..end_pos] {
                *b = b' ';
            }
            search_start = end_pos;
        }
    }

    out
}
