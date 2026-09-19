use crate::core::{Confidence, Finding, Location, MediaPath, Severity};

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

    for &(pattern, reason) in search_patterns {
        if data.windows(pattern.len()).any(|window| window == pattern) {
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
}
