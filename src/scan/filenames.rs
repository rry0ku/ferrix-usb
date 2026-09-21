use crate::core::{Confidence, Finding, Location, MediaPath, Severity};
use crate::policy::{is_os_artifact_path, Policy};

pub fn is_bidi_override(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
    )
}

pub fn check_filename_anomalies(
    filename: &str,
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
) {
    check_filename_anomalies_with_policy(filename, media_path, findings, &Policy::strict_default())
}

pub fn check_filename_anomalies_with_policy(
    filename: &str,
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
) {
    if filename.chars().any(is_bidi_override) {
        findings.push(Finding {
            id: "FX-FILE-004".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "Unicode bidi override detected in filename (RTLO)".to_string(),
            evidence: format!("filename '{filename}' contains directional override characters"),
        });
    }

    if filename.chars().any(|c| c.is_control()) {
        findings.push(Finding {
            id: "FX-FILE-004".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "control characters detected in filename".to_string(),
            evidence: format!("filename '{filename}' contains non-printable control characters"),
        });
    }

    if !policy.filenames.allow_unicode && !filename.is_ascii() {
        findings.push(Finding {
            id: "FX-FILE-004".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "non-ASCII characters detected in filename disallowed by policy".to_string(),
            evidence: format!("filename '{filename}' contains non-ASCII Unicode characters"),
        });
    }

    if policy.filenames.check_double_extensions {
        let parts: Vec<&str> = filename.split('.').collect();
        if parts.len() >= 3 {
            let ext = parts[parts.len() - 1].to_lowercase();
            let deceptive_ext = parts[parts.len() - 2].to_lowercase();

            let is_exec_ext = matches!(
                ext.as_str(),
                "exe" | "scr" | "bat" | "cmd" | "vbs" | "js" | "pif" | "com" | "ps1" | "sh"
            );
            let is_deceptive_ext = matches!(
                deceptive_ext.as_str(),
                "pdf" | "doc" | "docx" | "xls" | "xlsx" | "csv" | "jpg" | "jpeg" | "png" | "txt"
            );

            if is_exec_ext && is_deceptive_ext {
                findings.push(Finding {
                    id: "FX-FILE-004".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: "dangerous double extension detected".to_string(),
                    evidence: format!(
                        "file '{filename}' disguises executable (.{ext}) behind deceptive extension (.{deceptive_ext})"
                    ),
                });
            }
        }
    }

    let lower = filename.to_lowercase();
    if lower == "autorun.inf" {
        findings.push(Finding {
            id: "FX-FILE-002".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "autorun.inf execution trigger detected".to_string(),
            evidence: "presence of autorun configuration file on removable media".to_string(),
        });
    } else if lower.ends_with(".desktop") {
        findings.push(Finding {
            id: "FX-FILE-002".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "Linux desktop launcher file detected".to_string(),
            evidence: format!("file '{filename}' can execute arbitrary commands when opened"),
        });
    } else if lower.ends_with(".lnk") {
        findings.push(Finding {
            id: "FX-FILE-002".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "Windows shell shortcut (.lnk) file detected".to_string(),
            evidence: format!("shortcut file '{filename}' may point to executable payloads"),
        });
    }
}

pub fn check_hidden_file(
    filename: &str,
    is_hidden_attr: bool,
    is_executable_content: bool,
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
) {
    check_hidden_file_with_policy(
        filename,
        is_hidden_attr,
        is_executable_content,
        media_path,
        findings,
        &Policy::strict_default(),
    )
}

pub fn check_hidden_file_with_policy(
    filename: &str,
    is_hidden_attr: bool,
    is_executable_content: bool,
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
) {
    let is_dotfile = filename.starts_with('.') && filename != "." && filename != "..";
    let is_hidden = is_dotfile || is_hidden_attr;

    if !is_hidden {
        return;
    }

    if policy.allow_os_artifacts && is_os_artifact_path(filename) && !is_executable_content {
        return;
    }

    if is_executable_content {
        findings.push(Finding {
            id: "FX-FILE-003".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "hidden executable file detected".to_string(),
            evidence: format!("file '{filename}' is hidden and contains executable code"),
        });
    } else {
        findings.push(Finding {
            id: "FX-FILE-003".to_string(),
            severity: Severity::Info,
            confidence: Confidence::Low,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "hidden file or dotfile detected".to_string(),
            evidence: format!("file '{filename}' is marked as hidden or starts with a dot"),
        });
    }
}
