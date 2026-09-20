use crate::core::{Confidence, Finding, Location, MediaPath, Severity};
use crate::policy::Policy;
use std::collections::HashSet;

pub const OLE2_MAGIC: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

pub fn inspect_ooxml_relationships(
    xml_data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
) {
    let content = String::from_utf8_lossy(xml_data);
    for line in content.lines() {
        if line.contains("TargetMode=\"External\"") || line.contains("TargetMode='External'") {
            let mut target_uri = String::new();
            if let Some(target_idx) = line.find("Target=\"") {
                let rest = &line[target_idx + 8..];
                if let Some(end_quote) = rest.find('"') {
                    target_uri = rest[..end_quote].to_string();
                }
            } else if let Some(target_idx) = line.find("Target='") {
                let rest = &line[target_idx + 8..];
                if let Some(end_quote) = rest.find('\'') {
                    target_uri = rest[..end_quote].to_string();
                }
            }

            let lower = target_uri.to_lowercase();
            let is_high_risk = lower.starts_with("mhtml:")
                || lower.starts_with("ms-msdt:")
                || lower.starts_with("file:")
                || lower.starts_with("\\\\")
                || lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".vbs")
                || lower.ends_with(".ps1");

            let (sev, reason) = if is_high_risk {
                (
                    Severity::High,
                    "high-risk external relationship target detected in document (remote template/payload risk)",
                )
            } else {
                (
                    Severity::Medium,
                    "external relationship target detected in document",
                )
            };

            findings.push(Finding {
                id: "FX-FILE-008".to_string(),
                severity: sev,
                confidence: Confidence::High,
                stage: "file_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: reason.to_string(),
                evidence: format!("document contains external relationship target '{target_uri}'"),
            });
        }
    }
}

pub fn inspect_ole2_compound_file(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
) {
    if data.len() < 512 || &data[0..8] != OLE2_MAGIC {
        return;
    }

    let sector_shift = u16::from_le_bytes([data[30], data[31]]);
    if sector_shift != 9 && sector_shift != 12 {
        findings.push(Finding {
            id: "FX-FILE-008".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "malformed OLE2 compound document sector shift".to_string(),
            evidence: format!("sector shift {sector_shift} is neither 9 (512B) nor 12 (4096B)"),
        });
        return;
    }

    let sector_size = 1usize << sector_shift;
    let dir_first_sector = u32::from_le_bytes([data[48], data[49], data[50], data[51]]) as usize;

    let dir_offset = (dir_first_sector.saturating_add(1)).saturating_mul(sector_size);
    if dir_offset >= data.len() {
        return;
    }

    let mut visited_entries = HashSet::new();
    let mut entry_offset = dir_offset;
    let max_entries = 512;

    while entry_offset + 128 <= data.len() && visited_entries.len() < max_entries {
        visited_entries.insert(entry_offset);
        let entry_data = &data[entry_offset..entry_offset + 128];
        let name_len = u16::from_le_bytes([entry_data[64], entry_data[65]]) as usize;

        if name_len > 0 && name_len <= 64 {
            let mut utf16_chars = Vec::new();
            for chunk in entry_data[0..name_len.saturating_sub(2)].chunks_exact(2) {
                utf16_chars.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            let entry_name = String::from_utf16_lossy(&utf16_chars);
            let lower = entry_name.to_lowercase();

            if !policy.office.allow_macros
                && (lower.contains("vba") || lower.contains("macros") || lower.contains("_vba_project"))
            {
                findings.push(Finding {
                    id: "FX-FILE-007".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: "embedded VBA macro stream detected in legacy OLE2 document".to_string(),
                    evidence: format!("OLE2 directory entry '{entry_name}' indicates macro payload"),
                });
            }

            if lower.contains("ole10native") || lower.contains("package") {
                findings.push(Finding {
                    id: "FX-FILE-008".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: "embedded native OLE package/payload detected in document".to_string(),
                    evidence: format!("OLE2 directory entry '{entry_name}' contains embedded package"),
                });
            }
        }

        entry_offset += 128;
    }
}
