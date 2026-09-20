use crate::core::StageError;
use crate::policy::model::{
    ArchivePolicy, CarvePolicy, ClamAvPolicy, DeviceFilter, EgressPolicy, FilenamePolicy,
    OfficePolicy, PdfPolicy, Policy, VerdictAction,
};

pub fn parse_policy_str(input: &str) -> Result<Policy, StageError> {
    let mut name = None;
    let mut allowed_filesystems = None;
    let mut max_partitions = None;
    let mut max_file_size_mb = None;
    let mut allowed_devices = Vec::new();
    let mut denied_devices = Vec::new();
    let mut allowed_types = None;
    let mut allow_os_artifacts = None;
    let mut known_good_hashes = None;
    let mut yara_rules = Vec::new();
    let mut clamav = ClamAvPolicy::default();
    let mut carve = CarvePolicy::default();
    let mut archives = ArchivePolicy::default();
    let mut office = OfficePolicy::default();
    let mut pdf = PdfPolicy::default();
    let mut filenames = FilenamePolicy::default();
    let mut egress = EgressPolicy::default();
    let mut on_medium = None;
    let mut on_high = None;
    let mut on_critical = None;

    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let raw_line = lines[i];
        let trimmed = if let Some(idx) = raw_line.find('#') {
            &raw_line[..idx]
        } else {
            raw_line
        };
        let trimmed = trimmed.trim_end();

        if trimmed.trim().is_empty() {
            i += 1;
            continue;
        }

        let indent = trimmed.len() - trimmed.trim_start().len();
        if indent > 0 {
            return Err(StageError::Parse(format!(
                "unexpected indented line: '{trimmed}'"
            )));
        }

        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(StageError::Parse(format!(
                "invalid key-value line: '{trimmed}'"
            )));
        }

        let key = parts[0].trim();
        let val = parts[1].trim();

        match key {
            "name" => {
                name = Some(val.trim_matches('"').trim_matches('\'').to_string());
                i += 1;
            }
            "allowed_filesystems" => {
                let list = parse_inline_or_bullet_list(val, &lines, &mut i)?;
                allowed_filesystems = Some(list);
            }
            "max_partitions" => {
                let num = val.parse::<usize>().map_err(|e| {
                    StageError::Parse(format!("invalid max_partitions '{val}': {e}"))
                })?;
                max_partitions = Some(num);
                i += 1;
            }
            "max_file_size_mb" => {
                let num = val.parse::<u64>().map_err(|e| {
                    StageError::Parse(format!("invalid max_file_size_mb '{val}': {e}"))
                })?;
                max_file_size_mb = Some(num);
                i += 1;
            }
            "allowed_types" => {
                let list = parse_inline_or_bullet_list(val, &lines, &mut i)?;
                allowed_types = Some(list);
            }
            "allow_os_artifacts" => {
                allow_os_artifacts = Some(parse_bool(val)?);
                i += 1;
            }
            "known_good_hashes" => {
                let list = parse_inline_or_bullet_list(val, &lines, &mut i)?;
                known_good_hashes = Some(list);
            }
            "allowed_devices" => {
                if val == "[]" {
                    i += 1;
                    continue;
                }
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let line_content = next_trimmed.trim();
                    if let Some(stripped) = line_content.strip_prefix("- ") {
                        let mut vendor = String::new();
                        let mut product = String::new();
                        let mut serial = None;
                        let first_pair = stripped.trim();
                        if !first_pair.is_empty() {
                            let (k, v) = parse_pair(first_pair)?;
                            if k == "vendor" {
                                vendor = v;
                            } else if k == "product" {
                                product = v;
                            } else if k == "serial" {
                                serial = Some(v);
                            } else {
                                return Err(StageError::Parse(format!("unknown device key '{k}'")));
                            }
                        }

                        i += 1;
                        while i < lines.len() {
                            let sub_line = lines[i];
                            let sub_trimmed = if let Some(idx) = sub_line.find('#') {
                                &sub_line[..idx]
                            } else {
                                sub_line
                            };
                            if sub_trimmed.trim().is_empty() {
                                i += 1;
                                continue;
                            }
                            let sub_indent = sub_trimmed.len() - sub_trimmed.trim_start().len();
                            if sub_indent <= next_indent || sub_trimmed.trim().starts_with("- ") {
                                break;
                            }

                            let (k, v) = parse_pair(sub_trimmed.trim())?;
                            if k == "vendor" {
                                vendor = v;
                            } else if k == "product" {
                                product = v;
                            } else if k == "serial" {
                                serial = Some(v);
                            } else {
                                return Err(StageError::Parse(format!("unknown device key '{k}'")));
                            }
                            i += 1;
                        }

                        allowed_devices.push(DeviceFilter {
                            vendor,
                            product,
                            serial,
                        });
                    } else {
                        i += 1;
                    }
                }
            }
            "archives" => {
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let (k, v) = parse_pair(next_trimmed.trim())?;
                    match k.as_str() {
                        "max_depth" => {
                            archives.max_depth = v.parse::<usize>().map_err(|e| {
                                StageError::Parse(format!("invalid max_depth '{v}': {e}"))
                            })?;
                        }
                        "max_expansion_ratio" => {
                            archives.max_expansion_ratio = v.parse::<u64>().map_err(|e| {
                                StageError::Parse(format!("invalid max_expansion_ratio '{v}': {e}"))
                            })?;
                        }
                        "allow_symlinks" => {
                            archives.allow_symlinks = parse_bool(&v)?;
                        }
                        "max_uncompressed_size_mb" => {
                            archives.max_uncompressed_size_mb = v.parse::<u64>().map_err(|e| {
                                StageError::Parse(format!(
                                    "invalid max_uncompressed_size_mb '{v}': {e}"
                                ))
                            })?;
                        }
                        _ => {
                            return Err(StageError::Parse(format!("unknown archive key '{k}'")));
                        }
                    }
                    i += 1;
                }
            }
            "office" => {
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let (k, v) = parse_pair(next_trimmed.trim())?;
                    match k.as_str() {
                        "allow_macros" => {
                            office.allow_macros = parse_bool(&v)?;
                        }
                        _ => {
                            return Err(StageError::Parse(format!("unknown office key '{k}'")));
                        }
                    }
                    i += 1;
                }
            }
            "pdf" => {
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let (k, v) = parse_pair(next_trimmed.trim())?;
                    match k.as_str() {
                        "allow_javascript" => {
                            pdf.allow_javascript = parse_bool(&v)?;
                        }
                        "allow_launch_actions" => {
                            pdf.allow_launch_actions = parse_bool(&v)?;
                        }
                        "allow_embedded_files" => {
                            pdf.allow_embedded_files = parse_bool(&v)?;
                        }
                        _ => {
                            return Err(StageError::Parse(format!("unknown pdf key '{k}'")));
                        }
                    }
                    i += 1;
                }
            }
            "filenames" => {
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let (k, v) = parse_pair(next_trimmed.trim())?;
                    match k.as_str() {
                        "allow_unicode" => {
                            filenames.allow_unicode = parse_bool(&v)?;
                        }
                        "check_double_extensions" => {
                            filenames.check_double_extensions = parse_bool(&v)?;
                        }
                        _ => {
                            return Err(StageError::Parse(format!("unknown filenames key '{k}'")));
                        }
                    }
                    i += 1;
                }
            }
            "egress" => {
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let (k, v) = parse_pair(next_trimmed.trim())?;
                    match k.as_str() {
                        "check_unallocated_remnants" => {
                            egress.check_unallocated_remnants = parse_bool(&v)?;
                        }
                        "check_metadata" => {
                            egress.check_metadata = parse_bool(&v)?;
                        }
                        "require_wipe_verification" => {
                            egress.require_wipe_verification = parse_bool(&v)?;
                        }
                        _ => {
                            return Err(StageError::Parse(format!("unknown egress key '{k}'")));
                        }
                    }
                    i += 1;
                }
            }
            "denied_devices" => {
                if val == "[]" {
                    i += 1;
                    continue;
                }
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let line_content = next_trimmed.trim();
                    if let Some(stripped) = line_content.strip_prefix("- ") {
                        let mut vendor = String::new();
                        let mut product = String::new();
                        let mut serial = None;
                        let first_pair = stripped.trim();
                        if !first_pair.is_empty() {
                            let (k, v) = parse_pair(first_pair)?;
                            if k == "vendor" {
                                vendor = v;
                            } else if k == "product" {
                                product = v;
                            } else if k == "serial" {
                                serial = Some(v);
                            } else {
                                return Err(StageError::Parse(format!("unknown device key '{k}'")));
                            }
                        }

                        i += 1;
                        while i < lines.len() {
                            let sub_line = lines[i];
                            let sub_trimmed = if let Some(idx) = sub_line.find('#') {
                                &sub_line[..idx]
                            } else {
                                sub_line
                            };
                            if sub_trimmed.trim().is_empty() {
                                i += 1;
                                continue;
                            }
                            let sub_indent = sub_trimmed.len() - sub_trimmed.trim_start().len();
                            if sub_indent <= next_indent || sub_trimmed.trim().starts_with("- ") {
                                break;
                            }

                            let (k, v) = parse_pair(sub_trimmed.trim())?;
                            if k == "vendor" {
                                vendor = v;
                            } else if k == "product" {
                                product = v;
                            } else if k == "serial" {
                                serial = Some(v);
                            } else {
                                return Err(StageError::Parse(format!("unknown device key '{k}'")));
                            }
                            i += 1;
                        }

                        denied_devices.push(DeviceFilter {
                            vendor,
                            product,
                            serial,
                        });
                    } else {
                        i += 1;
                    }
                }
            }
            "yara_rules" => {
                let list = parse_inline_or_bullet_list(val, &lines, &mut i)?;
                yara_rules = list;
            }
            "clamav" => {
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let (k, v) = parse_pair(next_trimmed.trim())?;
                    match k.as_str() {
                        "enabled" => {
                            clamav.enabled = parse_bool(&v)?;
                        }
                        "socket_path" => {
                            clamav.socket_path = Some(v);
                        }
                        _ => {
                            return Err(StageError::Parse(format!("unknown clamav key '{k}'")));
                        }
                    }
                    i += 1;
                }
            }
            "carve" => {
                i += 1;
                while i < lines.len() {
                    let next_line = lines[i];
                    let next_trimmed = if let Some(idx) = next_line.find('#') {
                        &next_line[..idx]
                    } else {
                        next_line
                    };
                    if next_trimmed.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
                    if next_indent == 0 {
                        break;
                    }

                    let (k, v) = parse_pair(next_trimmed.trim())?;
                    match k.as_str() {
                        "enabled" => {
                            carve.enabled = parse_bool(&v)?;
                        }
                        "max_carved_files" => {
                            carve.max_carved_files = v.parse::<usize>().map_err(|e| {
                                StageError::Parse(format!("invalid max_carved_files '{v}': {e}"))
                            })?;
                        }
                        _ => {
                            return Err(StageError::Parse(format!("unknown carve key '{k}'")));
                        }
                    }
                    i += 1;
                }
            }
            "on_medium" => {
                on_medium = Some(parse_action(val)?);
                i += 1;
            }
            "on_high" => {
                on_high = Some(parse_action(val)?);
                i += 1;
            }
            "on_critical" => {
                on_critical = Some(parse_action(val)?);
                i += 1;
            }
            _ => {
                return Err(StageError::Parse(format!("unknown policy key '{key}'")));
            }
        }
    }

    Ok(Policy {
        name: name.unwrap_or_else(|| "custom-policy".to_string()),
        allowed_filesystems: allowed_filesystems
            .unwrap_or_else(|| vec!["fat32".to_string(), "exfat".to_string()]),
        max_partitions: max_partitions.unwrap_or(1),
        max_file_size_mb: max_file_size_mb.unwrap_or(512),
        allowed_devices,
        denied_devices,
        allowed_types: allowed_types.unwrap_or_else(|| {
            vec![
                "pdf".to_string(),
                "txt".to_string(),
                "png".to_string(),
                "jpg".to_string(),
                "docx".to_string(),
            ]
        }),
        allow_os_artifacts: allow_os_artifacts.unwrap_or(true),
        known_good_hashes: known_good_hashes.unwrap_or_default(),
        yara_rules,
        clamav,
        carve,
        archives,
        office,
        pdf,
        filenames,
        egress,
        on_medium: on_medium.unwrap_or(VerdictAction::Pass),
        on_high: on_high.unwrap_or(VerdictAction::Quarantine),
        on_critical: on_critical.unwrap_or(VerdictAction::Fail),
    })
}

fn parse_pair(line: &str) -> Result<(String, String), StageError> {
    let parts: Vec<&str> = line.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(StageError::Parse(format!("invalid pair '{line}'")));
    }
    let k = parts[0].trim().to_string();
    let v = parts[1]
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    Ok((k, v))
}

fn parse_bool(val: &str) -> Result<bool, StageError> {
    match val.to_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(StageError::Parse(format!("invalid boolean value '{val}'"))),
    }
}

fn parse_inline_or_bullet_list(
    val: &str,
    lines: &[&str],
    i: &mut usize,
) -> Result<Vec<String>, StageError> {
    if val.starts_with('[') && val.ends_with(']') {
        *i += 1;
        let inner = &val[1..val.len() - 1];
        let items: Vec<String> = inner
            .split(',')
            .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(items)
    } else if val.is_empty() {
        *i += 1;
        let mut items = Vec::new();
        while *i < lines.len() {
            let next_line = lines[*i];
            let next_trimmed = if let Some(idx) = next_line.find('#') {
                &next_line[..idx]
            } else {
                next_line
            };
            if next_trimmed.trim().is_empty() {
                *i += 1;
                continue;
            }
            let next_indent = next_trimmed.len() - next_trimmed.trim_start().len();
            if next_indent == 0 {
                break;
            }
            let line_content = next_trimmed.trim();
            if let Some(item) = line_content.strip_prefix("- ") {
                items.push(item.trim().trim_matches('"').trim_matches('\'').to_string());
                *i += 1;
            } else {
                break;
            }
        }
        Ok(items)
    } else {
        *i += 1;
        Ok(vec![val.trim_matches('"').trim_matches('\'').to_string()])
    }
}

fn parse_action(val: &str) -> Result<VerdictAction, StageError> {
    match val.to_lowercase().as_str() {
        "pass" => Ok(VerdictAction::Pass),
        "quarantine" => Ok(VerdictAction::Quarantine),
        "fail" => Ok(VerdictAction::Fail),
        _ => Err(StageError::Parse(format!("invalid verdict action '{val}'"))),
    }
}
