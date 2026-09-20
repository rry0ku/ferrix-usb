use crate::core::{Confidence, Finding, Location, MediaPath, Severity};
use crate::policy::Policy;

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

pub fn is_path_traversal_entry(name: &str) -> bool {
    name.contains("..")
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\0')
        || (name.len() >= 2
            && name.as_bytes()[1] == b':'
            && name.as_bytes()[0].is_ascii_alphabetic())
}

pub fn inspect_zip_archive(data: &[u8], media_path: &MediaPath, findings: &mut Vec<Finding>) {
    inspect_zip_archive_with_policy(data, media_path, findings, &Policy::strict_default())
}

pub fn inspect_zip_archive_with_policy(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
) {
    let mut total_uncompressed = 0u64;
    inspect_archive_recursive(data, media_path, findings, policy, 0, &mut total_uncompressed);
}

pub fn inspect_archive_recursive(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
    current_depth: usize,
    cumulative_uncompressed: &mut u64,
) {
    if current_depth > policy.archives.max_depth {
        findings.push(Finding {
            id: "FX-FILE-006".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "archive nested depth exceeds safe policy limit".to_string(),
            evidence: format!(
                "nested archive depth {current_depth} exceeds maximum configured depth {}",
                policy.archives.max_depth
            ),
        });
        return;
    }

    if data.starts_with(b"PK\x03\x04") || find_eocd(data).is_some() {
        inspect_zip_entries(
            data,
            media_path,
            findings,
            policy,
            current_depth,
            cumulative_uncompressed,
        );
    } else if is_tar_archive(data) {
        inspect_tar_entries(
            data,
            media_path,
            findings,
            policy,
            current_depth,
            cumulative_uncompressed,
        );
    } else if is_gzip_archive(data) {
        inspect_gzip_payload(
            data,
            media_path,
            findings,
            policy,
            current_depth,
            cumulative_uncompressed,
        );
    } else if is_7z_archive(data) {
        inspect_7z_container(data, media_path, findings, policy);
    }
}

fn inspect_zip_entries(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
    current_depth: usize,
    cumulative_uncompressed: &mut u64,
) {
    let max_limit = policy
        .archives
        .max_uncompressed_size_mb
        .saturating_mul(1024 * 1024);

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
            return;
        }

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
            let comp_method = u16::from_le_bytes([data[curr + 10], data[curr + 11]]);
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
                let entry_name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();

                if is_path_traversal_entry(&entry_name) {
                    findings.push(Finding {
                        id: "FX-FILE-006".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "file_scan".to_string(),
                        location: Location::Path(media_path.clone()),
                        reason: "archive contains path traversal attempt in central directory".to_string(),
                        evidence: format!("central directory entry '{entry_name}' attempts to escape target directory"),
                    });
                }

                let lower = entry_name.to_lowercase();
                if !policy.office.allow_macros
                    && (lower.contains("vbaproject.bin")
                        || lower.contains("vba/")
                        || lower.contains("macros"))
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

                let host_os = version_made_by >> 8;
                if !policy.archives.allow_symlinks
                    && host_os == 3
                    && ((external_attr >> 16) & 0xF000) == 0xA000
                {
                    findings.push(Finding {
                        id: "FX-FILE-006".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        stage: "file_scan".to_string(),
                        location: Location::Path(media_path.clone()),
                        reason: "archive contains symlink entry (symlink escape risk)".to_string(),
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
                        let lh_extra_len = u16::from_le_bytes([
                            data[local_header_offset + 28],
                            data[local_header_offset + 29],
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
                                    reason: "archive entry mismatch between local header and central directory".to_string(),
                                    evidence: format!("local header name '{lh_name}' differs from central directory name '{entry_name}'"),
                                });
                            }
                        }

                        let payload_start = local_header_offset + 30 + lh_name_len + lh_extra_len;
                        let payload_end = payload_start.saturating_add(comp_size as usize);
                        if payload_end <= data.len() && is_nested_archive_name(&entry_name) {
                            let entry_payload = &data[payload_start..payload_end];
                            let decompressed_opt = if comp_method == 0 {
                                Some(entry_payload.to_vec())
                            } else if comp_method == 8 {
                                miniz_oxide::inflate::decompress_to_vec_with_limit(
                                    entry_payload,
                                    16 * 1024 * 1024,
                                )
                                .ok()
                            } else {
                                None
                            };

                            if let Some(decomp) = decompressed_opt {
                                let nested_path = MediaPath::from(format!(
                                    "{}/{}",
                                    media_path.escaped(),
                                    entry_name
                                ));
                                inspect_archive_recursive(
                                    &decomp,
                                    &nested_path,
                                    findings,
                                    policy,
                                    current_depth + 1,
                                    cumulative_uncompressed,
                                );
                            }
                        }
                    }
                }
            }

            if comp_size > 0
                && uncomp_size > (comp_size.saturating_mul(policy.archives.max_expansion_ratio))
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
                        "entry expands from {comp_size} bytes to {uncomp_size} bytes (ratio > {}:1)",
                        policy.archives.max_expansion_ratio
                    ),
                });
            }

            *cumulative_uncompressed = cumulative_uncompressed.saturating_add(uncomp_size);
            if *cumulative_uncompressed > max_limit {
                findings.push(Finding {
                    id: "FX-FILE-006".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: "archive uncompressed size exceeds safe limit".to_string(),
                    evidence: format!(
                        "total uncompressed archive size exceeds {} MB limit",
                        policy.archives.max_uncompressed_size_mb
                    ),
                });
                break;
            }

            curr = curr
                .saturating_add(46)
                .saturating_add(name_len)
                .saturating_add(extra_len)
                .saturating_add(comment_len);
        }
    } else {
        inspect_zip_local_headers(
            data,
            media_path,
            findings,
            policy,
            current_depth,
            cumulative_uncompressed,
        );
    }
}

fn inspect_zip_local_headers(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
    current_depth: usize,
    cumulative_uncompressed: &mut u64,
) {
    let max_limit = policy
        .archives
        .max_uncompressed_size_mb
        .saturating_mul(1024 * 1024);
    let mut curr = 0;
    while curr + 30 <= data.len() {
        if data[curr] != 0x50 || data[curr + 1] != 0x4B || data[curr + 2] != 0x03 || data[curr + 3] != 0x04 {
            curr += 1;
            continue;
        }

        let comp_method = u16::from_le_bytes([data[curr + 8], data[curr + 9]]);
        let comp_size = u32::from_le_bytes([
            data[curr + 18],
            data[curr + 19],
            data[curr + 20],
            data[curr + 21],
        ]) as u64;
        let uncomp_size = u32::from_le_bytes([
            data[curr + 22],
            data[curr + 23],
            data[curr + 24],
            data[curr + 25],
        ]) as u64;
        let name_len = u16::from_le_bytes([data[curr + 26], data[curr + 27]]) as usize;
        let extra_len = u16::from_le_bytes([data[curr + 28], data[curr + 29]]) as usize;

        let name_start = curr + 30;
        let name_end = name_start.saturating_add(name_len);

        if name_end <= data.len() {
            let entry_name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();

            if is_path_traversal_entry(&entry_name) {
                findings.push(Finding {
                    id: "FX-FILE-006".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: "archive contains path traversal attempt in local header".to_string(),
                    evidence: format!("local header entry '{entry_name}' attempts to escape target directory"),
                });
            }

            let lower = entry_name.to_lowercase();
            if !policy.office.allow_macros
                && (lower.contains("vbaproject.bin")
                    || lower.contains("vba/")
                    || lower.contains("macros"))
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

            if comp_size > 0
                && uncomp_size > (comp_size.saturating_mul(policy.archives.max_expansion_ratio))
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
                        "entry expands from {comp_size} bytes to {uncomp_size} bytes (ratio > {}:1)",
                        policy.archives.max_expansion_ratio
                    ),
                });
            }

            *cumulative_uncompressed = cumulative_uncompressed.saturating_add(uncomp_size);
            if *cumulative_uncompressed > max_limit {
                findings.push(Finding {
                    id: "FX-FILE-006".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    stage: "file_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: "archive uncompressed size exceeds safe limit".to_string(),
                    evidence: format!(
                        "total uncompressed archive size exceeds {} MB limit",
                        policy.archives.max_uncompressed_size_mb
                    ),
                });
                break;
            }

            let payload_start = curr + 30 + name_len + extra_len;
            let payload_end = payload_start.saturating_add(comp_size as usize);
            if payload_end <= data.len() && is_nested_archive_name(&entry_name) {
                let entry_payload = &data[payload_start..payload_end];
                let decompressed_opt = if comp_method == 0 {
                    Some(entry_payload.to_vec())
                } else if comp_method == 8 {
                    miniz_oxide::inflate::decompress_to_vec_with_limit(
                        entry_payload,
                        16 * 1024 * 1024,
                    )
                    .ok()
                } else {
                    None
                };

                if let Some(decomp) = decompressed_opt {
                    let nested_path = MediaPath::from(format!(
                        "{}/{}",
                        media_path.escaped(),
                        entry_name
                    ));
                    inspect_archive_recursive(
                        &decomp,
                        &nested_path,
                        findings,
                        policy,
                        current_depth + 1,
                        cumulative_uncompressed,
                    );
                }
            }
        }

        let next_offset = curr
            .saturating_add(30)
            .saturating_add(name_len)
            .saturating_add(extra_len)
            .saturating_add(comp_size as usize);

        if next_offset <= curr {
            curr += 1;
        } else {
            curr = next_offset;
        }
    }
}

pub fn is_tar_archive(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }
    let magic = &data[257..262];
    magic == b"ustar"
}

fn inspect_tar_entries(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
    current_depth: usize,
    cumulative_uncompressed: &mut u64,
) {
    let max_limit = policy
        .archives
        .max_uncompressed_size_mb
        .saturating_mul(1024 * 1024);

    let mut offset = 0;
    while offset + 512 <= data.len() {
        let block = &data[offset..offset + 512];
        if block.iter().all(|&b| b == 0) {
            break;
        }

        let name_bytes = &block[0..100];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(100);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        if is_path_traversal_entry(&name) {
            findings.push(Finding {
                id: "FX-FILE-006".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "file_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: "tar archive contains path traversal entry".to_string(),
                evidence: format!("tar entry '{name}' attempts to escape target directory"),
            });
        }

        let typeflag = block[156];
        if !policy.archives.allow_symlinks && (typeflag == b'2' || typeflag == b'1') {
            findings.push(Finding {
                id: "FX-FILE-006".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "file_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: "tar archive contains link entry (symlink escape risk)".to_string(),
                evidence: format!("tar entry '{name}' is link type {typeflag}"),
            });
        }

        let size_bytes = &block[124..136];
        let size_str = String::from_utf8_lossy(size_bytes)
            .trim_matches('\0')
            .trim()
            .to_string();
        let file_size = u64::from_str_radix(&size_str, 8).unwrap_or(0);

        *cumulative_uncompressed = cumulative_uncompressed.saturating_add(file_size);
        if *cumulative_uncompressed > max_limit {
            findings.push(Finding {
                id: "FX-FILE-006".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "file_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: "tar uncompressed size exceeds safe limit".to_string(),
                evidence: format!(
                    "total uncompressed tar size exceeds {} MB limit",
                    policy.archives.max_uncompressed_size_mb
                ),
            });
            break;
        }

        let payload_start = offset + 512;
        let payload_end = payload_start.saturating_add(file_size as usize);

        if payload_end <= data.len() && is_nested_archive_name(&name) {
            let entry_payload = &data[payload_start..payload_end];
            let nested_path = MediaPath::from(format!("{}/{}", media_path.escaped(), name));
            inspect_archive_recursive(
                entry_payload,
                &nested_path,
                findings,
                policy,
                current_depth + 1,
                cumulative_uncompressed,
            );
        }

        let blocks = (file_size.saturating_add(511)) / 512;
        offset = offset.saturating_add(512).saturating_add((blocks as usize).saturating_mul(512));
    }
}

pub fn is_gzip_archive(data: &[u8]) -> bool {
    data.len() >= 10 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08
}

fn inspect_gzip_payload(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    policy: &Policy,
    current_depth: usize,
    cumulative_uncompressed: &mut u64,
) {
    if data.len() < 10 {
        return;
    }
    let flags = data[3];
    let mut header_size = 10usize;

    if (flags & 0x04) != 0 {
        if header_size + 2 <= data.len() {
            let xlen = u16::from_le_bytes([data[header_size], data[header_size + 1]]) as usize;
            header_size += 2 + xlen;
        }
    }
    if (flags & 0x08) != 0 {
        while header_size < data.len() && data[header_size] != 0 {
            header_size += 1;
        }
        header_size += 1;
    }
    if (flags & 0x10) != 0 {
        while header_size < data.len() && data[header_size] != 0 {
            header_size += 1;
        }
        header_size += 1;
    }
    if (flags & 0x02) != 0 {
        header_size += 2;
    }

    if header_size >= data.len() {
        return;
    }

    let isize = if data.len() >= 4 {
        u32::from_le_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ]) as u64
    } else {
        0
    };

    let comp_size = (data.len() - header_size) as u64;
    if comp_size > 0
        && isize > (comp_size.saturating_mul(policy.archives.max_expansion_ratio))
        && isize > (10 * 1024 * 1024)
    {
        findings.push(Finding {
            id: "FX-FILE-006".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "abnormal gzip expansion ratio (compression bomb)".to_string(),
            evidence: format!(
                "gzip expands from {comp_size} to {isize} bytes (ratio > {}:1)",
                policy.archives.max_expansion_ratio
            ),
        });
    }

    let payload = &data[header_size..];
    if let Ok(decomp) = miniz_oxide::inflate::decompress_to_vec_with_limit(payload, 16 * 1024 * 1024) {
        *cumulative_uncompressed = cumulative_uncompressed.saturating_add(decomp.len() as u64);
        let nested_path = MediaPath::from(format!("{}.decompressed", media_path.escaped()));
        inspect_archive_recursive(
            &decomp,
            &nested_path,
            findings,
            policy,
            current_depth + 1,
            cumulative_uncompressed,
        );
    }
}

pub fn is_7z_archive(data: &[u8]) -> bool {
    data.len() >= 6 && &data[0..6] == b"7z\xbc\xaf\x27\x1c"
}

fn inspect_7z_container(
    data: &[u8],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
    _policy: &Policy,
) {
    if data.len() < 32 {
        findings.push(Finding {
            id: "FX-FILE-006".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "truncated 7z archive header".to_string(),
            evidence: format!("7z container length {} is shorter than 32-byte header", data.len()),
        });
        return;
    }

    let major_version = data[6];
    let minor_version = data[7];
    if major_version > 1 {
        findings.push(Finding {
            id: "FX-FILE-006".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            stage: "file_scan".to_string(),
            location: Location::Path(media_path.clone()),
            reason: "unusual 7z major version".to_string(),
            evidence: format!("7z header specifies version {major_version}.{minor_version}"),
        });
    }
}

fn is_nested_archive_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".zip")
        || lower.ends_with(".tar")
        || lower.ends_with(".gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".7z")
        || lower.ends_with(".docx")
        || lower.ends_with(".xlsx")
        || lower.ends_with(".pptx")
        || lower.ends_with(".jar")
        || lower.ends_with(".apk")
}
