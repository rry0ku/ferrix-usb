use crate::core::StageError;
use crate::fs::extract_filesystem_files;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenamedFile {
    pub original: String,
    pub sanitized: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReport {
    pub files_released: usize,
    pub bytes_released: u64,
    pub renames: Vec<RenamedFile>,
    pub destination_dir: PathBuf,
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{FEFF}'
    )
}

fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub fn sanitize_destination_filename(raw_name: &str) -> (String, Option<String>) {
    let mut reasons = Vec::new();
    let mut clean: String = raw_name
        .chars()
        .filter_map(|c| {
            if is_bidi_control(c) {
                None
            } else if c.is_control() {
                Some('_')
            } else {
                Some(c)
            }
        })
        .collect();

    if clean != raw_name {
        reasons.push("removed bidi override or control characters".to_string());
    }

    if clean.starts_with('-') {
        clean = format!("_{clean}");
        reasons.push("prefixed leading dash".to_string());
    }

    let trimmed = clean.trim_end_matches(['.', ' ']);
    if trimmed.len() != clean.len() {
        clean = format!("{trimmed}_");
        reasons.push("sanitized trailing dot or space".to_string());
    }

    if is_windows_reserved(&clean) {
        clean = format!("safe_{clean}");
        reasons.push("prefixed Windows reserved device name".to_string());
    }

    if clean.len() > 255 {
        let ext_pos = clean.rfind('.');
        clean = match ext_pos {
            Some(idx) if idx < 240 => {
                let ext = &clean[idx..];
                format!("{}{ext}", &clean[..255 - ext.len()])
            }
            _ => clean[..255].to_string(),
        };
        reasons.push("truncated filename exceeding 255 bytes".to_string());
    }

    if reasons.is_empty() {
        (clean, None)
    } else {
        (clean, Some(reasons.join(", ")))
    }
}

pub fn sanitize_relative_path(
    path_str: &str,
    renames: &mut Vec<RenamedFile>,
) -> Result<PathBuf, StageError> {
    let clean = path_str.trim_start_matches('/').trim_start_matches('\\');
    let segments: Vec<&str> = clean.split(['/', '\\']).collect();
    let mut out_path = PathBuf::new();

    for seg in segments {
        let trimmed = seg.trim();
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        if trimmed == ".." {
            return Err(StageError::Parse(format!(
                "path traversal attempt detected in relative path '{path_str}'"
            )));
        }

        let (sanitized_seg, reason) = sanitize_destination_filename(trimmed);
        if let Some(r) = reason {
            renames.push(RenamedFile {
                original: trimmed.to_string(),
                sanitized: sanitized_seg.clone(),
                reason: r,
            });
        }
        out_path.push(sanitized_seg);
    }

    if out_path.as_os_str().is_empty() {
        return Err(StageError::Parse(format!(
            "invalid empty destination path for '{path_str}'"
        )));
    }

    Ok(out_path)
}

pub fn release_snapshot_files(
    snapshot_path: &Path,
    destination_dir: &Path,
    sector_size: u32,
) -> Result<ReleaseReport, StageError> {
    if !destination_dir.exists() {
        fs::create_dir_all(destination_dir).map_err(|e| {
            StageError::Io(format!(
                "failed to create release destination directory '{}': {e}",
                destination_dir.display()
            ))
        })?;
        let _ = fs::set_permissions(destination_dir, fs::Permissions::from_mode(0o755));
    }

    let canonical_dest = destination_dir.canonicalize().map_err(|e| {
        StageError::Io(format!(
            "failed to canonicalize release destination '{}': {e}",
            destination_dir.display()
        ))
    })?;

    let mut file = File::open(snapshot_path).map_err(|e| {
        StageError::Io(format!(
            "failed to open snapshot target '{}': {e}",
            snapshot_path.display()
        ))
    })?;

    let mut total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
    if total_bytes == 0 {
        if let Ok(end_pos) = file.seek(SeekFrom::End(0)) {
            total_bytes = end_pos;
            let _ = file.seek(SeekFrom::Start(0));
        }
    }

    let discovered_files = extract_filesystem_files(&mut file, total_bytes, sector_size)?;
    let mut renames = Vec::new();
    let mut files_released = 0usize;
    let mut bytes_released = 0u64;

    for entry in discovered_files {
        let path_str = String::from_utf8_lossy(entry.path.as_bytes()).to_string();
        let rel_path = sanitize_relative_path(&path_str, &mut renames)?;
        let target_path = canonical_dest.join(&rel_path);

        if !target_path.starts_with(&canonical_dest) {
            return Err(StageError::Parse(format!(
                "target path '{}' escapes staging root '{}'",
                target_path.display(),
                canonical_dest.display()
            )));
        }

        if entry.is_dir {
            if !target_path.exists() {
                fs::create_dir_all(&target_path).map_err(|e| {
                    StageError::Io(format!(
                        "failed to create directory '{}': {e}",
                        target_path.display()
                    ))
                })?;
                let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o755));
            }
            continue;
        }

        if let Some(parent) = target_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    StageError::Io(format!(
                        "failed to create parent directory '{}': {e}",
                        parent.display()
                    ))
                })?;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
            }
        }

        if target_path.exists() {
            if let Ok(meta) = target_path.symlink_metadata() {
                if meta.file_type().is_symlink() {
                    return Err(StageError::Parse(format!(
                        "refusing to release file over existing symlink '{}'",
                        target_path.display()
                    )));
                }
            }
        }

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);

        let mut out_file = options.open(&target_path).map_err(|e| {
            StageError::Io(format!(
                "failed to create destination file '{}': {e}",
                target_path.display()
            ))
        })?;

        let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o644));

        if entry.size > 0 {
            if let Some(offset) = entry.data_offset {
                file.seek(SeekFrom::Start(offset)).map_err(|e| {
                    StageError::Io(format!(
                        "failed to seek to offset {offset} in snapshot: {e}"
                    ))
                })?;

                let mut remaining = entry.size;
                let mut chunk = vec![0u8; 64 * 1024];

                while remaining > 0 {
                    let to_read = (remaining as usize).min(chunk.len());
                    file.read_exact(&mut chunk[..to_read]).map_err(|e| {
                        StageError::Io(format!("failed to read file data from snapshot: {e}"))
                    })?;
                    out_file.write_all(&chunk[..to_read]).map_err(|e| {
                        StageError::Io(format!("failed to write file data to destination: {e}"))
                    })?;
                    remaining -= to_read as u64;
                }
            }
        }

        files_released += 1;
        bytes_released = bytes_released.saturating_add(entry.size);
    }

    Ok(ReleaseReport {
        files_released,
        bytes_released,
        renames,
        destination_dir: canonical_dest,
    })
}
