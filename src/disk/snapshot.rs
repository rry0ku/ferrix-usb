use crate::core::{EventSink, ScanEvent, StageError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct Snapshot {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub device_hash: String,
}

struct PartialFileGuard<'a>(&'a Path, bool);

impl<'a> Drop for PartialFileGuard<'a> {
    fn drop(&mut self) {
        if !self.1 {
            let _ = std::fs::remove_file(self.0);
        }
    }
}

pub fn get_available_disk_space(dir: &Path) -> Result<u64, StageError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| StageError::Io(format!("invalid path for statvfs: {e}")))?;

    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            let available = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
            Ok(available)
        } else {
            let err = std::io::Error::last_os_error();
            Err(StageError::Io(format!(
                "statvfs failed for '{}': {err}",
                dir.display()
            )))
        }
    }
}

pub fn resolve_snapshot_directory(
    required_bytes: u64,
    preferred_dir: Option<&Path>,
) -> Result<PathBuf, StageError> {
    let safety_buffer = 128 * 1024 * 1024;
    let min_needed = required_bytes.saturating_add(safety_buffer);

    let mut candidates = Vec::new();
    if let Some(p) = preferred_dir {
        candidates.push(p.to_path_buf());
    }
    if let Ok(env_dir) = std::env::var("FERRIX_TMPDIR") {
        if !env_dir.is_empty() {
            candidates.push(PathBuf::from(env_dir));
        }
    }

    candidates.push(PathBuf::from("/var/tmp"));
    candidates.push(PathBuf::from("."));
    candidates.push(std::env::temp_dir());

    let mut checked_dirs = Vec::new();

    for candidate in candidates {
        if !candidate.exists() {
            let _ = std::fs::create_dir_all(&candidate);
        }
        if candidate.is_dir() {
            if let Ok(avail) = get_available_disk_space(&candidate) {
                checked_dirs.push((candidate.clone(), avail));
                if avail >= min_needed || required_bytes == 0 {
                    return Ok(candidate);
                }
            }
        }
    }

    let report = checked_dirs
        .iter()
        .map(|(p, a)| {
            format!(
                "{}: {:.2} GB available",
                p.display(),
                (*a as f64) / 1_073_741_824.0
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    Err(StageError::Io(format!(
        "Insufficient disk space for snapshot: device requires {:.2} GB, but checked candidate directories [{}] have insufficient free space. Please specify a directory with sufficient space using --out <dir> or FERRIX_TMPDIR.",
        (required_bytes as f64) / 1_073_741_824.0,
        report
    )))
}

pub fn get_device_or_file_size(file: &File, path: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::io::AsRawFd;
        if let Ok(meta) = file.metadata() {
            if meta.file_type().is_block_device() {
                let mut size: u64 = 0;
                let res = unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272, &mut size) };
                if res >= 0 && size > 0 {
                    return size;
                }
            } else if meta.len() > 0 {
                return meta.len();
            }
        }
    }
    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
        let sysfs_size_path = Path::new("/sys/class/block").join(file_name).join("size");
        if let Ok(content) = std::fs::read_to_string(sysfs_size_path) {
            if let Ok(sectors) = content.trim().parse::<u64>() {
                if sectors > 0 {
                    return sectors.saturating_mul(512);
                }
            }
        }
    }
    let mut f = file;
    if let Ok(end_pos) = f.seek(std::io::SeekFrom::End(0)) {
        let _ = f.seek(std::io::SeekFrom::Start(0));
        if end_pos > 0 {
            return end_pos;
        }
    }
    file.metadata().map(|m| m.len()).unwrap_or(0)
}

pub fn open_device_or_file_with_retry(
    path: &Path,
    timeout: std::time::Duration,
) -> std::io::Result<File> {
    let start = std::time::Instant::now();
    loop {
        match File::open(path) {
            Ok(file) => return Ok(file),
            Err(e) => {
                let code = e.raw_os_error();
                let is_transient = code == Some(6) || code == Some(16) || code == Some(11);
                if is_transient && start.elapsed() < timeout {
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    continue;
                }
                return Err(e);
            }
        }
    }
}

pub fn create_snapshot(
    source_path: &Path,
    destination_path: &Path,
    event_sink: &EventSink,
) -> Result<Snapshot, StageError> {
    let mut source_file =
        open_device_or_file_with_retry(source_path, std::time::Duration::from_secs(3)).map_err(
            |e| {
                StageError::Io(format!(
                    "failed to open source {}: {e}",
                    source_path.display()
                ))
            },
        )?;

    let total_size = get_device_or_file_size(&source_file, source_path);

    if let Some(parent) = destination_path.parent() {
        if let Ok(avail) = get_available_disk_space(parent) {
            if total_size > 0 && avail < total_size {
                return Err(StageError::Io(format!(
                    "Insufficient disk space in '{}': required {:.2} GB, available {:.2} GB",
                    parent.display(),
                    (total_size as f64) / 1_073_741_824.0,
                    (avail as f64) / 1_073_741_824.0
                )));
            }
        }
    }

    let mut guard = PartialFileGuard(destination_path, false);

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut dest_file = options.open(destination_path).map_err(|e| {
        StageError::Io(format!(
            "failed to create snapshot {}: {e}",
            destination_path.display()
        ))
    })?;

    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 128 * 1024];
    let mut bytes_copied = 0u64;

    loop {
        let bytes_read = source_file
            .read(&mut buffer)
            .map_err(|e| StageError::Io(format!("read failure during snapshot: {e}")))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);

        dest_file
            .write_all(&buffer[..bytes_read])
            .map_err(|e| StageError::Io(format!("write failure during snapshot: {e}")))?;

        bytes_copied = bytes_copied.saturating_add(bytes_read as u64);

        event_sink.emit(ScanEvent::Progress {
            stage_id: "snapshot".to_string(),
            current: bytes_copied,
            total: if total_size > 0 {
                Some(total_size)
            } else {
                None
            },
            message: Some(format!("snapshotting: {bytes_copied} bytes")),
        });
    }

    dest_file
        .flush()
        .map_err(|e| StageError::Io(format!("flush failed: {e}")))?;

    if let Ok(metadata) = dest_file.metadata() {
        let mut perms = metadata.permissions();
        #[cfg(unix)]
        perms.set_mode(0o400);
        #[cfg(not(unix))]
        perms.set_readonly(true);
        let _ = dest_file.set_permissions(perms);
    }

    guard.1 = true;

    let device_hash = hasher.finalize().to_hex().to_string();

    Ok(Snapshot {
        path: destination_path.to_path_buf(),
        size_bytes: bytes_copied,
        device_hash,
    })
}

pub fn hash_device_or_image(path: &Path) -> Result<(String, u64), StageError> {
    let mut file = File::open(path)
        .map_err(|e| StageError::Io(format!("failed to open target {}: {e}", path.display())))?;

    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 128 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| StageError::Io(format!("read failure during hashing: {e}")))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
        total_bytes = total_bytes.saturating_add(bytes_read as u64);
    }

    Ok((hasher.finalize().to_hex().to_string(), total_bytes))
}
