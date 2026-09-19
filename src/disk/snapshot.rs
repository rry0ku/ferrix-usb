use crate::core::{EventSink, ScanEvent, StageError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

pub struct Snapshot {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub device_hash: String,
}

pub fn create_snapshot(
    source_path: &Path,
    destination_path: &Path,
    event_sink: &EventSink,
) -> Result<Snapshot, StageError> {
    let mut source_file = File::open(source_path).map_err(|e| {
        StageError::Io(format!(
            "failed to open source {}: {e}",
            source_path.display()
        ))
    })?;

    let mut total_size = source_file.metadata().map(|m| m.len()).unwrap_or(0);
    if total_size == 0 {
        if let Ok(end_pos) = source_file.seek(std::io::SeekFrom::End(0)) {
            total_size = end_pos;
            let _ = source_file.seek(std::io::SeekFrom::Start(0));
        }
    }

    let mut dest_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(destination_path)
        .map_err(|e| {
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
        perms.set_readonly(true);
        let _ = dest_file.set_permissions(perms);
    }

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
