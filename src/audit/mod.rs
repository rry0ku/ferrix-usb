use crate::core::{StageError, Verdict};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: u64,
    pub event_type: String,
    pub scan_id: Option<String>,
    pub device_hash: Option<String>,
    pub verdict: Option<Verdict>,
    pub details: serde_json::Value,
    pub prev_entry_hash: String,
    pub entry_hash: String,
}

impl AuditEntry {
    pub fn compute_entry_hash(&self) -> Result<String, StageError> {
        let mut clone = self.clone();
        clone.entry_hash = String::new();
        let serialized = serde_json::to_vec(&clone)
            .map_err(|e| StageError::Internal(format!("failed to serialize audit entry: {e}")))?;
        Ok(blake3::hash(&serialized).to_hex().to_string())
    }
}

pub fn append_audit_entry(
    log_path: &Path,
    event_type: &str,
    scan_id: Option<&str>,
    device_hash: Option<&str>,
    verdict: Option<Verdict>,
    details: serde_json::Value,
) -> Result<AuditEntry, StageError> {
    if let Some(parent) = log_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                StageError::Io(format!(
                    "failed to create audit log dir {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(log_path).map_err(|e| {
        StageError::Io(format!(
            "failed to open audit log {}: {e}",
            log_path.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_EX);
        }
    }

    let reader = BufReader::new(&file);
    let mut last_entry: Option<AuditEntry> = None;

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| StageError::Io(format!("audit log read error: {e}")))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(trimmed)
            .map_err(|e| StageError::Parse(format!("corrupted audit log line '{trimmed}': {e}")))?;
        let computed = entry.compute_entry_hash()?;
        if computed != entry.entry_hash {
            return Err(StageError::Parse(format!(
                "tampered audit log entry at index {}",
                entry.index
            )));
        }
        last_entry = Some(entry);
    }

    let (next_index, prev_hash) = if let Some(last) = last_entry {
        (last.index + 1, last.entry_hash)
    } else {
        (0, GENESIS_HASH.to_string())
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut entry = AuditEntry {
        index: next_index,
        timestamp,
        event_type: event_type.to_string(),
        scan_id: scan_id.map(|s| s.to_string()),
        device_hash: device_hash.map(|s| s.to_string()),
        verdict,
        details,
        prev_entry_hash: prev_hash,
        entry_hash: String::new(),
    };

    let hash = entry.compute_entry_hash()?;
    entry.entry_hash = hash;

    let serialized = serde_json::to_string(&entry)
        .map_err(|e| StageError::Internal(format!("failed to serialize new audit entry: {e}")))?;

    use std::io::Seek;
    file.seek(std::io::SeekFrom::End(0))
        .map_err(|e| StageError::Io(format!("failed to seek to end of audit log: {e}")))?;

    writeln!(file, "{serialized}").map_err(|e| {
        StageError::Io(format!(
            "failed to write audit log line to {}: {e}",
            log_path.display()
        ))
    })?;

    file.flush()
        .map_err(|e| StageError::Io(format!("failed to flush audit log: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
    }

    Ok(entry)
}

pub fn verify_audit_chain(log_path: &Path) -> Result<bool, StageError> {
    if !log_path.exists() {
        return Ok(true);
    }

    let file = File::open(log_path).map_err(|e| {
        StageError::Io(format!(
            "failed to open audit log {}: {e}",
            log_path.display()
        ))
    })?;
    let reader = BufReader::new(file);

    let mut expected_index = 0u64;
    let mut expected_prev = GENESIS_HASH.to_string();

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| StageError::Io(format!("audit log read error: {e}")))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let entry: AuditEntry = serde_json::from_str(trimmed)
            .map_err(|e| StageError::Parse(format!("corrupted audit entry: {e}")))?;

        if entry.index != expected_index {
            return Ok(false);
        }

        if entry.prev_entry_hash != expected_prev {
            return Ok(false);
        }

        let computed = entry.compute_entry_hash()?;
        if computed != entry.entry_hash {
            return Ok(false);
        }

        expected_prev = entry.entry_hash;
        expected_index += 1;
    }

    Ok(true)
}
