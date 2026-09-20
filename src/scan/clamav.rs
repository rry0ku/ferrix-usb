use crate::core::{Confidence, Finding, Location, MediaPath, Severity, StageError};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const DEFAULT_CLAMD_SOCKETS: &[&str] = &[
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/tmp/clamd.socket",
];

pub struct ClamAvScanner {
    pub socket_path: Option<String>,
}

impl ClamAvScanner {
    pub fn new(socket_path: Option<String>) -> Self {
        Self { socket_path }
    }

    pub fn scan_bytes(
        &self,
        data: &[u8],
        _media_path: &MediaPath,
    ) -> Result<Option<String>, StageError> {
        if let Some(ref sock) = self.socket_path {
            if Path::new(sock).exists() {
                return scan_via_socket(Path::new(sock), data);
            }
        }

        for &sock in DEFAULT_CLAMD_SOCKETS {
            if Path::new(sock).exists() {
                return scan_via_socket(Path::new(sock), data);
            }
        }

        scan_via_cli(data)
    }

    pub fn inspect_and_record(
        &self,
        data: &[u8],
        media_path: &MediaPath,
        findings: &mut Vec<Finding>,
    ) -> Result<(), StageError> {
        match self.scan_bytes(data, media_path) {
            Ok(Some(signature)) => {
                findings.push(Finding {
                    id: "FX-CLAM-001".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    stage: "clamav_scan".to_string(),
                    location: Location::Path(media_path.clone()),
                    reason: format!("ClamAV malware signature detected: {signature}"),
                    evidence: format!("signature '{signature}' matched file contents"),
                });
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn scan_via_socket(socket_path: &Path, data: &[u8]) -> Result<Option<String>, StageError> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        StageError::Io(format!(
            "failed to connect to clamd socket {}: {e}",
            socket_path.display()
        ))
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| StageError::Io(format!("failed to set clamd read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| StageError::Io(format!("failed to set clamd write timeout: {e}")))?;

    stream
        .write_all(b"zINSTREAM\0")
        .map_err(|e| StageError::Io(format!("failed to write INSTREAM command to clamd: {e}")))?;

    let chunk_size = 64 * 1024;
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        let chunk = &data[offset..end];
        let len_be = (chunk.len() as u32).to_be_bytes();
        stream
            .write_all(&len_be)
            .map_err(|e| StageError::Io(format!("failed to write chunk size to clamd: {e}")))?;
        stream
            .write_all(chunk)
            .map_err(|e| StageError::Io(format!("failed to write chunk data to clamd: {e}")))?;
        offset = end;
    }

    stream
        .write_all(&0u32.to_be_bytes())
        .map_err(|e| StageError::Io(format!("failed to write stream terminator to clamd: {e}")))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| StageError::Io(format!("failed to read clamd response: {e}")))?;

    parse_clamd_response(&response)
}

fn parse_clamd_response(response: &str) -> Result<Option<String>, StageError> {
    let trimmed = response.trim();
    if trimmed.ends_with("OK") {
        Ok(None)
    } else if let Some(found_idx) = trimmed.rfind("FOUND") {
        let prefix = trimmed[..found_idx].trim();
        let sig = if let Some(colon_idx) = prefix.rfind(':') {
            prefix[colon_idx + 1..].trim()
        } else {
            prefix
        };
        Ok(Some(sig.to_string()))
    } else if trimmed.ends_with("ERROR") {
        Err(StageError::Internal(format!(
            "clamd returned error: {trimmed}"
        )))
    } else {
        Ok(None)
    }
}

fn scan_via_cli(data: &[u8]) -> Result<Option<String>, StageError> {
    let mut child = match Command::new("clamscan")
        .arg("--no-summary")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(data);
    }

    let output = child
        .wait_with_output()
        .map_err(|e| StageError::Io(format!("failed to wait on clamscan: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.code() == Some(1) || stdout.contains("FOUND") {
        if let Some(idx) = stdout.find("FOUND") {
            let line = stdout[..idx].lines().last().unwrap_or("").trim();
            let sig = line.split(':').nth(1).unwrap_or(line).trim();
            return Ok(Some(sig.to_string()));
        }
        return Ok(Some("Unknown ClamAV Threat".to_string()));
    }

    Ok(None)
}
