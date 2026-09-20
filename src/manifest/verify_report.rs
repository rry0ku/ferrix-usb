use crate::core::StageError;
use crate::report::forensic::ForensicReport;
use ed25519_dalek::VerifyingKey;
use std::fs;
use std::path::Path;

pub fn verify_forensic_report_file(
    report_path: &Path,
    pubkey: &VerifyingKey,
) -> Result<bool, StageError> {
    let data = fs::read(report_path).map_err(|e| {
        StageError::Io(format!(
            "failed to read report file {}: {e}",
            report_path.display()
        ))
    })?;

    let report: ForensicReport = serde_json::from_slice(&data).map_err(|e| {
        StageError::Parse(format!(
            "failed to parse forensic report JSON in {}: {e}",
            report_path.display()
        ))
    })?;

    report.verify_signature(pubkey)?;
    Ok(true)
}
