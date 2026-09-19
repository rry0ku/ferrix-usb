use crate::core::{Finding, Severity, StageError, Verdict};
use crate::manifest::Manifest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsSummary {
    pub verdict: Verdict,
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullReport {
    pub summary: FindingsSummary,
    pub manifest: Manifest,
    pub findings: Vec<Finding>,
}

pub fn generate_json_report(
    manifest: &Manifest,
    findings: &[Finding],
) -> Result<String, StageError> {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    let summary = FindingsSummary {
        verdict: manifest.verdict,
        total: findings.len(),
        critical,
        high,
        medium,
        low,
        info,
    };

    let report = FullReport {
        summary,
        manifest: manifest.clone(),
        findings: findings.to_vec(),
    };

    serde_json::to_string_pretty(&report)
        .map_err(|e| StageError::Internal(format!("failed to serialize report to JSON: {e}")))
}
