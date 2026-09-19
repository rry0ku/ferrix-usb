use crate::core::{Finding, Location, Severity, StageError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum SuppressionScope {
    FileHash(String),
    RuleAndPath {
        rule_id: String,
        path_pattern: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    pub id: String,
    pub scope: SuppressionScope,
    pub reason: String,
    pub author: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub finding: Finding,
    pub suppression_id: String,
    pub suppression_reason: String,
    pub author: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionStore {
    pub suppressions: Vec<Suppression>,
}

impl SuppressionStore {
    pub fn load(path: &Path) -> Result<Self, StageError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read(path).map_err(|e| {
            StageError::Io(format!(
                "failed to read suppression store {}: {e}",
                path.display()
            ))
        })?;
        serde_json::from_slice(&data).map_err(|e| {
            StageError::Parse(format!(
                "failed to parse suppression store {}: {e}",
                path.display()
            ))
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), StageError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    StageError::Io(format!(
                        "failed to create suppression dir {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        let serialized = serde_json::to_string_pretty(self).map_err(|e| {
            StageError::Internal(format!("failed to serialize suppression store: {e}"))
        })?;
        fs::write(path, serialized).map_err(|e| {
            StageError::Io(format!(
                "failed to write suppression store {}: {e}",
                path.display()
            ))
        })
    }

    pub fn is_suppressible(finding: &Finding) -> Result<(), StageError> {
        if finding.severity == Severity::Critical {
            return Err(StageError::Parse(
                "cannot suppress Critical finding".to_string(),
            ));
        }

        if finding.id == "FX-PART-001"
            || finding.id == "FX-PART-004"
            || finding.id == "FX-FS-001"
            || finding.id == "FX-FS-004"
        {
            return Err(StageError::Parse(format!(
                "cannot suppress structural ambiguity or differential finding {}",
                finding.id
            )));
        }

        if finding.reason.to_lowercase().contains("parse error")
            || finding.reason.to_lowercase().contains("stage error")
        {
            return Err(StageError::Parse(
                "cannot suppress parse or stage errors".to_string(),
            ));
        }

        Ok(())
    }

    pub fn add_suppression(&mut self, suppression: Suppression) -> Result<(), StageError> {
        if suppression.reason.trim().is_empty() {
            return Err(StageError::Parse(
                "suppression reason cannot be empty".to_string(),
            ));
        }

        if suppression.author.trim().is_empty() {
            return Err(StageError::Parse(
                "suppression author cannot be empty".to_string(),
            ));
        }

        if suppression.expires_at <= suppression.created_at {
            return Err(StageError::Parse(
                "suppression expires_at must be after created_at".to_string(),
            ));
        }

        match &suppression.scope {
            SuppressionScope::FileHash(hash) => {
                if hash.trim().is_empty() {
                    return Err(StageError::Parse(
                        "suppression file hash cannot be empty".to_string(),
                    ));
                }
            }
            SuppressionScope::RuleAndPath {
                rule_id,
                path_pattern,
            } => {
                if rule_id.trim().is_empty() {
                    return Err(StageError::Parse(
                        "suppression rule_id cannot be empty".to_string(),
                    ));
                }
                let trimmed_pattern = path_pattern.trim();
                if trimmed_pattern.is_empty()
                    || trimmed_pattern == "*"
                    || trimmed_pattern == "**"
                    || trimmed_pattern == "/*"
                {
                    return Err(StageError::Parse(
                        "wildcard-only scopes are strictly rejected".to_string(),
                    ));
                }
            }
        }

        self.suppressions.push(suppression);
        Ok(())
    }

    pub fn check_finding<'a>(
        &'a self,
        finding: &Finding,
        file_hash: Option<&str>,
        now: u64,
    ) -> Option<&'a Suppression> {
        if Self::is_suppressible(finding).is_err() {
            return None;
        }

        for sup in &self.suppressions {
            if sup.expires_at <= now {
                continue;
            }

            match &sup.scope {
                SuppressionScope::FileHash(expected_hash) => {
                    if let Some(h) = file_hash {
                        if h.eq_ignore_ascii_case(expected_hash) {
                            return Some(sup);
                        }
                    }
                }
                SuppressionScope::RuleAndPath {
                    rule_id,
                    path_pattern,
                } => {
                    if finding.id == *rule_id && path_matches(&finding.location, path_pattern) {
                        return Some(sup);
                    }
                }
            }
        }

        None
    }

    pub fn list_active(&self, now: u64) -> Vec<&Suppression> {
        self.suppressions
            .iter()
            .filter(|s| s.expires_at > now)
            .collect()
    }
}

pub fn path_matches(location: &Location, pattern: &str) -> bool {
    match location {
        Location::Path(media_path) => {
            let path_str = String::from_utf8_lossy(media_path.as_bytes()).to_string();
            let pat = pattern.trim();
            if let Some(suffix) = pat.strip_prefix('*') {
                path_str.ends_with(suffix)
            } else if let Some(prefix) = pat.strip_suffix('*') {
                path_str.starts_with(prefix)
            } else {
                path_str == pat || path_str.contains(pat)
            }
        }
        _ => false,
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
