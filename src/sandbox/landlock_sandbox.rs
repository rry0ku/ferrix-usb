use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockStatus {
    Enforced,
    PartiallyEnforced,
    NotSupported,
}

#[derive(Debug, thiserror::Error)]
pub enum LandlockError {
    #[error("failed to create ruleset: {0}")]
    CreateRuleset(String),
    #[error("failed to add path rule for {0}: {1}")]
    AddRule(String, String),
    #[error("failed to restrict process: {0}")]
    RestrictSelf(String),
}

pub fn apply_landlock(
    allowed_read_paths: &[&Path],
    allowed_write_paths: &[&Path],
) -> Result<LandlockStatus, LandlockError> {
    let abi = ABI::V1;
    let access = AccessFs::from_all(abi);

    let ruleset = match Ruleset::default().handle_access(access) {
        Ok(r) => match r.create() {
            Ok(created) => created,
            Err(_) => return Ok(LandlockStatus::NotSupported),
        },
        Err(_) => return Ok(LandlockStatus::NotSupported),
    };

    let mut current_ruleset = ruleset;
    let read_access = AccessFs::from_read(abi);
    let all_access = AccessFs::from_all(abi);

    for path in allowed_read_paths {
        if path.exists() {
            if let Ok(fd) = PathFd::new(path) {
                current_ruleset = current_ruleset
                    .add_rule(PathBeneath::new(fd, read_access))
                    .map_err(|e| {
                        LandlockError::AddRule(path.display().to_string(), e.to_string())
                    })?;
            }
        }
    }

    for path in allowed_write_paths {
        if path.exists() {
            if let Ok(fd) = PathFd::new(path) {
                current_ruleset = current_ruleset
                    .add_rule(PathBeneath::new(fd, all_access))
                    .map_err(|e| {
                        LandlockError::AddRule(path.display().to_string(), e.to_string())
                    })?;
            }
        }
    }

    match current_ruleset.restrict_self() {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(LandlockStatus::Enforced),
            RulesetStatus::PartiallyEnforced => Ok(LandlockStatus::PartiallyEnforced),
            RulesetStatus::NotEnforced => Ok(LandlockStatus::NotSupported),
        },
        Err(e) => Err(LandlockError::RestrictSelf(e.to_string())),
    }
}
