use nix::unistd::{geteuid, getgid, getuid, setgid, setgroups, setuid, Gid, Uid};
use std::env;

#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    #[error("failed to set GID to {0}: {1}")]
    SetGid(u32, nix::Error),
    #[error("failed to set UID to {0}: {1}")]
    SetUid(u32, nix::Error),
    #[error("failed to clear supplementary groups: {0}")]
    SetGroups(nix::Error),
    #[error("privilege drop verification failed: UID is still {0}, EUID is {1}")]
    VerificationFailed(u32, u32),
}

pub fn drop_privileges() -> Result<(u32, u32, bool), PrivilegeError> {
    let current_uid = getuid().as_raw();
    let current_euid = geteuid().as_raw();

    if current_uid != 0 && current_euid != 0 {
        return Ok((current_uid, getgid().as_raw(), false));
    }

    let target_uid = env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&id| id != 0)
        .unwrap_or(65534);

    let target_gid = env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&id| id != 0)
        .unwrap_or(65534);

    let target_gid_obj = Gid::from_raw(target_gid);
    let _ = setgroups(&[target_gid_obj]);

    setgid(target_gid_obj).map_err(|e| PrivilegeError::SetGid(target_gid, e))?;

    setuid(Uid::from_raw(target_uid)).map_err(|e| PrivilegeError::SetUid(target_uid, e))?;

    let final_uid = getuid().as_raw();
    let final_euid = geteuid().as_raw();
    if final_uid != target_uid || final_euid != target_uid {
        return Err(PrivilegeError::VerificationFailed(final_uid, final_euid));
    }

    Ok((target_uid, target_gid, true))
}
