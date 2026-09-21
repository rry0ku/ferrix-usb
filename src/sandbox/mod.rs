pub mod landlock_sandbox;
pub mod privilege;
pub mod seccomp_sandbox;

pub use landlock_sandbox::*;
pub use privilege::*;
pub use seccomp_sandbox::*;

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxInfo {
    pub privilege_dropped: bool,
    pub uid: u32,
    pub gid: u32,
    pub landlock_status: LandlockStatus,
    pub seccomp_status: SeccompStatus,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("privilege drop error: {0}")]
    Privilege(#[from] PrivilegeError),
    #[error("landlock error: {0}")]
    Landlock(#[from] LandlockError),
    #[error("seccomp error: {0}")]
    Seccomp(#[from] SeccompError),
}

pub fn enter_sandbox(
    allowed_read_paths: &[&Path],
    allowed_write_paths: &[&Path],
) -> Result<SandboxInfo, SandboxError> {
    let (uid, gid, privilege_dropped) = drop_privileges()?;
    let landlock_status = apply_landlock(allowed_read_paths, allowed_write_paths)?;
    let seccomp_status = apply_seccomp()?;

    Ok(SandboxInfo {
        privilege_dropped,
        uid,
        gid,
        landlock_status,
        seccomp_status,
    })
}

pub fn enter_sandbox_for_thread(
    allowed_read_paths: &[&Path],
    allowed_write_paths: &[&Path],
) -> Result<SandboxInfo, SandboxError> {
    let landlock_status = apply_landlock(allowed_read_paths, allowed_write_paths)?;
    let seccomp_status = apply_seccomp()?;

    Ok(SandboxInfo {
        privilege_dropped: false,
        uid: nix::unistd::getuid().as_raw(),
        gid: nix::unistd::getgid().as_raw(),
        landlock_status,
        seccomp_status,
    })
}
