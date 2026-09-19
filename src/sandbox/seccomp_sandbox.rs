use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompStatus {
    Enforced,
    NotSupported,
}

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("failed to build seccomp filter: {0}")]
    BuildFilter(String),
    #[error("failed to apply seccomp filter: {0}")]
    ApplyFilter(String),
}

pub fn build_scanner_seccomp_filter() -> Result<BpfProgram, SeccompError> {
    let mut rules = BTreeMap::new();

    let allowed_syscalls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_getdents64,
        libc::SYS_openat,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_sched_yield,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_restart_syscall,
        libc::SYS_clone,
        libc::SYS_set_robust_list,
        libc::SYS_prlimit64,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
    ];

    for sys in allowed_syscalls {
        rules.insert(sys, vec![]);
    }

    #[cfg(target_arch = "x86_64")]
    let target_arch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let target_arch = TargetArch::aarch64;
    #[cfg(target_arch = "x86")]
    let target_arch = TargetArch::x86;
    #[cfg(target_arch = "arm")]
    let target_arch = TargetArch::arm;
    #[cfg(target_arch = "riscv64")]
    let target_arch = TargetArch::riscv64;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::KillProcess,
        target_arch,
    )
    .map_err(|e| SeccompError::BuildFilter(format!("{e:?}")))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| SeccompError::BuildFilter(format!("{e:?}")))?;

    Ok(prog)
}

pub fn apply_seccomp() -> Result<SeccompStatus, SeccompError> {
    let prog = build_scanner_seccomp_filter()?;
    apply_filter(&prog).map_err(|e| SeccompError::ApplyFilter(format!("{e:?}")))?;
    Ok(SeccompStatus::Enforced)
}
