use ferrix_usb::sandbox::{
    apply_landlock, build_scanner_seccomp_filter, drop_privileges, LandlockStatus,
};
use std::path::Path;

#[test]
fn test_drop_privileges_non_root() {
    let res = drop_privileges();
    assert!(res.is_ok());
    let (uid, _gid, dropped) = res.unwrap();
    if uid != 0 {
        assert!(!dropped);
    }
}

#[test]
fn test_build_scanner_seccomp_filter() {
    let res = build_scanner_seccomp_filter();
    assert!(res.is_ok());
    let bpf_program = res.unwrap();
    assert!(!bpf_program.is_empty());
}

#[test]
fn test_apply_landlock_dry_run() {
    let temp_dir = std::env::temp_dir();
    let res = apply_landlock(&[&temp_dir as &Path], &[]);
    assert!(res.is_ok());
    let status = res.unwrap();
    assert!(
        status == LandlockStatus::Enforced
            || status == LandlockStatus::PartiallyEnforced
            || status == LandlockStatus::NotSupported
    );
}

#[test]
fn test_apply_seccomp_execution_and_network_block() {
    use ferrix_usb::sandbox::{apply_seccomp, SeccompStatus};
    use nix::sys::wait::waitpid;
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            assert_eq!(status, nix::sys::wait::WaitStatus::Exited(child, 0));
        }
        Ok(ForkResult::Child) => {
            let res = apply_seccomp();
            if let Ok(SeccompStatus::Enforced) = res {
                let mut buf = [0u8; 16];
                let _ =
                    unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                if sock >= 0 {
                    unsafe { libc::close(sock) };
                    unsafe { libc::_exit(1) };
                }
            }
            unsafe { libc::_exit(0) };
        }
        Err(_) => {}
    }
}
