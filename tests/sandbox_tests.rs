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
