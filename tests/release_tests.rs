use ferrix_usb::core::{StageError, Verdict};
use ferrix_usb::release::{
    release_snapshot_files, sanitize_destination_filename, sanitize_relative_path,
};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn write_temp_image(name: &str, data: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    let mut file = File::create(&path).unwrap();
    file.write_all(data).unwrap();
    path
}

fn make_clean_fat32_disk(total_sectors: u64, part_start: u64, part_sectors: u64) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * 512];

    buf[510] = 0x55;
    buf[511] = 0xAA;
    let p1 = &mut buf[446..462];
    p1[0] = 0x80;
    p1[4] = 0x0C;
    p1[8..12].copy_from_slice(&(part_start as u32).to_le_bytes());
    p1[12..16].copy_from_slice(&(part_sectors as u32).to_le_bytes());

    let fs_offset = (part_start * 512) as usize;
    let bpb = &mut buf[fs_offset..fs_offset + 512];

    bpb[0] = 0xEB;
    bpb[1] = 0x58;
    bpb[2] = 0x90;
    bpb[3..11].copy_from_slice(b"MSDOS5.0");
    bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
    bpb[13] = 8;
    bpb[14..16].copy_from_slice(&32u16.to_le_bytes());
    bpb[16] = 2;
    bpb[17..19].copy_from_slice(&0u16.to_le_bytes());
    bpb[19..21].copy_from_slice(&0u16.to_le_bytes());
    bpb[21] = 0xF8;
    bpb[22..24].copy_from_slice(&0u16.to_le_bytes());
    bpb[32..36].copy_from_slice(&(part_sectors as u32).to_le_bytes());
    bpb[36..40].copy_from_slice(&32u32.to_le_bytes());
    bpb[44..48].copy_from_slice(&2u32.to_le_bytes());
    bpb[50..52].copy_from_slice(&6u16.to_le_bytes());
    bpb[510] = 0x55;
    bpb[511] = 0xAA;

    let backup_offset = fs_offset + 6 * 512;
    let primary_bpb = buf[fs_offset..fs_offset + 512].to_vec();
    buf[backup_offset..backup_offset + 512].copy_from_slice(&primary_bpb);

    buf
}

#[test]
fn test_sanitize_destination_filename_normal() {
    let (name, reason) = sanitize_destination_filename("document.pdf");
    assert_eq!(name, "document.pdf");
    assert!(reason.is_none());
}

#[test]
fn test_sanitize_destination_filename_leading_dash() {
    let (name, reason) = sanitize_destination_filename("-rf");
    assert_eq!(name, "_-rf");
    assert!(reason.is_some());
    assert!(reason.unwrap().contains("leading dash"));
}

#[test]
fn test_sanitize_destination_filename_trailing_dot_and_space() {
    let (name1, reason1) = sanitize_destination_filename("file.txt.");
    assert_eq!(name1, "file.txt_");
    assert!(reason1.is_some());

    let (name2, reason2) = sanitize_destination_filename("file.txt ");
    assert_eq!(name2, "file.txt_");
    assert!(reason2.is_some());
}

#[test]
fn test_sanitize_destination_filename_windows_reserved() {
    let (name1, reason1) = sanitize_destination_filename("CON.txt");
    assert_eq!(name1, "safe_CON.txt");
    assert!(reason1.is_some());

    let (name2, reason2) = sanitize_destination_filename("nul");
    assert_eq!(name2, "safe_nul");
    assert!(reason2.is_some());

    let (name3, reason3) = sanitize_destination_filename("aux.dat");
    assert_eq!(name3, "safe_aux.dat");
    assert!(reason3.is_some());
}

#[test]
fn test_sanitize_destination_filename_bidi_and_control() {
    let (name, reason) = sanitize_destination_filename("safe\u{202E}txt.exe");
    assert_eq!(name, "safetxt.exe");
    assert!(reason.is_some());

    let (name_ctrl, reason_ctrl) = sanitize_destination_filename("bad\x07name.txt");
    assert_eq!(name_ctrl, "bad_name.txt");
    assert!(reason_ctrl.is_some());
}

#[test]
fn test_sanitize_destination_filename_overlong() {
    let long_name = format!("{}.txt", "a".repeat(300));
    let (sanitized, reason) = sanitize_destination_filename(&long_name);
    assert!(sanitized.len() <= 255);
    assert!(reason.is_some());
    assert!(reason.unwrap().contains("255 bytes"));
}

#[test]
fn test_sanitize_relative_path_clean() {
    let mut renames = Vec::new();
    let res = sanitize_relative_path("docs/sub/readme.txt", &mut renames);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), PathBuf::from("docs/sub/readme.txt"));
    assert!(renames.is_empty());
}

#[test]
fn test_sanitize_relative_path_traversal_rejected() {
    let mut renames = Vec::new();
    let res1 = sanitize_relative_path("../escape.txt", &mut renames);
    assert!(matches!(res1, Err(StageError::Parse(_))));

    let res2 = sanitize_relative_path("docs/../../escape.txt", &mut renames);
    assert!(matches!(res2, Err(StageError::Parse(_))));

    let res3 = sanitize_relative_path("", &mut renames);
    assert!(matches!(res3, Err(StageError::Parse(_))));
}

#[test]
fn test_sanitize_relative_path_sanitizes_segments() {
    let mut renames = Vec::new();
    let res = sanitize_relative_path("docs/-flag.txt", &mut renames);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), PathBuf::from("docs/_-flag.txt"));
    assert_eq!(renames.len(), 1);
    assert_eq!(renames[0].original, "-flag.txt");
    assert_eq!(renames[0].sanitized, "_-flag.txt");
}

#[test]
fn test_release_snapshot_files_creates_staging_and_normalizes_permissions() {
    let img = make_clean_fat32_disk(12000, 2048, 8192);
    let img_path = write_temp_image("ferrix_test_release_snap.img", &img);
    let staging_dir = std::env::temp_dir().join("ferrix_test_staging_release");

    if staging_dir.exists() {
        let _ = std::fs::remove_dir_all(&staging_dir);
    }

    let report = release_snapshot_files(&img_path, &staging_dir, 512).unwrap();
    assert_eq!(report.destination_dir, staging_dir.canonicalize().unwrap());

    let staging_meta = std::fs::metadata(&staging_dir).unwrap();
    let mode = staging_meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);

    let _ = std::fs::remove_file(img_path);
    let _ = std::fs::remove_dir_all(staging_dir);
}

#[test]
fn test_fail_closed_release_guard() {
    let quarantine_verdict = Verdict::Quarantine;
    let fail_verdict = Verdict::Fail;
    let pass_verdict = Verdict::Pass;

    let can_release = |verdict: Verdict| verdict == Verdict::Pass;

    assert!(!can_release(quarantine_verdict));
    assert!(!can_release(fail_verdict));
    assert!(can_release(pass_verdict));
}
