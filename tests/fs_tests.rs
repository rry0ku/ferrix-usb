use ferrix_usb::core::{resolve_verdict, ScanContext, Stage, StageResult, StageStatus, Verdict};
use ferrix_usb::fs::FilesystemScanStage;
use std::fs::File;
use std::io::Write;

fn write_temp_image(name: &str, data: &[u8]) -> std::path::PathBuf {
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
fn test_clean_fat32_scan_passes() {
    let img = make_clean_fat32_disk(12000, 2048, 8192);
    let path = write_temp_image("ferrix_test_clean_fat32.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FilesystemScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.is_empty());

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Pass);
}

#[test]
fn test_fat32_size_mismatch_quarantines() {
    let mut img = make_clean_fat32_disk(12000, 2048, 8192);
    let fs_offset = (2048 * 512) as usize;
    let excessive_sectors = 15000u32;
    img[fs_offset + 32..fs_offset + 36].copy_from_slice(&excessive_sectors.to_le_bytes());
    let backup_offset = fs_offset + 6 * 512;
    img[backup_offset + 32..backup_offset + 36].copy_from_slice(&excessive_sectors.to_le_bytes());

    let path = write_temp_image("ferrix_test_fat32_size_mismatch.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FilesystemScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FS-001"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_fat32_backup_mismatch_quarantines() {
    let mut img = make_clean_fat32_disk(12000, 2048, 8192);
    let backup_offset = (2048 * 512) + (6 * 512);
    img[backup_offset + 71..backup_offset + 82].copy_from_slice(b"DIFFERENT  ");

    let path = write_temp_image("ferrix_test_fat32_backup_mismatch.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FilesystemScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FS-002"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_duplicate_entries_quarantines() {
    let mut img = make_clean_fat32_disk(12000, 2048, 8192);

    let fs_offset = 2048 * 512;
    let reserved_sectors = 32;
    let num_fats = 2;
    let sectors_per_fat = 32;
    let root_cluster = 2;
    let sectors_per_cluster = 8;
    let bytes_per_sector = 512;

    let first_data_sector = reserved_sectors + (num_fats * sectors_per_fat);
    let cluster_offset = fs_offset
        + (first_data_sector + (root_cluster - 2) * sectors_per_cluster) * bytes_per_sector;

    let e1 = &mut img[cluster_offset..cluster_offset + 32];
    e1[0..8].copy_from_slice(b"PAYLOAD ");
    e1[8..11].copy_from_slice(b"TXT");
    e1[11] = 0x20;

    let e2 = &mut img[cluster_offset + 32..cluster_offset + 64];
    e2[0..8].copy_from_slice(b"payload ");
    e2[8..11].copy_from_slice(b"txt");
    e2[11] = 0x20;

    let path = write_temp_image("ferrix_test_fat32_dup_entries.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FilesystemScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FS-003"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_polyglot_fat_ext4_quarantines() {
    let mut img = make_clean_fat32_disk(12000, 2048, 8192);

    let ext_offset = (2048 * 512) + 1024;
    let ext_sb = &mut img[ext_offset..ext_offset + 1024];
    ext_sb[0..4].copy_from_slice(&100u32.to_le_bytes());
    ext_sb[4..8].copy_from_slice(&2048u32.to_le_bytes());
    ext_sb[24..28].copy_from_slice(&2u32.to_le_bytes());
    ext_sb[56] = 0x53;
    ext_sb[57] = 0xEF;

    let path = write_temp_image("ferrix_test_polyglot.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FilesystemScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FS-004"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}
