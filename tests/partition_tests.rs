use ferrix_usb::core::{resolve_verdict, ScanContext, Stage, StageResult, StageStatus, Verdict};
use ferrix_usb::disk::partition::crc32;
use ferrix_usb::disk::PartitionScanStage;
use std::fs::File;
use std::io::Write;

fn make_clean_mbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];

    buf[510] = 0x55;
    buf[511] = 0xAA;

    let p1 = &mut buf[446..462];
    p1[0] = 0x80;
    p1[4] = 0x83;

    let start_lba = 2048u32;
    let sector_count = (total_sectors - 2048) as u32;

    p1[8..12].copy_from_slice(&start_lba.to_le_bytes());
    p1[12..16].copy_from_slice(&sector_count.to_le_bytes());

    buf
}

fn make_overlapping_mbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let p1 = &mut buf[446..462];
    p1[0] = 0x00;
    p1[4] = 0x83;
    p1[8..12].copy_from_slice(&2048u32.to_le_bytes());
    p1[12..16].copy_from_slice(&4096u32.to_le_bytes());

    let p2 = &mut buf[462..478];
    p2[0] = 0x00;
    p2[4] = 0x83;
    p2[8..12].copy_from_slice(&4096u32.to_le_bytes());
    p2[12..16].copy_from_slice(&4096u32.to_le_bytes());

    buf
}

fn make_out_of_bounds_mbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let p1 = &mut buf[446..462];
    p1[0] = 0x00;
    p1[4] = 0x83;
    p1[8..12].copy_from_slice(&2048u32.to_le_bytes());
    let excessive_sectors = (total_sectors + 1000) as u32;
    p1[12..16].copy_from_slice(&excessive_sectors.to_le_bytes());

    buf
}

fn make_hidden_type_mbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let p1 = &mut buf[446..462];
    p1[0] = 0x00;
    p1[4] = 0x1B;
    p1[8..12].copy_from_slice(&2048u32.to_le_bytes());
    let count = (total_sectors - 2048) as u32;
    p1[12..16].copy_from_slice(&count.to_le_bytes());

    buf
}

fn make_unallocated_data_mbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = make_clean_mbr(total_sectors, sector_size);
    let secret_offset = 2 * sector_size;
    buf[secret_offset..secret_offset + 12].copy_from_slice(b"CONFIDENTIAL");
    buf
}

fn make_clean_gpt(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];

    buf[510] = 0x55;
    buf[511] = 0xAA;
    let pmbr = &mut buf[446..462];
    pmbr[4] = 0xEE;
    pmbr[8..12].copy_from_slice(&1u32.to_le_bytes());
    let pmbr_size = (total_sectors.saturating_sub(1).min(0xFFFFFFFF)) as u32;
    pmbr[12..16].copy_from_slice(&pmbr_size.to_le_bytes());

    let mut entries = vec![0u8; 128 * 128];
    let e1 = &mut entries[0..128];
    e1[0..16].copy_from_slice(&[
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ]);
    e1[16..32].copy_from_slice(&[1u8; 16]);
    let start_lba = 2048u64;
    let end_lba = total_sectors - 35;
    e1[32..40].copy_from_slice(&start_lba.to_le_bytes());
    e1[40..48].copy_from_slice(&end_lba.to_le_bytes());

    let entries_crc = crc32(&entries);

    let mut header = vec![0u8; 92];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x00010000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[24..32].copy_from_slice(&1u64.to_le_bytes());
    let backup_lba = total_sectors - 1;
    header[32..40].copy_from_slice(&backup_lba.to_le_bytes());
    header[40..48].copy_from_slice(&34u64.to_le_bytes());
    header[48..56].copy_from_slice(&(total_sectors - 35).to_le_bytes());
    header[56..72].copy_from_slice(&[2u8; 16]);
    header[72..80].copy_from_slice(&2u64.to_le_bytes());
    header[80..84].copy_from_slice(&128u32.to_le_bytes());
    header[84..88].copy_from_slice(&128u32.to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());

    let header_crc = crc32(&header);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());

    buf[sector_size..sector_size + 92].copy_from_slice(&header);
    buf[2 * sector_size..2 * sector_size + entries.len()].copy_from_slice(&entries);

    let mut backup_header = header.clone();
    backup_header[16..20].copy_from_slice(&[0; 4]);
    backup_header[24..32].copy_from_slice(&backup_lba.to_le_bytes());
    backup_header[32..40].copy_from_slice(&1u64.to_le_bytes());
    let backup_entries_lba = total_sectors - 33;
    backup_header[72..80].copy_from_slice(&backup_entries_lba.to_le_bytes());
    let backup_header_crc = crc32(&backup_header);
    backup_header[16..20].copy_from_slice(&backup_header_crc.to_le_bytes());

    let backup_header_offset = (backup_lba * sector_size as u64) as usize;
    buf[backup_header_offset..backup_header_offset + 92].copy_from_slice(&backup_header);

    let backup_entries_offset = (backup_entries_lba * sector_size as u64) as usize;
    buf[backup_entries_offset..backup_entries_offset + entries.len()].copy_from_slice(&entries);

    buf
}

fn make_gpt_missing_pmbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = make_clean_gpt(total_sectors, sector_size);
    buf[446..462].fill(0);
    buf
}

fn write_temp_image(name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(name);
    let mut file = File::create(&path).unwrap();
    file.write_all(data).unwrap();
    path
}

#[test]
fn test_clean_mbr_scan_passes() {
    let img = make_clean_mbr(10000, 512);
    let path = write_temp_image("ferrix_test_clean_mbr.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Pass);
    assert!(findings.is_empty());
}

#[test]
fn test_clean_gpt_scan_passes() {
    let img = make_clean_gpt(10000, 512);
    let path = write_temp_image("ferrix_test_clean_gpt.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Pass);
    assert!(findings.is_empty());
}

#[test]
fn test_overlapping_partitions_quarantines() {
    let img = make_overlapping_mbr(10000, 512);
    let path = write_temp_image("ferrix_test_overlap_mbr.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-001"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_out_of_bounds_partition_quarantines() {
    let img = make_out_of_bounds_mbr(10000, 512);
    let path = write_temp_image("ferrix_test_oob_mbr.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-002"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_gpt_missing_protective_mbr_quarantines() {
    let img = make_gpt_missing_pmbr(10000, 512);
    let path = write_temp_image("ferrix_test_gpt_no_pmbr.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-003"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_unallocated_data_finding() {
    let img = make_unallocated_data_mbr(10000, 512);
    let path = write_temp_image("ferrix_test_unalloc.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-005"));
}

#[test]
fn test_hidden_type_finding() {
    let img = make_hidden_type_mbr(10000, 512);
    let path = write_temp_image("ferrix_test_hidden.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-006"));
}

fn make_gpt_with_backup_mismatch(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = make_clean_gpt(total_sectors, sector_size);

    let backup_entries_lba = total_sectors - 33;
    let backup_entries_offset = (backup_entries_lba * sector_size as u64) as usize;

    let mut different_entries = vec![0u8; 128 * 128];
    let e1 = &mut different_entries[0..128];
    e1[0..16].copy_from_slice(&[
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ]);
    e1[16..32].copy_from_slice(&[2u8; 16]);
    let start_lba = 4096u64;
    let end_lba = total_sectors - 50;
    e1[32..40].copy_from_slice(&start_lba.to_le_bytes());
    e1[40..48].copy_from_slice(&end_lba.to_le_bytes());

    buf[backup_entries_offset..backup_entries_offset + different_entries.len()]
        .copy_from_slice(&different_entries);

    let different_entries_crc = crc32(&different_entries);
    let backup_header_offset = ((total_sectors - 1) * sector_size as u64) as usize;
    buf[backup_header_offset + 88..backup_header_offset + 92]
        .copy_from_slice(&different_entries_crc.to_le_bytes());

    let mut header_copy = buf[backup_header_offset..backup_header_offset + 92].to_vec();
    header_copy[16..20].fill(0);
    let new_header_crc = crc32(&header_copy);
    buf[backup_header_offset + 16..backup_header_offset + 20]
        .copy_from_slice(&new_header_crc.to_le_bytes());

    buf
}

fn make_pmbr_without_gpt(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];
    buf[510] = 0x55;
    buf[511] = 0xAA;
    let pmbr = &mut buf[446..462];
    pmbr[4] = 0xEE;
    pmbr[8..12].copy_from_slice(&1u32.to_le_bytes());
    pmbr[12..16].copy_from_slice(&1000u32.to_le_bytes());
    buf
}

fn make_unallocated_data_at_end_mbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let p1 = &mut buf[446..462];
    p1[0] = 0x80;
    p1[4] = 0x83;
    let start_lba = 2048u32;
    let sector_count = 2048u32;
    p1[8..12].copy_from_slice(&start_lba.to_le_bytes());
    p1[12..16].copy_from_slice(&sector_count.to_le_bytes());

    let secret_offset = (total_sectors - 100) as usize * sector_size;
    buf[secret_offset..secret_offset + 12].copy_from_slice(b"CONFIDENTIAL");
    buf
}

fn make_zero_sector_mbr(total_sectors: u64, sector_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_sectors as usize * sector_size];
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let p1 = &mut buf[446..462];
    p1[0] = 0x00;
    p1[4] = 0x83;
    let start_lba = 2048u32;
    let sector_count = 0u32;
    p1[8..12].copy_from_slice(&start_lba.to_le_bytes());
    p1[12..16].copy_from_slice(&sector_count.to_le_bytes());
    buf
}

#[test]
fn test_gpt_backup_mismatch_quarantines() {
    let img = make_gpt_with_backup_mismatch(10000, 512);
    let path = write_temp_image("ferrix_test_gpt_mismatch.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-004"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_protective_mbr_invalid_gpt_quarantines() {
    let img = make_pmbr_without_gpt(10000, 512);
    let path = write_temp_image("ferrix_test_pmbr_no_gpt.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-003"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_unallocated_data_at_end_of_disk() {
    let img = make_unallocated_data_at_end_mbr(10000, 512);
    let path = write_temp_image("ferrix_test_unalloc_end.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-005"));
}

#[test]
fn test_inverted_partition_range_quarantines() {
    let img = make_zero_sector_mbr(10000, 512);
    let path = write_temp_image("ferrix_test_zero_sector.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PartitionScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-PART-002"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}
