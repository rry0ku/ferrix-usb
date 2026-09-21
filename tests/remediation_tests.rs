use ferrix_usb::core::{MediaPath, ScanContext, Stage};
use ferrix_usb::disk::partition::parse_disk_layout;
use ferrix_usb::fs::extract_filesystem_files;
use ferrix_usb::manifest::{
    compute_layout_hash, generate_nonce, hash_discovered_files, load_station_signing_key,
    load_station_verifying_key, Manifest,
};
use ferrix_usb::scan::archives::inspect_zip_archive;
use ferrix_usb::scan::pdf::inspect_pdf_content;
use ferrix_usb::scan::FileScanStage;
use std::fs::File;
use std::io::{Cursor, Write};

fn write_temp_file(name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(name);
    let mut file = File::create(&path).unwrap();
    file.write_all(data).unwrap();
    path
}

#[test]
fn test_ebr_logical_partition_detection() {
    let total_sectors = 10000u64;
    let mut disk = vec![0u8; total_sectors as usize * 512];

    disk[510] = 0x55;
    disk[511] = 0xAA;

    let p1 = &mut disk[446..462];
    p1[0] = 0x00;
    p1[4] = 0x05;
    p1[8..12].copy_from_slice(&2048u32.to_le_bytes());
    p1[12..16].copy_from_slice(&4096u32.to_le_bytes());

    let ebr1_offset = 2048 * 512;
    disk[ebr1_offset + 510] = 0x55;
    disk[ebr1_offset + 511] = 0xAA;

    let ebr1_entry0 = &mut disk[ebr1_offset + 446..ebr1_offset + 462];
    ebr1_entry0[4] = 0x0B;
    ebr1_entry0[8..12].copy_from_slice(&1u32.to_le_bytes());
    ebr1_entry0[12..16].copy_from_slice(&1024u32.to_le_bytes());

    let ebr1_entry1 = &mut disk[ebr1_offset + 462..ebr1_offset + 478];
    ebr1_entry1[4] = 0x05;
    ebr1_entry1[8..12].copy_from_slice(&2048u32.to_le_bytes());
    ebr1_entry1[12..16].copy_from_slice(&1024u32.to_le_bytes());

    let ebr2_offset = 4096 * 512;
    disk[ebr2_offset + 510] = 0x55;
    disk[ebr2_offset + 511] = 0xAA;

    let ebr2_entry0 = &mut disk[ebr2_offset + 446..ebr2_offset + 462];
    ebr2_entry0[4] = 0x83;
    ebr2_entry0[8..12].copy_from_slice(&1u32.to_le_bytes());
    ebr2_entry0[12..16].copy_from_slice(&512u32.to_le_bytes());

    let mut cursor = Cursor::new(&disk);
    let layout = parse_disk_layout(&mut cursor, disk.len() as u64, 512).unwrap();

    assert!(layout
        .partitions
        .iter()
        .any(|p| p.index == 1 && p.type_byte == Some(0x05)));
    assert!(layout
        .partitions
        .iter()
        .any(|p| p.index == 5 && p.type_byte == Some(0x0B) && p.start_lba == 2049));
    assert!(layout
        .partitions
        .iter()
        .any(|p| p.index == 6 && p.type_byte == Some(0x83) && p.start_lba == 4097));
}

#[test]
fn test_fat_recursive_subdirectory_traversal() {
    let total_sectors = 12000u64;
    let part_start = 2048u64;
    let part_sectors = 8192u64;

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
    bpb[21] = 0xF8;
    bpb[32..36].copy_from_slice(&(part_sectors as u32).to_le_bytes());
    bpb[36..40].copy_from_slice(&32u32.to_le_bytes());
    bpb[44..48].copy_from_slice(&2u32.to_le_bytes());
    bpb[50..52].copy_from_slice(&6u16.to_le_bytes());
    bpb[510] = 0x55;
    bpb[511] = 0xAA;

    let backup_offset = fs_offset + 6 * 512;
    let primary_bpb = buf[fs_offset..fs_offset + 512].to_vec();
    buf[backup_offset..backup_offset + 512].copy_from_slice(&primary_bpb);

    let first_data_sector = 32 + (2 * 32);

    let fat_offset = fs_offset + 32 * 512;
    let set_fat_entry = |buf: &mut [u8], cluster: usize, val: u32| {
        let entry_pos = fat_offset + cluster * 4;
        buf[entry_pos..entry_pos + 4].copy_from_slice(&val.to_le_bytes());
    };
    set_fat_entry(&mut buf, 0, 0x0FFF_FFF8);
    set_fat_entry(&mut buf, 1, 0x0FFF_FFFF);
    set_fat_entry(&mut buf, 2, 0x0FFF_FFFF);
    set_fat_entry(&mut buf, 3, 0x0FFF_FFFF);
    set_fat_entry(&mut buf, 4, 0x0FFF_FFFF);

    let root_offset = fs_offset + first_data_sector * 512;
    let dir_entry = &mut buf[root_offset..root_offset + 32];
    dir_entry[0..8].copy_from_slice(b"DOCS    ");
    dir_entry[8..11].copy_from_slice(b"   ");
    dir_entry[11] = 0x10;
    dir_entry[20..22].copy_from_slice(&0u16.to_le_bytes());
    dir_entry[26..28].copy_from_slice(&3u16.to_le_bytes());
    dir_entry[28..32].copy_from_slice(&0u32.to_le_bytes());

    let subdir_offset = fs_offset + (first_data_sector + 8) * 512;
    let file_entry = &mut buf[subdir_offset..subdir_offset + 32];
    file_entry[0..8].copy_from_slice(b"PAYLOAD ");
    file_entry[8..11].copy_from_slice(b"JPG");
    file_entry[11] = 0x20;
    file_entry[20..22].copy_from_slice(&0u16.to_le_bytes());
    file_entry[26..28].copy_from_slice(&4u16.to_le_bytes());
    file_entry[28..32].copy_from_slice(&1024u32.to_le_bytes());

    let file_data_offset = fs_offset + (first_data_sector + (4 - 2) * 8) * 512;
    buf[file_data_offset] = 0x4D;
    buf[file_data_offset + 1] = 0x5A;
    buf[file_data_offset + 0x3c] = 0x80;
    buf[file_data_offset + 0x80..file_data_offset + 0x84].copy_from_slice(b"PE\0\0");

    let mut cursor = Cursor::new(&buf);
    let files = extract_filesystem_files(&mut cursor, buf.len() as u64, 512).unwrap();

    assert!(files
        .iter()
        .any(|f| f.path.to_string() == "DOCS/PAYLOAD.JPG"));

    let img_path = write_temp_file("ferrix_test_subdir_recursion.img", &buf);
    let ctx = ScanContext::new(img_path.clone());
    let stage = FileScanStage::default();
    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(img_path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-001"));
}

#[test]
fn test_pdf_flatedecode_decompression_detected() {
    let raw_stream = b"<< /JavaScript (app.alert('malicious_code')) >>";
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(raw_stream, 6);

    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<< /Length ");
    pdf.extend_from_slice(compressed.len().to_string().as_bytes());
    pdf.extend_from_slice(b" /Filter /FlateDecode >>\nstream\r\n");
    pdf.extend_from_slice(&compressed);
    pdf.extend_from_slice(b"\r\nendstream\nendobj\n%%EOF\n");

    let mut findings = Vec::new();
    inspect_pdf_content(&pdf, &MediaPath::from("test.pdf"), &mut findings);

    assert!(findings
        .iter()
        .any(|f| f.id == "FX-FILE-008" && f.evidence.contains("JavaScript")));
}

#[test]
fn test_zip_central_directory_and_symlink_detected() {
    let mut zip = Vec::new();

    let lh_offset = zip.len() as u32;
    zip.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    zip.extend_from_slice(&20u16.to_le_bytes());
    zip.extend_from_slice(&0x0008u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    let entry_name = b"symlink_entry";
    zip.extend_from_slice(&(entry_name.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(entry_name);

    let target = b"/etc/passwd";
    zip.extend_from_slice(target);

    zip.extend_from_slice(&[0x50, 0x4B, 0x07, 0x08]);
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&(target.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(target.len() as u32).to_le_bytes());

    let cd_offset = zip.len() as u32;
    zip.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
    zip.extend_from_slice(&((3u16 << 8) | 20u16).to_le_bytes());
    zip.extend_from_slice(&20u16.to_le_bytes());
    zip.extend_from_slice(&0x0008u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&(target.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(target.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(entry_name.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0xA1ED0000u32.to_le_bytes());
    zip.extend_from_slice(&lh_offset.to_le_bytes());
    zip.extend_from_slice(entry_name);

    let cd_size = (zip.len() as u32) - cd_offset;

    zip.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&1u16.to_le_bytes());
    zip.extend_from_slice(&1u16.to_le_bytes());
    zip.extend_from_slice(&cd_size.to_le_bytes());
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());

    let mut findings = Vec::new();
    inspect_zip_archive(&zip, &MediaPath::from("test.zip"), &mut findings);

    assert!(findings
        .iter()
        .any(|f| f.id == "FX-FILE-006" && f.reason.contains("symlink")));
}

#[test]
fn test_manifest_nonce_replay_protection() {
    let key_dir = std::env::temp_dir().join("ferrix_test_nonce_keys");
    let _ = std::fs::create_dir_all(&key_dir);
    let (key_path, pub_path) =
        ferrix_usb::manifest::generate_station_keypair(&key_dir, true).unwrap();
    let signing_key = load_station_signing_key(&key_path).unwrap();
    let verifying_key = load_station_verifying_key(&pub_path).unwrap();

    let media_data = vec![0u8; 1000 * 512];
    let media_path = write_temp_file("ferrix_test_nonce_media.img", &media_data);
    let (device_hash, device_size) =
        ferrix_usb::disk::snapshot::hash_device_or_image(&media_path).unwrap();

    let mut file = File::open(&media_path).unwrap();
    let layout =
        ferrix_usb::disk::partition::parse_disk_layout(&mut file, device_size, 512).unwrap();
    let layout_hash = compute_layout_hash(&layout);
    let discovered = extract_filesystem_files(&mut file, device_size, 512).unwrap();
    let files = hash_discovered_files(&mut file, &discovered).unwrap();

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut manifest = Manifest {
        version: "0.1.0".to_string(),
        station_id: "station-test".to_string(),
        nonce: generate_nonce(),
        issued_at: now_ts,
        expires_at: now_ts + 3600,
        device_identity: None,
        device_size_bytes: device_size,
        device_hash,
        partition_layout_hash: layout_hash,
        files,
        policy_hash: "policy-hash".to_string(),
        stages_required: vec!["file_scan".to_string()],
        stages_completed: vec![],
        verdict: ferrix_usb::core::Verdict::Pass,
        signature: None,
    };
    manifest.sign(&signing_key).unwrap();

    let nonce_log = std::env::temp_dir().join(format!("ferrix_nonce_log_{}.txt", generate_nonce()));

    let report1 = manifest
        .verify_against_media_with_nonce_log(&media_path, &verifying_key, Some(&nonce_log))
        .unwrap();
    assert!(report1.valid);

    let report2 = manifest
        .verify_against_media_with_nonce_log(&media_path, &verifying_key, Some(&nonce_log))
        .unwrap();
    assert!(!report2.valid);
    assert!(report2
        .mismatches
        .iter()
        .any(|m| m.component == "nonce_replay"));

    manifest.expires_at = 1000;
    manifest.sign(&signing_key).unwrap();
    let report3 = manifest
        .verify_against_media_with_nonce_log(&media_path, &verifying_key, None)
        .unwrap();
    assert!(!report3.valid);
    assert!(report3
        .mismatches
        .iter()
        .any(|m| m.component == "expiration"));

    let _ = std::fs::remove_file(media_path);
    let _ = std::fs::remove_file(nonce_log);
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(pub_path);
    let _ = std::fs::remove_dir_all(key_dir);
}
