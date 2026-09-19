use ed25519_dalek::Signer;
use ferrix_usb::audit::{append_audit_entry, verify_audit_chain};
use ferrix_usb::core::Verdict;
use ferrix_usb::disk::partition::parse_disk_layout;
use ferrix_usb::disk::snapshot::hash_device_or_image;
use ferrix_usb::fs::extract_filesystem_files;
use ferrix_usb::manifest::{
    compute_layout_hash, generate_nonce, generate_station_keypair, hash_discovered_files,
    load_station_signing_key, load_station_verifying_key, Manifest,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_temp_file(name: &str, data: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    let mut file = File::create(&path).unwrap();
    file.write_all(data).unwrap();
    path
}

fn make_fat32_image(file_name: &str, file_ext: &str, file_data: &[u8]) -> Vec<u8> {
    let total_sectors = 12000u64;
    let mut buf = vec![0u8; total_sectors as usize * 512];

    buf[510] = 0x55;
    buf[511] = 0xAA;

    let part_start = 2048u64;
    let part_sectors = 8192u64;
    let p = &mut buf[446..462];
    p[0] = 0x80;
    p[4] = 0x0C;
    p[8..12].copy_from_slice(&(part_start as u32).to_le_bytes());
    p[12..16].copy_from_slice(&(part_sectors as u32).to_le_bytes());

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

    if !file_name.is_empty() || !file_data.is_empty() {
        let first_data_sector = 32 + (2 * 32);
        let root_cluster_offset = fs_offset + first_data_sector * 512;

        let entry = &mut buf[root_cluster_offset..root_cluster_offset + 32];
        let mut name_bytes = [b' '; 8];
        for (j, b) in file_name.bytes().take(8).enumerate() {
            name_bytes[j] = b.to_ascii_uppercase();
        }
        let mut ext_bytes = [b' '; 3];
        for (j, b) in file_ext.bytes().take(3).enumerate() {
            ext_bytes[j] = b.to_ascii_uppercase();
        }

        entry[0..8].copy_from_slice(&name_bytes);
        entry[8..11].copy_from_slice(&ext_bytes);
        entry[11] = 0x20;

        let file_cluster = 3u32;
        entry[20..22].copy_from_slice(&((file_cluster >> 16) as u16).to_le_bytes());
        entry[26..28].copy_from_slice(&(file_cluster as u16).to_le_bytes());
        entry[28..32].copy_from_slice(&(file_data.len() as u32).to_le_bytes());

        let file_data_offset =
            fs_offset + (first_data_sector + (file_cluster - 2) as usize * 8) * 512;
        if file_data_offset + file_data.len() <= buf.len() {
            buf[file_data_offset..file_data_offset + file_data.len()].copy_from_slice(file_data);
        }
    }

    buf
}

#[test]
fn test_keygen_and_load_keys() {
    let temp_dir = std::env::temp_dir().join(format!("ferrix_keys_{}", generate_nonce()));
    let (key_path, pub_path) = generate_station_keypair(&temp_dir, false).unwrap();

    assert!(key_path.exists());
    assert!(pub_path.exists());

    let sk = load_station_signing_key(&key_path).unwrap();
    let pk = load_station_verifying_key(&pub_path).unwrap();

    let test_msg = b"hello ferrix station";
    let sig = sk.sign(test_msg);
    assert!(pk.verify_strict(test_msg, &sig).is_ok());

    assert!(generate_station_keypair(&temp_dir, false).is_err());
    assert!(generate_station_keypair(&temp_dir, true).is_ok());

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_manifest_signing_and_tamper_detection() {
    let temp_dir = std::env::temp_dir().join(format!("ferrix_keys_{}", generate_nonce()));
    let (key_path, pub_path) = generate_station_keypair(&temp_dir, false).unwrap();
    let sk = load_station_signing_key(&key_path).unwrap();
    let pk = load_station_verifying_key(&pub_path).unwrap();

    let mut manifest = Manifest {
        version: "0.1.0".to_string(),
        station_id: "station-alpha".to_string(),
        nonce: generate_nonce(),
        issued_at: 1000,
        expires_at: 2000,
        device_identity: None,
        device_size_bytes: 1024,
        device_hash: "abcd".to_string(),
        partition_layout_hash: "ef01".to_string(),
        files: Vec::new(),
        policy_hash: "1234".to_string(),
        stages_required: vec!["partition_scan".to_string()],
        stages_completed: Vec::new(),
        verdict: Verdict::Pass,
        signature: None,
    };

    manifest.sign(&sk).unwrap();
    assert!(manifest.signature.is_some());
    assert!(manifest.verify_signature(&pk).is_ok());

    manifest.device_hash = "tampered_hash".to_string();
    assert!(manifest.verify_signature(&pk).is_err());

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_manifest_verify_against_matching_media() {
    let img = make_fat32_image("DOC", "TXT", b"Legitimate document content");
    let img_path = write_temp_file("ferrix_test_matching_media.img", &img);

    let temp_dir = std::env::temp_dir().join(format!("ferrix_keys_{}", generate_nonce()));
    let (key_path, pub_path) = generate_station_keypair(&temp_dir, false).unwrap();
    let sk = load_station_signing_key(&key_path).unwrap();
    let pk = load_station_verifying_key(&pub_path).unwrap();

    let (device_hash, device_size_bytes) = hash_device_or_image(&img_path).unwrap();
    let mut f = File::open(&img_path).unwrap();
    let layout = parse_disk_layout(&mut f, device_size_bytes, 512).unwrap();
    let partition_layout_hash = compute_layout_hash(&layout);
    let discovered = extract_filesystem_files(&mut f, device_size_bytes, 512).unwrap();
    let files = hash_discovered_files(&mut f, &discovered).unwrap();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut manifest = Manifest {
        version: "0.1.0".to_string(),
        station_id: "station-test".to_string(),
        nonce: generate_nonce(),
        issued_at: now_ts,
        expires_at: now_ts + 86400,
        device_identity: None,
        device_size_bytes,
        device_hash,
        partition_layout_hash,
        files,
        policy_hash: "test_policy_hash".to_string(),
        stages_required: vec!["partition_scan".to_string(), "filesystem_scan".to_string()],
        stages_completed: Vec::new(),
        verdict: Verdict::Pass,
        signature: None,
    };

    manifest.sign(&sk).unwrap();

    let report = manifest.verify_against_media(&img_path, &pk).unwrap();
    assert!(report.valid);
    assert!(report.mismatches.is_empty());
    assert_eq!(report.manifest_station_id, "station-test");

    let _ = std::fs::remove_file(img_path);
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_manifest_verify_fails_on_tampered_media() {
    let img = make_fat32_image("DOC", "TXT", b"Legitimate document content");
    let img_path = write_temp_file("ferrix_test_tamper_media.img", &img);

    let temp_dir = std::env::temp_dir().join(format!("ferrix_keys_{}", generate_nonce()));
    let (key_path, pub_path) = generate_station_keypair(&temp_dir, false).unwrap();
    let sk = load_station_signing_key(&key_path).unwrap();
    let pk = load_station_verifying_key(&pub_path).unwrap();

    let (device_hash, device_size_bytes) = hash_device_or_image(&img_path).unwrap();
    let mut f = File::open(&img_path).unwrap();
    let layout = parse_disk_layout(&mut f, device_size_bytes, 512).unwrap();
    let partition_layout_hash = compute_layout_hash(&layout);
    let discovered = extract_filesystem_files(&mut f, device_size_bytes, 512).unwrap();
    let files = hash_discovered_files(&mut f, &discovered).unwrap();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut manifest = Manifest {
        version: "0.1.0".to_string(),
        station_id: "station-test".to_string(),
        nonce: generate_nonce(),
        issued_at: now_ts,
        expires_at: now_ts + 86400,
        device_identity: None,
        device_size_bytes,
        device_hash,
        partition_layout_hash,
        files,
        policy_hash: "test_policy_hash".to_string(),
        stages_required: vec!["partition_scan".to_string()],
        stages_completed: Vec::new(),
        verdict: Verdict::Pass,
        signature: None,
    };

    manifest.sign(&sk).unwrap();

    let mut tampered_img = img;
    tampered_img[1000] ^= 0xFF;
    let mut f_tampered = File::create(&img_path).unwrap();
    f_tampered.write_all(&tampered_img).unwrap();

    let report = manifest.verify_against_media(&img_path, &pk).unwrap();
    assert!(!report.valid);
    assert!(report
        .mismatches
        .iter()
        .any(|m| m.component == "device_hash"));

    let _ = std::fs::remove_file(img_path);
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_audit_chain_append_and_verify() {
    let log_path = std::env::temp_dir().join(format!("ferrix_audit_{}.jsonl", generate_nonce()));

    let entry1 = append_audit_entry(
        &log_path,
        "keygen",
        None,
        None,
        None,
        serde_json::json!({"action": "key_generated"}),
    )
    .unwrap();
    assert_eq!(entry1.index, 0);

    let entry2 = append_audit_entry(
        &log_path,
        "scan",
        Some("scan-123"),
        Some("hash-abc"),
        Some(Verdict::Pass),
        serde_json::json!({"findings": 0}),
    )
    .unwrap();
    assert_eq!(entry2.index, 1);
    assert_eq!(entry2.prev_entry_hash, entry1.entry_hash);

    let entry3 = append_audit_entry(
        &log_path,
        "verify",
        Some("scan-123"),
        Some("hash-abc"),
        Some(Verdict::Pass),
        serde_json::json!({"valid": true}),
    )
    .unwrap();
    assert_eq!(entry3.index, 2);
    assert_eq!(entry3.prev_entry_hash, entry2.entry_hash);

    assert!(verify_audit_chain(&log_path).unwrap());

    let content = std::fs::read_to_string(&log_path).unwrap();
    let tampered = content.replacen("scan-123", "scan-666", 1);
    std::fs::write(&log_path, tampered).unwrap();

    assert!(!verify_audit_chain(&log_path).unwrap());

    let _ = std::fs::remove_file(log_path);
}
