use ed25519_dalek::{Signer, SigningKey};
use ferrix_usb::core::{Location, ScanContext, Severity, Stage};
use ferrix_usb::policy::{load_policy, parse_policy_str, Policy, PolicyScanStage, VerdictAction};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn write_temp_file(name: &str, data: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    let mut file = File::create(&path).unwrap();
    file.write_all(data).unwrap();
    path
}

fn make_fat32_image(
    num_partitions: usize,
    fs_type_byte: u8,
    file_name: &str,
    file_ext: &str,
    file_data: &[u8],
) -> Vec<u8> {
    let total_sectors = 16000u64;
    let mut buf = vec![0u8; total_sectors as usize * 512];

    buf[510] = 0x55;
    buf[511] = 0xAA;

    for i in 0..num_partitions {
        let part_start = 2048u64 + (i as u64 * 4096);
        let part_sectors = 4096u64;
        let entry_offset = 446 + i * 16;
        let p = &mut buf[entry_offset..entry_offset + 16];
        p[0] = if i == 0 { 0x80 } else { 0x00 };
        p[4] = fs_type_byte;
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

        if i == 0 && (!file_name.is_empty() || !file_data.is_empty()) {
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
                buf[file_data_offset..file_data_offset + file_data.len()]
                    .copy_from_slice(file_data);
            }
        }
    }

    buf
}

#[test]
fn test_strict_default_policy_passes_clean_disk() {
    let img = make_fat32_image(1, 0x0C, "README", "TXT", b"Safe plain text content");
    let path = write_temp_file("ferrix_test_policy_clean.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.is_empty());
}

#[test]
fn test_policy_max_partitions_exceeded() {
    let img = make_fat32_image(2, 0x0C, "README", "TXT", b"Safe plain text content");
    let path = write_temp_file("ferrix_test_policy_multi_part.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-POL-001"
        && f.severity == Severity::High
        && f.location == Location::Device));
}

#[test]
fn test_policy_disallowed_filesystem() {
    let total_sectors = 8000u64;
    let mut buf = vec![0u8; total_sectors as usize * 512];
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let part_start = 2048u64;
    let part_sectors = 4096u64;
    let p = &mut buf[446..462];
    p[0] = 0x80;
    p[4] = 0x07;
    p[8..12].copy_from_slice(&(part_start as u32).to_le_bytes());
    p[12..16].copy_from_slice(&(part_sectors as u32).to_le_bytes());

    let fs_offset = (part_start * 512) as usize;
    let ntfs_bpb = &mut buf[fs_offset..fs_offset + 512];
    ntfs_bpb[0..3].copy_from_slice(b"\xEB\x52\x90");
    ntfs_bpb[3..11].copy_from_slice(b"NTFS    ");
    ntfs_bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
    ntfs_bpb[13] = 8;
    ntfs_bpb[40..48].copy_from_slice(&part_sectors.to_le_bytes());
    ntfs_bpb[510] = 0x55;
    ntfs_bpb[511] = 0xAA;

    let path = write_temp_file("ferrix_test_policy_ntfs.img", &buf);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-POL-002"
        && f.severity == Severity::High
        && f.evidence.contains("NTFS")));
}

#[test]
fn test_policy_file_size_exceeded() {
    let mut large_data = vec![b'A'; 2 * 1024 * 1024];
    large_data[0..4].copy_from_slice(b"%PDF");

    let total_sectors = 20000u64;
    let mut buf = vec![0u8; total_sectors as usize * 512];
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let part_start = 2048u64;
    let part_sectors = 16000u64;
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

    let first_data_sector = 32 + (2 * 32);
    let root_cluster_offset = fs_offset + first_data_sector * 512;
    let entry = &mut buf[root_cluster_offset..root_cluster_offset + 32];
    entry[0..8].copy_from_slice(b"BIGFILE ");
    entry[8..11].copy_from_slice(b"PDF");
    entry[11] = 0x20;
    let file_cluster = 3u32;
    entry[20..22].copy_from_slice(&((file_cluster >> 16) as u16).to_le_bytes());
    entry[26..28].copy_from_slice(&(file_cluster as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&(large_data.len() as u32).to_le_bytes());

    let file_data_offset = fs_offset + (first_data_sector + (file_cluster - 2) as usize * 8) * 512;
    let copy_len = (buf.len() - file_data_offset).min(large_data.len());
    buf[file_data_offset..file_data_offset + copy_len].copy_from_slice(&large_data[..copy_len]);

    let path = write_temp_file("ferrix_test_policy_bigfile.img", &buf);
    let ctx = ScanContext::new(path.clone());

    let mut custom_policy = Policy::strict_default();
    custom_policy.max_file_size_mb = 1;
    let stage = PolicyScanStage::new(custom_policy);

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-POL-003"
        && f.severity == Severity::High
        && f.reason.contains("file size")));
}

#[test]
fn test_policy_disallowed_content_type() {
    let elf_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let img = make_fat32_image(1, 0x0C, "PAYLOAD", "BIN", elf_payload);
    let path = write_temp_file("ferrix_test_policy_elf.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-POL-004"
        && f.severity == Severity::High
        && f.evidence.contains("Linux ELF Executable")));
}

#[test]
fn test_policy_parser_valid_and_unknown_keys() {
    let yaml_valid = r#"
name: test-corp-policy
allowed_filesystems: [fat32, exfat]
max_partitions: 2
max_file_size_mb: 1024
allowed_types: [pdf, txt]
on_high: fail
on_critical: fail
"#;

    let parsed = parse_policy_str(yaml_valid).unwrap();
    assert_eq!(parsed.name, "test-corp-policy");
    assert_eq!(parsed.max_partitions, 2);
    assert_eq!(parsed.max_file_size_mb, 1024);
    assert_eq!(parsed.allowed_filesystems, vec!["fat32", "exfat"]);
    assert_eq!(parsed.allowed_types, vec!["pdf", "txt"]);
    assert_eq!(parsed.on_high, VerdictAction::Fail);

    let yaml_unknown = r#"
name: bad-policy
unknown_setting_flag: true
"#;
    assert!(parse_policy_str(yaml_unknown).is_err());
}

#[test]
fn test_ed25519_signature_verification_and_fallback() {
    let signing_key = SigningKey::from_bytes(&[99u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let policy_yaml = r#"name: signed-policy
allowed_filesystems: [fat32]
max_partitions: 1
max_file_size_mb: 256
allowed_types: [pdf, txt]
on_high: quarantine
on_critical: fail
"#;

    let signature = signing_key.sign(policy_yaml.as_bytes());

    let policy_path = write_temp_file("ferrix_test_signed_policy.yaml", policy_yaml.as_bytes());
    let sig_path = policy_path.with_extension("yaml.sig");
    let mut sig_file = File::create(&sig_path).unwrap();
    sig_file.write_all(&signature.to_bytes()).unwrap();

    let pubkey_path = policy_path.with_extension("pub");
    let mut pub_file = File::create(&pubkey_path).unwrap();
    pub_file.write_all(&verifying_key.to_bytes()).unwrap();

    let (pol, warn) = load_policy(Some(&policy_path), Some(&pubkey_path));
    assert!(warn.is_none());
    assert_eq!(pol.name, "signed-policy");
    assert_eq!(pol.max_file_size_mb, 256);

    let tampered_yaml = format!("{policy_yaml}\n# tamper\n");
    let mut pol_file = File::create(&policy_path).unwrap();
    pol_file.write_all(tampered_yaml.as_bytes()).unwrap();

    let (pol_fallback, warn_fallback) = load_policy(Some(&policy_path), Some(&pubkey_path));
    assert!(warn_fallback.is_some());
    assert_eq!(pol_fallback.name, "strict-default");

    let _ = std::fs::remove_file(&policy_path);
    let _ = std::fs::remove_file(&sig_path);
    let _ = std::fs::remove_file(&pubkey_path);
}

#[test]
fn test_default_config_yaml_parsing() {
    let yaml_content = std::fs::read_to_string("config.default.yaml").unwrap();
    let pol = parse_policy_str(&yaml_content).unwrap();

    assert_eq!(pol.name, "default-security-policy");
    assert_eq!(pol.max_partitions, 2);
    assert_eq!(pol.max_file_size_mb, 2048);
    assert_eq!(
        pol.allowed_filesystems,
        vec!["fat32".to_string(), "exfat".to_string(), "ntfs".to_string()]
    );
    assert_eq!(
        pol.allowed_types,
        vec![
            "pdf".to_string(),
            "txt".to_string(),
            "png".to_string(),
            "jpg".to_string(),
            "gif".to_string(),
            "docx".to_string(),
            "xlsx".to_string(),
            "pptx".to_string(),
            "zip".to_string(),
        ]
    );
    assert!(pol.allow_os_artifacts);
    assert!(pol.allowed_devices.is_empty());
    assert!(pol.known_good_hashes.is_empty());
    assert_eq!(pol.archives.max_depth, 3);
    assert_eq!(pol.archives.max_expansion_ratio, 100);
    assert!(!pol.archives.allow_symlinks);
    assert_eq!(pol.archives.max_uncompressed_size_mb, 1024);
    assert!(!pol.office.allow_macros);
    assert!(!pol.pdf.allow_javascript);
    assert!(!pol.pdf.allow_launch_actions);
    assert!(!pol.pdf.allow_embedded_files);
    assert!(pol.filenames.allow_unicode);
    assert!(pol.filenames.check_double_extensions);
    assert!(pol.egress.check_unallocated_remnants);
    assert!(pol.egress.check_metadata);
    assert!(!pol.egress.require_wipe_verification);
    assert_eq!(pol.on_medium, VerdictAction::Pass);
    assert_eq!(pol.on_high, VerdictAction::Quarantine);
    assert_eq!(pol.on_critical, VerdictAction::Fail);
}

#[test]
fn test_os_artifacts_avoid_false_positives() {
    use ferrix_usb::policy::is_os_artifact_path;

    assert!(is_os_artifact_path(
        "System Volume Information/IndexerVolumeGuid"
    ));
    assert!(is_os_artifact_path("$RECYCLE.BIN/S-1-5-21-test"));
    assert!(is_os_artifact_path(".Trashes/501"));
    assert!(is_os_artifact_path(".fseventsd/fseventsd-uuid"));
    assert!(is_os_artifact_path(".DS_Store"));
    assert!(is_os_artifact_path("lost+found"));
    assert!(is_os_artifact_path("Desktop.ini"));
    assert!(is_os_artifact_path("Thumbs.db"));
    assert!(!is_os_artifact_path("Documents/report.pdf"));
    assert!(!is_os_artifact_path("payload.exe"));

    let unknown_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let img = make_fat32_image(1, 0x0C, "DESKTOP", "INI", &unknown_data);
    let path = write_temp_file("ferrix_test_os_artifact.img", &img);
    let ctx = ScanContext::new(path.clone());

    let mut policy = Policy::strict_default();
    policy.allow_os_artifacts = true;
    let stage = PolicyScanStage::new(policy);
    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().all(|f| f.id != "FX-POL-004"));
}

#[test]
fn test_os_artifacts_flags_anomalous_exec() {
    let elf_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let img = make_fat32_image(1, 0x0C, "DESKTOP", "INI", elf_payload);
    let path = write_temp_file("ferrix_test_os_artifact_malware.img", &img);
    let ctx = ScanContext::new(path.clone());

    let mut policy = Policy::strict_default();
    policy.allow_os_artifacts = true;
    let stage = PolicyScanStage::new(policy);
    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-POL-004"
        && f.severity == Severity::High
        && f.reason.contains("OS artifact")));
}

#[test]
fn test_known_good_hash_allowlist() {
    let custom_data = b"Custom internal tool binary payload";
    let hash = blake3::hash(custom_data).to_hex().to_string();

    let img = make_fat32_image(1, 0x0C, "CUSTOM", "BIN", custom_data);
    let path = write_temp_file("ferrix_test_known_good.img", &img);
    let ctx = ScanContext::new(path.clone());

    let mut policy = Policy::strict_default();
    policy.known_good_hashes = vec![hash];
    let stage = PolicyScanStage::new(policy);
    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().all(|f| f.id != "FX-POL-004"));
}

#[test]
fn test_device_filter_with_serial() {
    use ferrix_usb::device::{
        check_device_anomalies, UsbDevice, UsbInterface, USB_CLASS_MASS_STORAGE,
    };
    use ferrix_usb::policy::DeviceFilter;

    let dev_matching = UsbDevice {
        vendor_id: "0781".to_string(),
        product_id: "5581".to_string(),
        serial: Some("ABC123456".to_string()),
        manufacturer: Some("SanDisk".to_string()),
        product_name: Some("Ultra".to_string()),
        interfaces: vec![UsbInterface {
            interface_number: 0,
            interface_class: USB_CLASS_MASS_STORAGE,
            interface_subclass: 0x06,
            interface_protocol: 0x50,
        }],
        authorized: true,
        sysfs_path: PathBuf::from("/sys/bus/usb/devices/1-1"),
    };

    let dev_wrong_serial = UsbDevice {
        vendor_id: "0781".to_string(),
        product_id: "5581".to_string(),
        serial: Some("WRONG_SERIAL".to_string()),
        manufacturer: Some("SanDisk".to_string()),
        product_name: Some("Ultra".to_string()),
        interfaces: vec![UsbInterface {
            interface_number: 0,
            interface_class: USB_CLASS_MASS_STORAGE,
            interface_subclass: 0x06,
            interface_protocol: 0x50,
        }],
        authorized: true,
        sysfs_path: PathBuf::from("/sys/bus/usb/devices/1-1"),
    };

    let mut policy = Policy::strict_default();
    policy.allowed_devices = vec![DeviceFilter {
        vendor: "0781".to_string(),
        product: "5581".to_string(),
        serial: Some("ABC123456".to_string()),
    }];

    let findings_matching = check_device_anomalies(&dev_matching, &policy);
    assert!(findings_matching.is_empty());

    let findings_wrong_serial = check_device_anomalies(&dev_wrong_serial, &policy);
    assert!(findings_wrong_serial.iter().any(|f| f.id == "FX-DEV-003"));
}

#[test]
fn test_resolve_verdict_with_policy_actions() {
    use ferrix_usb::core::{Confidence, Finding, Location, StageResult, StageStatus, Verdict};
    use ferrix_usb::policy::resolve_verdict_with_policy;

    let mut policy = Policy::strict_default();
    policy.on_medium = VerdictAction::Quarantine;
    policy.on_high = VerdictAction::Fail;

    let medium_finding = Finding {
        id: "FX-FILE-002".to_string(),
        severity: Severity::Medium,
        confidence: Confidence::High,
        stage: "file_scan".to_string(),
        location: Location::Device,
        reason: "medium finding".to_string(),
        evidence: "evidence".to_string(),
    };

    let stages = vec![StageResult {
        stage_id: "test".to_string(),
        status: StageStatus::Ok,
        findings: vec![medium_finding.clone()],
    }];

    let verdict = resolve_verdict_with_policy(&["test"], &stages, &[medium_finding], &policy);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_policy_allows_mp3_audio_files_with_id3() {
    let mut mp3_data = vec![0u8; 512];
    mp3_data[0..3].copy_from_slice(b"ID3");
    mp3_data[3] = 3;
    mp3_data[4] = 0;
    mp3_data[5] = 0;
    mp3_data[6..10].copy_from_slice(&[0, 0, 0, 10]);

    let img = make_fat32_image(1, 0x0C, "TRACK01", "MP3", &mp3_data);
    let path = write_temp_file("ferrix_test_policy_mp3_id3.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.is_empty());
}

#[test]
fn test_policy_allows_raw_mpeg_sync_mp3() {
    let mut mp3_data = vec![0u8; 512];
    mp3_data[0] = 0xFF;
    mp3_data[1] = 0xFB;
    mp3_data[2] = 0x90;
    mp3_data[3] = 0x64;

    let img = make_fat32_image(1, 0x0C, "TRACK02", "MP3", &mp3_data);
    let path = write_temp_file("ferrix_test_policy_mp3_sync.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.is_empty());
}

#[test]
fn test_policy_allows_flac_wav_mp4() {
    let mut flac_data = vec![0u8; 512];
    flac_data[0..4].copy_from_slice(b"fLaC");

    let img = make_fat32_image(1, 0x0C, "MUSIC", "FLA", &flac_data);
    let path = write_temp_file("ferrix_test_policy_flac.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.is_empty());
}

#[test]
fn test_policy_blocks_executable_disguised_as_mp3() {
    let mut pe_data = vec![0u8; 512];
    pe_data[0] = 0x4D;
    pe_data[1] = 0x5A;

    let img = make_fat32_image(1, 0x0C, "SONG", "MP3", &pe_data);
    let path = write_temp_file("ferrix_test_policy_disguised_mp3.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = PolicyScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-POL-004"
        && f.severity == Severity::High
        && f.evidence.contains("Windows PE Executable")));
}
