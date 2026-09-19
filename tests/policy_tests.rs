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
