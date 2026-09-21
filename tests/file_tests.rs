use ferrix_usb::core::{resolve_verdict, ScanContext, Stage, StageResult, StageStatus, Verdict};
use ferrix_usb::scan::FileScanStage;
use std::fs::File;
use std::io::Write;

fn write_temp_image(name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(name);
    let mut file = File::create(&path).unwrap();
    file.write_all(data).unwrap();
    path
}

fn make_fat32_disk_with_file(
    base_name: &str,
    ext: &str,
    file_data: &[u8],
    is_hidden: bool,
) -> Vec<u8> {
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
    let root_cluster_offset = fs_offset + first_data_sector * 512;

    let entry = &mut buf[root_cluster_offset..root_cluster_offset + 32];
    let mut name_bytes = [b' '; 8];
    for (i, b) in base_name.bytes().take(8).enumerate() {
        name_bytes[i] = b.to_ascii_uppercase();
    }
    let mut ext_bytes = [b' '; 3];
    for (i, b) in ext.bytes().take(3).enumerate() {
        ext_bytes[i] = b.to_ascii_uppercase();
    }

    entry[0..8].copy_from_slice(&name_bytes);
    entry[8..11].copy_from_slice(&ext_bytes);
    entry[11] = if is_hidden { 0x22 } else { 0x20 };

    let file_cluster = 3u32;
    entry[20..22].copy_from_slice(&((file_cluster >> 16) as u16).to_le_bytes());
    entry[26..28].copy_from_slice(&(file_cluster as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&(file_data.len() as u32).to_le_bytes());

    let file_data_offset = fs_offset + (first_data_sector + (file_cluster - 2) as usize * 8) * 512;
    if file_data_offset + file_data.len() <= buf.len() {
        buf[file_data_offset..file_data_offset + file_data.len()].copy_from_slice(file_data);
    }

    buf
}

#[test]
fn test_clean_file_passes() {
    let img = make_fat32_disk_with_file("README", "TXT", b"Safe plain text content", false);
    let path = write_temp_image("ferrix_test_clean_file.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Pass);
}

#[test]
fn test_executable_disguised_as_jpg_quarantines() {
    let mut pe_data = vec![0u8; 1024];
    pe_data[0] = 0x4D;
    pe_data[1] = 0x5A;
    pe_data[0x3c] = 0x80;
    pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");

    let img = make_fat32_disk_with_file("PHOTO", "JPG", &pe_data, false);
    let path = write_temp_image("ferrix_test_fake_jpg.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-001"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_autorun_inf_quarantines() {
    let autorun_data = b"[autorun]\nopen=malware.exe\n";
    let img = make_fat32_disk_with_file("AUTORUN", "INF", autorun_data, false);
    let path = write_temp_image("ferrix_test_autorun.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-002"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_double_extension_quarantines() {
    let img = make_fat32_disk_with_file("DOC.PDF", "EXE", b"binary", false);
    let path = write_temp_image("ferrix_test_double_ext.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-004"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_zip_path_traversal_quarantines() {
    let mut zip_data = Vec::new();
    zip_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    zip_data.extend_from_slice(&[0u8; 14]);
    zip_data.extend_from_slice(&10u32.to_le_bytes());
    zip_data.extend_from_slice(&10u32.to_le_bytes());
    let evil_name = b"../../etc/passwd";
    zip_data.extend_from_slice(&(evil_name.len() as u16).to_le_bytes());
    zip_data.extend_from_slice(&0u16.to_le_bytes());
    zip_data.extend_from_slice(evil_name);
    zip_data.extend_from_slice(b"1234567890");

    let img = make_fat32_disk_with_file("BACKUP", "ZIP", &zip_data, false);
    let path = write_temp_image("ferrix_test_zip_traversal.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-006"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_pdf_javascript_quarantines() {
    let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /JavaScript (app.alert('evil')) >>\nendobj\n";
    let img = make_fat32_disk_with_file("MANUAL", "PDF", pdf_data, false);
    let path = write_temp_image("ferrix_test_pdf_js.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-008"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_office_macro_quarantines() {
    let mut docx_data = Vec::new();
    docx_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    docx_data.extend_from_slice(&[0u8; 14]);
    docx_data.extend_from_slice(&10u32.to_le_bytes());
    docx_data.extend_from_slice(&10u32.to_le_bytes());
    let macro_name = b"word/vbaProject.bin";
    docx_data.extend_from_slice(&(macro_name.len() as u16).to_le_bytes());
    docx_data.extend_from_slice(&0u16.to_le_bytes());
    docx_data.extend_from_slice(macro_name);
    docx_data.extend_from_slice(b"1234567890");

    let img = make_fat32_disk_with_file("REPORT", "DOC", &docx_data, false);
    let path = write_temp_image("ferrix_test_office_macro.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-007"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_hidden_executable_quarantines() {
    let mut pe_data = vec![0u8; 1024];
    pe_data[0] = 0x4D;
    pe_data[1] = 0x5A;
    pe_data[0x3c] = 0x80;
    pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");

    let img = make_fat32_disk_with_file("PAYLOAD", "EXE", &pe_data, true);
    let path = write_temp_image("ferrix_test_hidden_exe.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings
        .iter()
        .any(|f| f.id == "FX-FILE-003" && f.severity == ferrix_usb::core::Severity::High));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_zip_path_traversal_windows_drive_and_null_bytes() {
    let mut zip_data = Vec::new();
    zip_data.extend_from_slice(b"PK\x03\x04");
    zip_data.extend_from_slice(&20u16.to_le_bytes());
    zip_data.extend_from_slice(&0u16.to_le_bytes());
    zip_data.extend_from_slice(&0u16.to_le_bytes());
    zip_data.extend_from_slice(&0u16.to_le_bytes());
    zip_data.extend_from_slice(&0u16.to_le_bytes());
    zip_data.extend_from_slice(&0u32.to_le_bytes());
    zip_data.extend_from_slice(&10u32.to_le_bytes());
    zip_data.extend_from_slice(&10u32.to_le_bytes());
    let evil_name = b"C:\\Windows\\evil.exe";
    zip_data.extend_from_slice(&(evil_name.len() as u16).to_le_bytes());
    zip_data.extend_from_slice(&0u16.to_le_bytes());
    zip_data.extend_from_slice(evil_name);
    zip_data.extend_from_slice(b"1234567890");

    let img = make_fat32_disk_with_file("ESCAPE", "ZIP", &zip_data, false);
    let path = write_temp_image("ferrix_test_zip_win_drive.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-006"));
}

#[test]
fn test_carve_pe_signature_validation_rejects_false_positive_mz() {
    let mut fake_mz = vec![0u8; 1024];
    fake_mz[0] = b'M';
    fake_mz[1] = b'Z';
    fake_mz[2..10].copy_from_slice(b"NOT A PE");
    assert!(ferrix_usb::scan::carve::detect_carved_header(&fake_mz).is_none());

    let mut valid_pe = vec![0u8; 1024];
    valid_pe[0] = b'M';
    valid_pe[1] = b'Z';
    valid_pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    valid_pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    valid_pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    valid_pe[0x86..0x88].copy_from_slice(&3u16.to_le_bytes());
    let (ftype, _, is_exec) =
        ferrix_usb::scan::carve::detect_carved_header(&valid_pe).expect("should detect valid PE");
    assert_eq!(ftype, "Windows PE Executable");
    assert!(is_exec);
}

#[test]
fn test_carve_valid_file_types() {
    let mut png = vec![0u8; 512];
    png[0..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    png[12..16].copy_from_slice(b"IHDR");
    let (ftype, _, is_exec) =
        ferrix_usb::scan::carve::detect_carved_header(&png).expect("should detect PNG");
    assert_eq!(ftype, "PNG Image");
    assert!(!is_exec);

    let mut pdf = vec![0u8; 512];
    pdf[0..8].copy_from_slice(b"%PDF-1.7");
    pdf[500..505].copy_from_slice(b"%%EOF");
    let (ftype, _, is_exec) =
        ferrix_usb::scan::carve::detect_carved_header(&pdf).expect("should detect PDF");
    assert_eq!(ftype, "PDF Document");
    assert!(!is_exec);

    let mut jpeg = vec![0u8; 512];
    jpeg[0..4].copy_from_slice(b"\xFF\xD8\xFF\xE0");
    let (ftype, _, is_exec) =
        ferrix_usb::scan::carve::detect_carved_header(&jpeg).expect("should detect JPEG");
    assert_eq!(ftype, "JPEG Image");
    assert!(!is_exec);
}

#[test]
fn test_clean_mp3_passes_file_scan() {
    let mut mp3_data = vec![0u8; 512];
    mp3_data[0..3].copy_from_slice(b"ID3");
    mp3_data[3] = 3;
    mp3_data[4] = 0;
    mp3_data[5] = 0;
    mp3_data[6..10].copy_from_slice(&[0, 0, 0, 10]);

    let img = make_fat32_disk_with_file("TRACK", "MP3", &mp3_data, false);
    let path = write_temp_image("ferrix_test_clean_mp3.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Pass);
}

#[test]
fn test_clean_mp4_passes_file_scan() {
    let mut mp4_data = vec![0u8; 512];
    mp4_data[0..4].copy_from_slice(&24u32.to_be_bytes());
    mp4_data[4..8].copy_from_slice(b"ftyp");
    mp4_data[8..12].copy_from_slice(b"mp42");

    let img = make_fat32_disk_with_file("VIDEO", "MP4", &mp4_data, false);
    let path = write_temp_image("ferrix_test_clean_mp4.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Pass);
}

#[test]
fn test_executable_disguised_as_mp3_quarantines() {
    let mut pe_data = vec![0u8; 1024];
    pe_data[0] = 0x4D;
    pe_data[1] = 0x5A;
    pe_data[0x3c] = 0x80;
    pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");

    let img = make_fat32_disk_with_file("SONG", "MP3", &pe_data, false);
    let path = write_temp_image("ferrix_test_fake_mp3.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = FileScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-FILE-001"));

    let stage_result = StageResult {
        stage_id: stage.id().to_string(),
        status: StageStatus::Ok,
        findings: findings.clone(),
    };

    let verdict = resolve_verdict(&[stage.id()], &[stage_result], &findings);
    assert_eq!(verdict, Verdict::Quarantine);
}

#[test]
fn test_text_file_starting_with_mz_is_not_flagged_as_pe() {
    let data = b"MZ is not always a PE executable header in plain text files.";
    assert_eq!(
        ferrix_usb::scan::magic::detect_content_type(data),
        ferrix_usb::scan::magic::DetectedType::PlainText
    );
    let mut findings = Vec::new();
    ferrix_usb::scan::magic::check_extension_content_mismatch(
        "notes.txt",
        data,
        &ferrix_usb::core::MediaPath::from("notes.txt"),
        &mut findings,
    );
    assert!(findings.is_empty());
}

#[test]
fn test_markdown_file_starting_with_hashbang_is_not_flagged_as_script() {
    let data = b"#! Important Heading\nThis is notes, not a script.";
    assert_eq!(
        ferrix_usb::scan::magic::detect_content_type(data),
        ferrix_usb::scan::magic::DetectedType::PlainText
    );
    let mut findings = Vec::new();
    ferrix_usb::scan::magic::check_extension_content_mismatch(
        "heading.txt",
        data,
        &ferrix_usb::core::MediaPath::from("heading.txt"),
        &mut findings,
    );
    assert!(findings.is_empty());
}

#[test]
fn test_utf8_international_text_detected_as_plaintext() {
    let data = "Bonjour le monde, café et crème! \u{0928}\u{092e}\u{0938}\u{094d}\u{0924}\u{0947} \u{4e16}\u{754c}".as_bytes();
    assert_eq!(
        ferrix_usb::scan::magic::detect_content_type(data),
        ferrix_usb::scan::magic::DetectedType::PlainText
    );
}

#[test]
fn test_zip_with_code_macro_not_flagged_as_vba() {
    let mut zip = Vec::new();
    zip.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    zip.extend_from_slice(&[0u8; 14]);
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    let name = b"src/macros.rs";
    zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(name);

    let cd_offset = zip.len() as u32;
    zip.extend_from_slice(&[0x50, 0x4B, 0x02, 0x01]);
    zip.extend_from_slice(&[0u8; 16]);
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(name);
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
    ferrix_usb::scan::archives::inspect_zip_archive(
        &zip,
        &ferrix_usb::core::MediaPath::from("code.zip"),
        &mut findings,
    );
    assert!(!findings.iter().any(|f| f.id == "FX-FILE-007"));
}

#[test]
fn test_pdf_with_hyperlink_uri_is_info_severity() {
    let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /URI (https://example.com) >>\nendobj\n";
    let mut findings = Vec::new();
    ferrix_usb::scan::pdf::inspect_pdf_content(
        pdf_data,
        &ferrix_usb::core::MediaPath::from("doc.pdf"),
        &mut findings,
    );
    let uri_finding = findings.iter().find(|f| f.evidence.contains("/URI"));
    assert!(uri_finding.is_some());
    assert_eq!(
        uri_finding.unwrap().severity,
        ferrix_usb::core::Severity::Info
    );
}

#[test]
fn test_ooxml_web_hyperlink_is_info_severity() {
    let xml_data = br#"<Relationship TargetMode="External" Target="https://example.com/page"/>"#;
    let mut findings = Vec::new();
    ferrix_usb::scan::documents::inspect_ooxml_relationships(
        xml_data,
        &ferrix_usb::core::MediaPath::from("doc.docx"),
        &mut findings,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, ferrix_usb::core::Severity::Info);
}

#[test]
fn test_tar_internal_hard_link_not_flagged_as_symlink() {
    let mut tar = vec![0u8; 1536];
    let name = b"hardlink_target.txt";
    tar[0..name.len()].copy_from_slice(name);
    tar[156] = b'1';
    let target = b"original.txt";
    tar[157..157 + target.len()].copy_from_slice(target);
    tar[257..262].copy_from_slice(b"ustar");

    let mut findings = Vec::new();
    let ctx = ferrix_usb::core::ScanContext::new(std::path::PathBuf::from("dummy"));
    let stage = FileScanStage::default();
    let mut uncompressed = 0u64;
    ferrix_usb::scan::archives::inspect_archive_recursive(
        &tar,
        &ferrix_usb::core::MediaPath::from("archive.tar"),
        &mut findings,
        &stage.policy,
        0,
        &mut uncompressed,
    );
    let _ = ctx;
    assert!(!findings.iter().any(|f| f.id == "FX-FILE-006"));
}

#[test]
fn test_office_docx_not_flagged_as_extension_mismatch() {
    let zip_header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00";
    let mut findings = Vec::new();
    ferrix_usb::scan::magic::check_extension_content_mismatch(
        "report.docx",
        zip_header,
        &ferrix_usb::core::MediaPath::from("report.docx"),
        &mut findings,
    );
    assert!(findings.is_empty());
}

#[test]
fn test_svg_xml_text_not_flagged_as_extension_mismatch() {
    let svg_data = b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\"><circle cx=\"50\" cy=\"50\" r=\"40\"/></svg>";
    let mut findings = Vec::new();
    ferrix_usb::scan::magic::check_extension_content_mismatch(
        "icon.svg",
        svg_data,
        &ferrix_usb::core::MediaPath::from("icon.svg"),
        &mut findings,
    );
    assert!(findings.is_empty());
}

#[test]
fn test_zip_filename_with_double_dots_not_flagged_as_path_traversal() {
    assert!(!ferrix_usb::scan::archives::is_path_traversal_entry(
        "version..1.txt"
    ));
    assert!(!ferrix_usb::scan::archives::is_path_traversal_entry(
        "chapter...txt"
    ));
    assert!(!ferrix_usb::scan::archives::is_path_traversal_entry(
        "docs/notes..draft.md"
    ));
    assert!(ferrix_usb::scan::archives::is_path_traversal_entry(
        "../passwd"
    ));
    assert!(ferrix_usb::scan::archives::is_path_traversal_entry(
        "docs/../../etc/shadow"
    ));
}

#[test]
fn test_pdf_json_token_not_flagged_as_javascript() {
    let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /JSON (some-font-or-key) >>\nendobj\n";
    let mut findings = Vec::new();
    ferrix_usb::scan::pdf::inspect_pdf_content(
        pdf_data,
        &ferrix_usb::core::MediaPath::from("doc.pdf"),
        &mut findings,
    );
    assert!(!findings
        .iter()
        .any(|f| f.evidence.contains("JSON") || f.reason.contains("JavaScript")));
}

#[test]
fn test_elf_invalid_header_not_flagged_as_elf() {
    let invalid_elf = b"\x7FELF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert_ne!(
        ferrix_usb::scan::magic::detect_content_type(invalid_elf),
        ferrix_usb::scan::magic::DetectedType::Elf
    );
}

#[test]
fn test_double_extension_csv_exe_quarantines() {
    let mut findings = Vec::new();
    ferrix_usb::scan::filenames::check_filename_anomalies(
        "payroll.csv.exe",
        &ferrix_usb::core::MediaPath::from("payroll.csv.exe"),
        &mut findings,
    );
    assert!(findings
        .iter()
        .any(|f| f.id == "FX-FILE-004" && f.severity == ferrix_usb::core::Severity::High));
}
