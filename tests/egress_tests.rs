use ferrix_usb::core::{Location, ScanContext, Severity, Stage};
use ferrix_usb::egress::{shannon_entropy, EgressScanStage};
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
    unallocated_gap_data: Option<&[u8]>,
    file_name: &str,
    file_ext: &str,
    file_data: &[u8],
) -> Vec<u8> {
    let total_sectors = 14000u64;
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

    if let Some(gap_data) = unallocated_gap_data {
        let gap_offset = ((part_start + part_sectors) * 512) as usize;
        if gap_offset + gap_data.len() <= buf.len() {
            buf[gap_offset..gap_offset + gap_data.len()].copy_from_slice(gap_data);
        }
    }

    buf
}

#[test]
fn test_clean_zeroed_media_passes_egress() {
    let img = make_fat32_image(None, "CLEAN", "TXT", b"Completely clean text file");
    let path = write_temp_file("ferrix_test_egress_clean.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = EgressScanStage::default().with_verify_wipe(true);

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.is_empty());
}

#[test]
fn test_deleted_pdf_remnant_in_unallocated_space_quarantines() {
    let remnant = b"%PDF-1.4\n1 0 obj\n<< /Title (Deleted Secret) >>\nendobj\n";
    let img = make_fat32_image(Some(remnant), "README", "TXT", b"Hello");
    let path = write_temp_file("ferrix_test_egress_pdf_remnant.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = EgressScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-EGR-001"
        && f.severity == Severity::High
        && f.evidence.contains("PDF Document")));
}

#[test]
fn test_dirty_unallocated_block_fails_wipe_verification() {
    let dirty_block = b"CONFIDENTIAL INTERNAL MEMO NOT FOR RELEASE ";
    let mut pattern = Vec::new();
    while pattern.len() < 4096 {
        pattern.extend_from_slice(dirty_block);
    }

    let img = make_fat32_image(Some(&pattern), "README", "TXT", b"Hello");
    let path = write_temp_file("ferrix_test_egress_dirty_wipe.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = EgressScanStage::default().with_verify_wipe(true);

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-EGR-002"
        && f.severity == Severity::High
        && f.reason.contains("unwiped")));
}

#[test]
fn test_random_wipe_passes_wipe_verification() {
    let gap_size = (14000 - (2048 + 8192)) as usize * 512;
    let mut random_gap = vec![0u8; gap_size];
    for (i, b) in random_gap.iter_mut().enumerate() {
        let hash = blake3::hash(&(i as u64).to_le_bytes());
        *b = hash.as_bytes()[0];
    }
    assert!(shannon_entropy(&random_gap) > 7.5);

    let img = make_fat32_image(Some(&random_gap), "README", "TXT", b"Hello");
    let path = write_temp_file("ferrix_test_egress_random_wipe.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = EgressScanStage::default().with_verify_wipe(true);

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(!findings.iter().any(|f| f.id == "FX-EGR-002"));
}

#[test]
fn test_jpeg_exif_metadata_detected() {
    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x10]);
    jpeg.extend_from_slice(b"Exif\x00\x00");
    jpeg.extend_from_slice(b"TIFFDATA");
    jpeg.extend_from_slice(&[0xFF, 0xD9]);

    let img = make_fat32_image(None, "PHOTO", "JPG", &jpeg);
    let path = write_temp_file("ferrix_test_egress_exif.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = EgressScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-EGR-003"
        && f.severity == Severity::Medium
        && matches!(f.location, Location::Path(_))
        && f.reason.contains("EXIF")));
}

#[test]
fn test_pdf_author_metadata_detected() {
    let pdf = b"%PDF-1.4\n/Author (Internal Auditor)\n/Producer (Acrobat 9)\n";
    let img = make_fat32_image(None, "REPORT", "PDF", pdf);
    let path = write_temp_file("ferrix_test_egress_pdf_meta.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = EgressScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-EGR-003"
        && f.severity == Severity::Medium
        && f.evidence.contains("Author")));
}

#[test]
fn test_office_metadata_detected() {
    let office = b"PK\x03\x04docProps/core.xml<dc:creator>CEO Office</dc:creator>";
    let img = make_fat32_image(None, "PLAN", "DOCX", office);
    let path = write_temp_file("ferrix_test_egress_office_meta.img", &img);
    let ctx = ScanContext::new(path.clone());
    let stage = EgressScanStage::default();

    let findings = stage.run(&ctx).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(findings.iter().any(|f| f.id == "FX-EGR-003"
        && f.severity == Severity::Medium
        && f.reason.contains("Office")));
}
