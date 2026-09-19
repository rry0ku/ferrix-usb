pub mod archives;
pub mod filenames;
pub mod magic;
pub mod pdf;

pub use archives::*;
pub use filenames::*;
pub use magic::*;
pub use pdf::*;

use crate::core::{Finding, ScanContext, Stage, StageError};
use crate::fs::extract_filesystem_files;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub struct FileScanStage {
    pub sector_size: u32,
    pub max_file_read_size: usize,
}

impl Default for FileScanStage {
    fn default() -> Self {
        Self {
            sector_size: 512,
            max_file_read_size: 32 * 1024 * 1024,
        }
    }
}

impl FileScanStage {
    pub fn new(sector_size: u32) -> Self {
        Self {
            sector_size,
            max_file_read_size: 32 * 1024 * 1024,
        }
    }
}

impl Stage for FileScanStage {
    fn id(&self) -> &'static str {
        "file_scan"
    }

    fn name(&self) -> &'static str {
        "File Layer Content & Evasion Inspection"
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError> {
        let scan_path = ctx.snapshot_path.as_ref().unwrap_or(&ctx.target_path);
        let mut file = File::open(scan_path).map_err(|e| {
            StageError::Io(format!(
                "failed to open scan target {}: {e}",
                scan_path.display()
            ))
        })?;

        let mut total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
        if total_bytes == 0 {
            if let Ok(end_pos) = file.seek(SeekFrom::End(0)) {
                total_bytes = end_pos;
                let _ = file.seek(SeekFrom::Start(0));
            }
        }

        let discovered_files = extract_filesystem_files(&mut file, total_bytes, self.sector_size)?;
        let total_files = discovered_files.len();
        let mut findings = Vec::new();

        for (idx, entry) in discovered_files.iter().enumerate() {
            let filename = String::from_utf8_lossy(entry.path.as_bytes()).to_string();

            ctx.event_sink.emit(crate::core::ScanEvent::Progress {
                stage_id: self.id().to_string(),
                current: (idx + 1) as u64,
                total: Some(total_files as u64),
                message: Some(format!("scanning: {filename}")),
            });

            check_filename_anomalies(&filename, &entry.path, &mut findings);

            let mut header_buf = vec![0u8; 4096.min(entry.size as usize)];
            let has_content = if let Some(offset) = entry.data_offset {
                if entry.size > 0 && file.seek(SeekFrom::Start(offset)).is_ok() {
                    file.read_exact(&mut header_buf).is_ok()
                } else {
                    false
                }
            } else {
                false
            };

            let detected = if has_content {
                detect_content_type(&header_buf)
            } else {
                magic::DetectedType::Unknown
            };

            let is_exec = detected.risk_class() == magic::RiskClass::Executable;
            let is_hidden_attr = (entry.attributes & 0x02) != 0;
            check_hidden_file(
                &filename,
                is_hidden_attr,
                is_exec,
                &entry.path,
                &mut findings,
            );

            if has_content {
                check_extension_content_mismatch(
                    &filename,
                    &header_buf,
                    &entry.path,
                    &mut findings,
                );

                let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
                let is_archive_type = detected == magic::DetectedType::ZipOrOffice
                    || matches!(
                        ext.as_str(),
                        "zip" | "docx" | "xlsx" | "pptx" | "jar" | "apk"
                    );
                let is_pdf_type = detected == magic::DetectedType::Pdf || ext == "pdf";

                if (is_archive_type || is_pdf_type) && entry.data_offset.is_some() {
                    let read_len = (entry.size as usize).min(self.max_file_read_size);
                    if let Some(offset) = entry.data_offset {
                        if file.seek(SeekFrom::Start(offset)).is_ok() {
                            let mut full_buf = vec![0u8; read_len];
                            if file.read_exact(&mut full_buf).is_ok() {
                                if is_archive_type {
                                    inspect_zip_archive(&full_buf, &entry.path, &mut findings);
                                }
                                if is_pdf_type {
                                    inspect_pdf_content(&full_buf, &entry.path, &mut findings);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
