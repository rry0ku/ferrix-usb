pub mod archives;
pub mod carve;
pub mod clamav;
pub mod documents;
pub mod filenames;
pub mod magic;
pub mod pdf;
pub mod yara;

pub use archives::*;
pub use carve::*;
pub use clamav::*;
pub use documents::*;
pub use filenames::*;
pub use magic::*;
pub use pdf::*;
pub use yara::*;

use crate::core::{Finding, ScanContext, Stage, StageError};
use crate::fs::extract_filesystem_files;
use crate::policy::Policy;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub struct FileScanStage {
    pub sector_size: u32,
    pub max_file_read_size: usize,
    pub policy: Policy,
}

impl Default for FileScanStage {
    fn default() -> Self {
        Self {
            sector_size: 512,
            max_file_read_size: 32 * 1024 * 1024,
            policy: Policy::strict_default(),
        }
    }
}

impl FileScanStage {
    pub fn new(sector_size: u32) -> Self {
        Self {
            sector_size,
            max_file_read_size: 32 * 1024 * 1024,
            policy: Policy::strict_default(),
        }
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
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

        let total_bytes = crate::disk::snapshot::get_device_or_file_size(&file, scan_path);

        let mut yara_rules = Vec::new();
        for rule_path_str in &self.policy.yara_rules {
            let p = Path::new(rule_path_str);
            if let Ok(rules) = load_yara_rules_from_path(p) {
                yara_rules.extend(rules);
            }
        }

        let clamav_scanner = if self.policy.clamav.enabled {
            Some(ClamAvScanner::new(self.policy.clamav.socket_path.clone()))
        } else {
            None
        };

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

            check_filename_anomalies_with_policy(
                &filename,
                &entry.path,
                &mut findings,
                &self.policy,
            );

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
            check_hidden_file_with_policy(
                &filename,
                is_hidden_attr,
                is_exec,
                &entry.path,
                &mut findings,
                &self.policy,
            );

            let is_known_good = if !self.policy.known_good_hashes.is_empty() && entry.size > 0 {
                if let Some(offset) = entry.data_offset {
                    if file.seek(SeekFrom::Start(offset)).is_ok() {
                        let mut hasher = blake3::Hasher::new();
                        let mut remaining = entry.size;
                        let mut chunk = vec![0u8; 64 * 1024];
                        let mut ok = true;
                        while remaining > 0 {
                            let to_read = (remaining as usize).min(chunk.len());
                            if file.read_exact(&mut chunk[..to_read]).is_ok() {
                                hasher.update(&chunk[..to_read]);
                                remaining -= to_read as u64;
                            } else {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            let hash_hex = hasher.finalize().to_hex().to_string();
                            self.policy
                                .known_good_hashes
                                .iter()
                                .any(|h| h.eq_ignore_ascii_case(&hash_hex))
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if has_content && !is_known_good {
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
                        "zip"
                            | "docx"
                            | "xlsx"
                            | "pptx"
                            | "jar"
                            | "apk"
                            | "tar"
                            | "gz"
                            | "tgz"
                            | "7z"
                    );
                let is_pdf_type = detected == magic::DetectedType::Pdf || ext == "pdf";
                let is_ole2_type = header_buf.starts_with(OLE2_MAGIC);

                let needs_full_buffer = is_archive_type
                    || is_pdf_type
                    || is_ole2_type
                    || !yara_rules.is_empty()
                    || clamav_scanner.is_some();

                if needs_full_buffer && entry.data_offset.is_some() {
                    let read_len = (entry.size as usize).min(self.max_file_read_size);
                    if let Some(offset) = entry.data_offset {
                        if file.seek(SeekFrom::Start(offset)).is_ok() {
                            let mut full_buf = vec![0u8; read_len];
                            if file.read_exact(&mut full_buf).is_ok() {
                                if !yara_rules.is_empty() {
                                    scan_data_with_yara(
                                        &full_buf,
                                        &yara_rules,
                                        &entry.path,
                                        &mut findings,
                                    );
                                }

                                if let Some(ref clam) = clamav_scanner {
                                    let _ = clam.inspect_and_record(
                                        &full_buf,
                                        &entry.path,
                                        &mut findings,
                                    );
                                }

                                if is_archive_type {
                                    inspect_zip_archive_with_policy(
                                        &full_buf,
                                        &entry.path,
                                        &mut findings,
                                        &self.policy,
                                    );
                                }

                                if is_pdf_type {
                                    inspect_pdf_content_with_policy(
                                        &full_buf,
                                        &entry.path,
                                        &mut findings,
                                        &self.policy,
                                    );
                                }

                                if is_ole2_type {
                                    inspect_ole2_compound_file(
                                        &full_buf,
                                        &entry.path,
                                        &mut findings,
                                        &self.policy,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        if self.policy.carve.enabled && total_bytes > 0 {
            ctx.event_sink.emit(crate::core::ScanEvent::Progress {
                stage_id: self.id().to_string(),
                current: total_files as u64,
                total: Some(total_files as u64),
                message: Some("carving files from unallocated and raw space".to_string()),
            });

            let sec = if self.sector_size == 0 {
                512
            } else {
                self.sector_size as u64
            };
            let layout_res =
                crate::disk::partition::parse_disk_layout(&mut file, total_bytes, self.sector_size);

            let unallocated_ranges: Vec<(u64, u64)> = match layout_res {
                Ok(ref layout) if !layout.partitions.is_empty() => {
                    let mut sorted = layout.partitions.clone();
                    sorted.sort_by_key(|p| p.start_lba);
                    let mut ranges = Vec::new();
                    let first_start_byte = sorted[0].start_lba.saturating_mul(sec);
                    let reserved_prefix = 2048 * sec;
                    if first_start_byte > reserved_prefix {
                        ranges.push((reserved_prefix, first_start_byte - reserved_prefix));
                    }
                    for i in 0..sorted.len().saturating_sub(1) {
                        let p1_end_byte = (sorted[i].end_lba.saturating_add(1)).saturating_mul(sec);
                        let p2_start_byte = sorted[i + 1].start_lba.saturating_mul(sec);
                        if p2_start_byte > p1_end_byte {
                            ranges.push((p1_end_byte, p2_start_byte - p1_end_byte));
                        }
                    }
                    let last_end_byte =
                        (sorted.last().unwrap().end_lba.saturating_add(1)).saturating_mul(sec);
                    if total_bytes > last_end_byte {
                        ranges.push((last_end_byte, total_bytes - last_end_byte));
                    }
                    ranges
                }
                _ => {
                    let mut sector0 = vec![0u8; 512];
                    let has_fs = if file.seek(SeekFrom::Start(0)).is_ok()
                        && file.read_exact(&mut sector0).is_ok()
                    {
                        crate::fs::fat::parse_fat_boot_sector(&sector0).is_ok()
                            || crate::fs::exfat::parse_exfat_boot_sector(&sector0).is_ok()
                            || crate::fs::ntfs::parse_ntfs_boot_sector(&sector0).is_ok()
                    } else {
                        false
                    };
                    if has_fs {
                        Vec::new()
                    } else {
                        vec![(0, total_bytes)]
                    }
                }
            };

            if !unallocated_ranges.is_empty() {
                let _ = carve_unallocated_space(
                    &mut file,
                    &unallocated_ranges,
                    self.policy.carve.max_carved_files,
                    self.sector_size,
                    &mut findings,
                );
            }
        }

        Ok(findings)
    }
}
