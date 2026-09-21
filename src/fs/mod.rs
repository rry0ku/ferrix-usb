pub mod anomalies;
pub mod exfat;
pub mod ext;
pub mod fat;
pub mod ntfs;

pub use anomalies::*;
pub use exfat::*;
pub use ext::*;
pub use fat::*;
pub use ntfs::*;

use crate::core::{Finding, MediaPath, ScanContext, Stage, StageError};
use crate::disk::partition::parse_disk_layout;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredFile {
    pub path: MediaPath,
    pub size: u64,
    pub is_dir: bool,
    pub attributes: u8,
    pub partition_index: u32,
    pub data_offset: Option<u64>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub starting_cluster: Option<u32>,
    pub cluster_size: Option<u32>,
    pub fs_type: Option<String>,
    pub detected_type: Option<String>,
}

impl Default for DiscoveredFile {
    fn default() -> Self {
        Self {
            path: MediaPath::from(""),
            size: 0,
            is_dir: false,
            attributes: 0,
            partition_index: 0,
            data_offset: None,
            created: None,
            modified: None,
            accessed: None,
            starting_cluster: None,
            cluster_size: None,
            fs_type: None,
            detected_type: None,
        }
    }
}

pub struct FilesystemScanStage {
    pub sector_size: u32,
}

impl Default for FilesystemScanStage {
    fn default() -> Self {
        Self { sector_size: 512 }
    }
}

impl FilesystemScanStage {
    pub fn new(sector_size: u32) -> Self {
        Self { sector_size }
    }
}

impl Stage for FilesystemScanStage {
    fn id(&self) -> &'static str {
        "filesystem_scan"
    }

    fn name(&self) -> &'static str {
        "Filesystem Structure & Integrity Inspection"
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError> {
        let scan_path = ctx.snapshot_path.as_ref().unwrap_or(&ctx.target_path);
        let mut file = crate::disk::snapshot::open_device_or_file_with_retry(
            scan_path,
            std::time::Duration::from_secs(3),
        )
        .map_err(|e| {
            StageError::Io(format!(
                "failed to open scan target {}: {e}",
                scan_path.display()
            ))
        })?;

        let total_bytes = crate::disk::snapshot::get_device_or_file_size(&file, scan_path);

        let layout = parse_disk_layout(&mut file, total_bytes, self.sector_size)?;
        let mut findings = Vec::new();

        let partition_targets: Vec<(u32, u64, u64)> = if layout.partitions.is_empty() {
            vec![(0, 0, total_bytes / self.sector_size as u64)]
        } else {
            layout
                .partitions
                .iter()
                .map(|p| (p.index, p.start_lba, p.total_sectors))
                .collect()
        };

        let total_parts = partition_targets.len();
        for (i, (part_index, start_lba, total_sectors)) in partition_targets.into_iter().enumerate()
        {
            ctx.event_sink.emit(crate::core::ScanEvent::Progress {
                stage_id: self.id().to_string(),
                current: (i + 1) as u64,
                total: Some(total_parts as u64),
                message: Some(format!(
                    "Inspecting filesystem on partition {part_index}..."
                )),
            });

            let part_offset = start_lba.saturating_mul(self.sector_size as u64);

            if file.seek(SeekFrom::Start(part_offset)).is_err() {
                continue;
            }

            let sec = if self.sector_size == 0 {
                512
            } else {
                self.sector_size as usize
            };
            let mut sector0 = vec![0u8; sec];
            if file.read_exact(&mut sector0).is_err() {
                continue;
            }

            let mut detected_fs = Vec::new();

            let fat_res = parse_fat_boot_sector(&sector0);
            let exfat_res = parse_exfat_boot_sector(&sector0);
            let ntfs_res = parse_ntfs_boot_sector(&sector0);

            let ext_res = {
                let ext_offset = part_offset.saturating_add(1024);
                if file.seek(SeekFrom::Start(ext_offset)).is_ok() {
                    let mut ext_buf = vec![0u8; 1024];
                    if file.read_exact(&mut ext_buf).is_ok() {
                        parse_ext_superblock(&ext_buf).ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if fat_res.is_ok() {
                detected_fs.push("FAT");
            }
            if exfat_res.is_ok() {
                detected_fs.push("exFAT");
            }
            if ntfs_res.is_ok() {
                detected_fs.push("NTFS");
                check_unsupported_filesystem(part_index, "NTFS", &mut findings);
            }
            if ext_res.is_some() {
                detected_fs.push("ext4");
                check_unsupported_filesystem(part_index, "ext4", &mut findings);
            }

            check_polyglot_signatures(part_index, &detected_fs, &mut findings);

            if let Ok(fat) = fat_res {
                check_fs_size_mismatch(
                    part_index,
                    "FAT",
                    fat.total_sectors,
                    total_sectors,
                    &mut findings,
                );

                if fat.sectors_per_cluster == 0
                    || (fat.sectors_per_cluster & (fat.sectors_per_cluster - 1)) != 0
                {
                    check_boot_sector_inconsistency(
                        part_index,
                        "FAT",
                        &format!("invalid sectors_per_cluster: {}", fat.sectors_per_cluster),
                        &mut findings,
                    );
                }

                if fat.reserved_sectors == 0 {
                    check_boot_sector_inconsistency(
                        part_index,
                        "FAT",
                        "reserved sectors cannot be zero",
                        &mut findings,
                    );
                }

                if let Ok(backup_matches) =
                    check_fat_backup_boot_sector(&mut file, part_offset, &fat)
                {
                    if !backup_matches {
                        check_backup_boot_sector_mismatch(part_index, "FAT", &mut findings);
                    }
                }

                let dir_data = match fat.fat_type {
                    FatType::Fat32 => {
                        let root_cluster = fat.root_cluster;
                        if root_cluster >= 2 {
                            let first_data_sector = fat.reserved_sectors as u64
                                + (fat.num_fats as u64 * fat.sectors_per_fat as u64);
                            let chain = read_cluster_chain(
                                &mut file,
                                part_offset,
                                &fat,
                                root_cluster,
                                1024,
                            )
                            .unwrap_or_default();
                            read_chain_data(
                                &mut file,
                                part_offset,
                                &fat,
                                first_data_sector,
                                &chain,
                                1024 * 1024 * 4,
                            )
                            .ok()
                        } else {
                            None
                        }
                    }
                    FatType::Fat12 | FatType::Fat16 => {
                        let root_dir_offset = part_offset.saturating_add(
                            (fat.reserved_sectors as u64
                                + (fat.num_fats as u64 * fat.sectors_per_fat as u64))
                                * fat.bytes_per_sector as u64,
                        );
                        let root_dir_bytes = fat.root_entries as usize * 32;
                        if root_dir_bytes > 0 && file.seek(SeekFrom::Start(root_dir_offset)).is_ok()
                        {
                            let mut buf = vec![0u8; root_dir_bytes];
                            if file.read_exact(&mut buf).is_ok() {
                                Some(buf)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                };

                if let Some(data) = dir_data {
                    if let Ok((_entries, duplicates)) = parse_fat_directory(&data) {
                        check_duplicate_entries(part_index, &duplicates, &mut findings);
                    }
                }
            }

            if let Ok(exfat) = exfat_res {
                check_fs_size_mismatch(
                    part_index,
                    "exFAT",
                    exfat.volume_length_sectors,
                    total_sectors,
                    &mut findings,
                );

                if let Ok(backup_matches) =
                    check_exfat_backup_boot_sector(&mut file, part_offset, &exfat)
                {
                    if !backup_matches {
                        check_backup_boot_sector_mismatch(part_index, "exFAT", &mut findings);
                    }
                }
            }

            if let Ok(ntfs) = ntfs_res {
                check_fs_size_mismatch(
                    part_index,
                    "NTFS",
                    ntfs.total_sectors,
                    total_sectors,
                    &mut findings,
                );

                if let Ok(backup_matches) =
                    check_ntfs_backup_boot_sector(&mut file, part_offset, total_sectors, &ntfs)
                {
                    if !backup_matches {
                        check_backup_boot_sector_mismatch(part_index, "NTFS", &mut findings);
                    }
                }
            }

            if let Some(ext) = ext_res {
                let ext_sectors = ext.total_bytes / self.sector_size as u64;
                check_fs_size_mismatch(
                    part_index,
                    "ext4",
                    ext_sectors,
                    total_sectors,
                    &mut findings,
                );
            }
        }

        Ok(findings)
    }
}

pub fn extract_filesystem_files<R: Read + Seek>(
    file: &mut R,
    total_bytes: u64,
    sector_size: u32,
) -> Result<Vec<DiscoveredFile>, StageError> {
    extract_filesystem_files_with_cancel(file, total_bytes, sector_size, None)
}

pub fn extract_filesystem_files_with_cancel<R: Read + Seek>(
    file: &mut R,
    total_bytes: u64,
    sector_size: u32,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Vec<DiscoveredFile>, StageError> {
    let layout = parse_disk_layout(file, total_bytes, sector_size)?;
    let mut discovered = Vec::new();

    let partition_targets: Vec<(u32, u64, u64)> = if layout.partitions.is_empty() {
        vec![(0, 0, total_bytes / sector_size as u64)]
    } else {
        layout
            .partitions
            .iter()
            .map(|p| (p.index, p.start_lba, p.total_sectors))
            .collect()
    };

    for (part_index, start_lba, _total_sectors) in partition_targets {
        if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
            return Err(StageError::Io("Operation cancelled".to_string()));
        }
        let part_offset = start_lba.saturating_mul(sector_size as u64);
        if file.seek(SeekFrom::Start(part_offset)).is_err() {
            continue;
        }

        let sec = if sector_size == 0 {
            512
        } else {
            sector_size as usize
        };
        let mut sector0 = vec![0u8; sec];
        if file.read_exact(&mut sector0).is_err() {
            continue;
        }

        if let Ok(fat) = parse_fat_boot_sector(&sector0) {
            let (root_dir_data, first_data_sector) = match fat.fat_type {
                FatType::Fat32 => {
                    let root_cluster = fat.root_cluster;
                    let fds = fat.reserved_sectors as u64
                        + (fat.num_fats as u64 * fat.sectors_per_fat as u64);
                    if root_cluster >= 2 {
                        let chain = read_cluster_chain(file, part_offset, &fat, root_cluster, 1024)
                            .unwrap_or_default();
                        let data =
                            read_chain_data(file, part_offset, &fat, fds, &chain, 1024 * 1024 * 4)
                                .ok();
                        (data, fds)
                    } else {
                        (None, fds)
                    }
                }
                FatType::Fat12 | FatType::Fat16 => {
                    let root_dir_sectors = ((fat.root_entries as u32 * 32)
                        .saturating_add(fat.bytes_per_sector as u32)
                        .saturating_sub(1))
                        / fat.bytes_per_sector as u32;
                    let fds = fat.reserved_sectors as u64
                        + (fat.num_fats as u64 * fat.sectors_per_fat as u64)
                        + root_dir_sectors as u64;
                    let root_dir_offset = part_offset.saturating_add(
                        (fat.reserved_sectors as u64
                            + (fat.num_fats as u64 * fat.sectors_per_fat as u64))
                            * fat.bytes_per_sector as u64,
                    );
                    let root_dir_bytes = fat.root_entries as usize * 32;
                    let data = if root_dir_bytes > 0
                        && file.seek(SeekFrom::Start(root_dir_offset)).is_ok()
                    {
                        let mut buf = vec![0u8; root_dir_bytes];
                        if file.read_exact(&mut buf).is_ok() {
                            Some(buf)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    (data, fds)
                }
            };

            let fs_type_str = match fat.fat_type {
                FatType::Fat32 => "FAT32",
                FatType::Fat16 => "FAT16",
                FatType::Fat12 => "FAT12",
            };
            let cluster_size =
                (fat.bytes_per_sector as u32).saturating_mul(fat.sectors_per_cluster as u32);

            let mut dir_queue: Vec<(String, u32, usize)> = Vec::new();

            if let Some(data) = root_dir_data {
                if let Ok((entries, _)) = parse_fat_directory(&data) {
                    for entry in entries {
                        if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
                            return Err(StageError::Io("Operation cancelled".to_string()));
                        }
                        let data_offset = if entry.cluster >= 2 {
                            Some(cluster_to_byte_offset(
                                part_offset,
                                &fat,
                                first_data_sector,
                                entry.cluster,
                            ))
                        } else {
                            None
                        };

                        let detected_type = if !entry.is_dir && entry.size > 0 {
                            if let Some(off) = data_offset {
                                if file.seek(SeekFrom::Start(off)).is_ok() {
                                    let mut hdr = vec![0u8; 512.min(entry.size as usize)];
                                    if file.read_exact(&mut hdr).is_ok() {
                                        let dt = crate::scan::detect_content_type(&hdr);
                                        if dt != crate::scan::magic::DetectedType::Unknown {
                                            Some(dt.name().to_string())
                                        } else {
                                            Some("Binary Data / Unknown".to_string())
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else if entry.is_dir {
                            Some("Directory".to_string())
                        } else {
                            Some("Empty File".to_string())
                        };

                        discovered.push(DiscoveredFile {
                            path: MediaPath::from(entry.name.as_bytes()),
                            size: entry.size,
                            is_dir: entry.is_dir,
                            attributes: entry.attributes,
                            partition_index: part_index,
                            data_offset,
                            created: entry.created,
                            modified: entry.modified,
                            accessed: entry.accessed,
                            starting_cluster: if entry.cluster >= 2 {
                                Some(entry.cluster)
                            } else {
                                None
                            },
                            cluster_size: Some(cluster_size),
                            fs_type: Some(fs_type_str.to_string()),
                            detected_type,
                        });

                        if entry.is_dir && entry.cluster >= 2 {
                            dir_queue.push((entry.name, entry.cluster, 1));
                        }
                    }
                }
            }

            let mut visited_clusters = HashSet::new();
            if fat.fat_type == FatType::Fat32 && fat.root_cluster >= 2 {
                visited_clusters.insert(fat.root_cluster);
            }

            while let Some((dir_path, dir_cluster, depth)) = dir_queue.pop() {
                if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
                    return Err(StageError::Io("Operation cancelled".to_string()));
                }
                if depth > 16 || !visited_clusters.insert(dir_cluster) {
                    continue;
                }

                let chain = match read_cluster_chain(file, part_offset, &fat, dir_cluster, 1024) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let data = match read_chain_data(
                    file,
                    part_offset,
                    &fat,
                    first_data_sector,
                    &chain,
                    1024 * 1024 * 4,
                ) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                if let Ok((entries, _)) = parse_fat_directory(&data) {
                    for entry in entries {
                        if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
                            return Err(StageError::Io("Operation cancelled".to_string()));
                        }
                        let child_path = format!("{dir_path}/{}", entry.name);
                        let data_offset = if entry.cluster >= 2 {
                            Some(cluster_to_byte_offset(
                                part_offset,
                                &fat,
                                first_data_sector,
                                entry.cluster,
                            ))
                        } else {
                            None
                        };

                        let detected_type = if !entry.is_dir && entry.size > 0 {
                            if let Some(off) = data_offset {
                                if file.seek(SeekFrom::Start(off)).is_ok() {
                                    let mut hdr = vec![0u8; 512.min(entry.size as usize)];
                                    if file.read_exact(&mut hdr).is_ok() {
                                        let dt = crate::scan::detect_content_type(&hdr);
                                        if dt != crate::scan::magic::DetectedType::Unknown {
                                            Some(dt.name().to_string())
                                        } else {
                                            Some("Binary Data / Unknown".to_string())
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else if entry.is_dir {
                            Some("Directory".to_string())
                        } else {
                            Some("Empty File".to_string())
                        };

                        discovered.push(DiscoveredFile {
                            path: MediaPath::from(child_path.as_bytes()),
                            size: entry.size,
                            is_dir: entry.is_dir,
                            attributes: entry.attributes,
                            partition_index: part_index,
                            data_offset,
                            created: entry.created,
                            modified: entry.modified,
                            accessed: entry.accessed,
                            starting_cluster: if entry.cluster >= 2 {
                                Some(entry.cluster)
                            } else {
                                None
                            },
                            cluster_size: Some(cluster_size),
                            fs_type: Some(fs_type_str.to_string()),
                            detected_type,
                        });

                        if entry.is_dir && entry.cluster >= 2 && depth < 16 {
                            dir_queue.push((child_path, entry.cluster, depth + 1));
                        }
                    }
                }
            }
        } else if let Ok(exfat) = parse_exfat_boot_sector(&sector0) {
            let root_cluster = exfat.root_dir_first_cluster;
            if root_cluster >= 2 {
                let cluster_size = (exfat.bytes_per_sector as usize)
                    .saturating_mul(exfat.sectors_per_cluster as usize);
                let chain = read_exfat_cluster_chain(file, part_offset, &exfat, root_cluster, 1024)
                    .unwrap_or_else(|_| vec![root_cluster]);
                let mut dir_data = Vec::new();
                for c in chain {
                    if let Some(c_offset) = exfat_cluster_to_offset(part_offset, &exfat, c) {
                        if file.seek(SeekFrom::Start(c_offset)).is_ok() {
                            let mut buf = vec![0u8; cluster_size];
                            if file.read_exact(&mut buf).is_ok() {
                                dir_data.extend_from_slice(&buf);
                            }
                        }
                    }
                }
                for entry in parse_exfat_directory(&dir_data) {
                    if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
                        return Err(StageError::Io("Operation cancelled".to_string()));
                    }
                    let data_offset = exfat_cluster_to_offset(part_offset, &exfat, entry.cluster);
                    let detected_type = if !entry.is_dir && entry.size > 0 {
                        if let Some(off) = data_offset {
                            if file.seek(SeekFrom::Start(off)).is_ok() {
                                let mut hdr = vec![0u8; 512.min(entry.size as usize)];
                                if file.read_exact(&mut hdr).is_ok() {
                                    let dt = crate::scan::detect_content_type(&hdr);
                                    if dt != crate::scan::magic::DetectedType::Unknown {
                                        Some(dt.name().to_string())
                                    } else {
                                        Some("Binary Data / Unknown".to_string())
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else if entry.is_dir {
                        Some("Directory".to_string())
                    } else {
                        Some("Empty File".to_string())
                    };

                    discovered.push(DiscoveredFile {
                        path: MediaPath::from(entry.name.as_bytes()),
                        size: entry.size,
                        is_dir: entry.is_dir,
                        attributes: entry.attributes as u8,
                        partition_index: part_index,
                        data_offset,
                        created: entry.created,
                        modified: entry.modified,
                        accessed: entry.accessed,
                        starting_cluster: if entry.cluster >= 2 {
                            Some(entry.cluster)
                        } else {
                            None
                        },
                        cluster_size: Some(cluster_size as u32),
                        fs_type: Some("exFAT".to_string()),
                        detected_type,
                    });
                }
            }
        }
    }

    Ok(discovered)
}
