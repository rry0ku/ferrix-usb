use crate::core::StageError;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatBootSector {
    pub fat_type: FatType,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entries: u16,
    pub total_sectors: u64,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
    pub backup_boot_sector: Option<u16>,
    pub oem_name: String,
    pub volume_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub cluster: u32,
    pub attributes: u8,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
}

pub fn format_dos_datetime(date: u16, time: u16) -> Option<String> {
    if date == 0 && time == 0 {
        return None;
    }
    let year = 1980 + ((date >> 9) & 0x7F) as u32;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;

    let hour = ((time >> 11) & 0x1F) as u32;
    let minute = ((time >> 5) & 0x3F) as u32;
    let second = ((time & 0x1F) * 2) as u32;

    if (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
    {
        Some(format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
        ))
    } else {
        None
    }
}

pub fn format_dos_date(date: u16) -> Option<String> {
    if date == 0 {
        return None;
    }
    let year = 1980 + ((date >> 9) & 0x7F) as u32;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;

    if (1..=12).contains(&month) && (1..=31).contains(&day) {
        Some(format!("{year:04}-{month:02}-{day:02}"))
    } else {
        None
    }
}

pub fn parse_fat_boot_sector(sector: &[u8]) -> Result<FatBootSector, StageError> {
    if sector.len() < 512 {
        return Err(StageError::Parse(
            "sector smaller than 512 bytes".to_string(),
        ));
    }

    if sector[510] != 0x55 || sector[511] != 0xAA {
        return Err(StageError::Parse(
            "invalid boot sector signature".to_string(),
        ));
    }

    let is_jump = (sector[0] == 0xEB && sector[2] == 0x90) || sector[0] == 0xE9;
    if !is_jump {
        return Err(StageError::Parse(
            "invalid jump instruction in boot sector".to_string(),
        ));
    }

    let oem_bytes = &sector[3..11];
    let oem_name = String::from_utf8_lossy(oem_bytes).trim().to_string();

    let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
    let sectors_per_cluster = sector[13];
    let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
    let num_fats = sector[16];
    let root_entries = u16::from_le_bytes([sector[17], sector[18]]);
    let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
    let sectors_per_fat_16 = u16::from_le_bytes([sector[22], sector[23]]);
    let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);

    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        return Err(StageError::Parse(
            "zero sector or cluster size in FAT BPB".to_string(),
        ));
    }

    let sectors_per_fat_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
    let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
    let backup_boot_sector = u16::from_le_bytes([sector[50], sector[51]]);

    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16 as u64
    } else {
        total_sectors_32 as u64
    };

    let sectors_per_fat = if sectors_per_fat_16 != 0 {
        sectors_per_fat_16 as u32
    } else {
        sectors_per_fat_32
    };

    let root_dir_sectors = ((root_entries as u32 * 32)
        .saturating_add(bytes_per_sector as u32)
        .saturating_sub(1))
        / bytes_per_sector as u32;

    let total_data_sectors = total_sectors.saturating_sub(
        reserved_sectors as u64
            + (num_fats as u64 * sectors_per_fat as u64)
            + root_dir_sectors as u64,
    );

    let total_clusters = total_data_sectors / sectors_per_cluster as u64;

    let fat_type = if sectors_per_fat_16 == 0 && sectors_per_fat_32 > 0 {
        FatType::Fat32
    } else if root_entries != 0 {
        if total_clusters < 4085 {
            FatType::Fat12
        } else {
            FatType::Fat16
        }
    } else if total_clusters < 4085 {
        FatType::Fat12
    } else if total_clusters < 65525 {
        FatType::Fat16
    } else {
        FatType::Fat32
    };

    let (backup_sec, vol_label) = if fat_type == FatType::Fat32 {
        let label_bytes = &sector[71..82];
        let label = String::from_utf8_lossy(label_bytes).trim().to_string();
        (
            Some(backup_boot_sector),
            if label.is_empty() { None } else { Some(label) },
        )
    } else {
        let label_bytes = &sector[43..54];
        let label = String::from_utf8_lossy(label_bytes).trim().to_string();
        (None, if label.is_empty() { None } else { Some(label) })
    };

    Ok(FatBootSector {
        fat_type,
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        root_entries,
        total_sectors,
        sectors_per_fat,
        root_cluster,
        backup_boot_sector: backup_sec,
        oem_name,
        volume_label: vol_label,
    })
}

pub fn check_fat_backup_boot_sector<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    bpb: &FatBootSector,
) -> Result<bool, StageError> {
    let backup_sec = match bpb.backup_boot_sector {
        Some(s) if s > 0 && s < bpb.reserved_sectors => s,
        _ => return Ok(true),
    };

    let primary_offset = partition_offset;
    let backup_offset =
        partition_offset.saturating_add(backup_sec as u64 * bpb.bytes_per_sector as u64);

    reader
        .seek(SeekFrom::Start(primary_offset))
        .map_err(|e| StageError::Io(format!("failed to seek to primary boot sector: {e}")))?;
    let mut primary_buf = vec![0u8; 512];
    reader
        .read_exact(&mut primary_buf)
        .map_err(|e| StageError::Io(format!("failed to read primary boot sector: {e}")))?;

    reader
        .seek(SeekFrom::Start(backup_offset))
        .map_err(|e| StageError::Io(format!("failed to seek to backup boot sector: {e}")))?;
    let mut backup_buf = vec![0u8; 512];
    reader
        .read_exact(&mut backup_buf)
        .map_err(|e| StageError::Io(format!("failed to read backup boot sector: {e}")))?;

    Ok(primary_buf == backup_buf)
}

pub fn parse_fat_directory(dir_data: &[u8]) -> Result<(Vec<FatDirEntry>, Vec<String>), StageError> {
    let mut entries = Vec::new();
    let mut duplicates = Vec::new();
    let mut seen_names = HashSet::new();

    let mut lfn_parts: Vec<(u8, String)> = Vec::new();
    let mut idx = 0;

    while idx + 32 <= dir_data.len() {
        let entry = &dir_data[idx..idx + 32];
        idx += 32;

        let first_byte = entry[0];
        if first_byte == 0x00 {
            break;
        }
        if first_byte == 0xE5 {
            lfn_parts.clear();
            continue;
        }

        let attr = entry[11];
        if attr == 0x0F {
            let seq = entry[0];
            let mut name_utf16 = Vec::with_capacity(13);
            for pair in entry[1..11].as_chunks::<2>().0 {
                let code = u16::from_le_bytes([pair[0], pair[1]]);
                if code != 0 && code != 0xFFFF {
                    name_utf16.push(code);
                }
            }
            for pair in entry[14..26].as_chunks::<2>().0 {
                let code = u16::from_le_bytes([pair[0], pair[1]]);
                if code != 0 && code != 0xFFFF {
                    name_utf16.push(code);
                }
            }
            for pair in entry[28..32].as_chunks::<2>().0 {
                let code = u16::from_le_bytes([pair[0], pair[1]]);
                if code != 0 && code != 0xFFFF {
                    name_utf16.push(code);
                }
            }
            let part_str = String::from_utf16_lossy(&name_utf16);
            lfn_parts.push((seq, part_str));
            continue;
        }

        if (attr & 0x08) != 0 {
            lfn_parts.clear();
            continue;
        }

        let full_name = if !lfn_parts.is_empty() {
            lfn_parts.sort_by_key(|p| p.0 & 0x1F);
            let combined: String = lfn_parts.iter().map(|p| p.1.as_str()).collect();
            lfn_parts.clear();
            combined
        } else {
            let base_bytes = &entry[0..8];
            let ext_bytes = &entry[8..11];
            let base = String::from_utf8_lossy(base_bytes).trim().to_string();
            let ext = String::from_utf8_lossy(ext_bytes).trim().to_string();
            if ext.is_empty() {
                base
            } else {
                format!("{base}.{ext}")
            }
        };

        if full_name.is_empty() || full_name == "." || full_name == ".." {
            continue;
        }

        let lower_name = full_name.to_lowercase();
        if !seen_names.insert(lower_name) {
            duplicates.push(full_name.clone());
        }

        let is_dir = (attr & 0x10) != 0;
        let cluster_high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
        let cluster_low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
        let cluster = (cluster_high << 16) | cluster_low;
        let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]) as u64;

        let c_time = u16::from_le_bytes([entry[14], entry[15]]);
        let c_date = u16::from_le_bytes([entry[16], entry[17]]);
        let created = format_dos_datetime(c_date, c_time);

        let a_date = u16::from_le_bytes([entry[18], entry[19]]);
        let accessed = format_dos_date(a_date);

        let m_time = u16::from_le_bytes([entry[22], entry[23]]);
        let m_date = u16::from_le_bytes([entry[24], entry[25]]);
        let modified = format_dos_datetime(m_date, m_time);

        entries.push(FatDirEntry {
            name: full_name,
            is_dir,
            size,
            cluster,
            attributes: attr,
            created,
            modified,
            accessed,
        });
    }

    Ok((entries, duplicates))
}

pub fn read_next_cluster<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    bpb: &FatBootSector,
    cluster: u32,
) -> Result<Option<u32>, StageError> {
    let fat_offset =
        partition_offset.saturating_add(bpb.reserved_sectors as u64 * bpb.bytes_per_sector as u64);

    match bpb.fat_type {
        FatType::Fat32 => {
            let entry_offset = fat_offset.saturating_add(cluster as u64 * 4);
            reader
                .seek(SeekFrom::Start(entry_offset))
                .map_err(|e| StageError::Io(format!("failed to seek FAT32 entry: {e}")))?;
            let mut buf = [0u8; 4];
            reader
                .read_exact(&mut buf)
                .map_err(|e| StageError::Io(format!("failed to read FAT32 entry: {e}")))?;
            let val = u32::from_le_bytes(buf) & 0x0FFF_FFFF;
            if !(2..0x0FFF_FFF8).contains(&val) {
                Ok(None)
            } else {
                Ok(Some(val))
            }
        }
        FatType::Fat16 => {
            let entry_offset = fat_offset.saturating_add(cluster as u64 * 2);
            reader
                .seek(SeekFrom::Start(entry_offset))
                .map_err(|e| StageError::Io(format!("failed to seek FAT16 entry: {e}")))?;
            let mut buf = [0u8; 2];
            reader
                .read_exact(&mut buf)
                .map_err(|e| StageError::Io(format!("failed to read FAT16 entry: {e}")))?;
            let val = u16::from_le_bytes(buf) as u32;
            if !(2..0xFFF8).contains(&val) {
                Ok(None)
            } else {
                Ok(Some(val))
            }
        }
        FatType::Fat12 => {
            let entry_offset = fat_offset.saturating_add((cluster as u64 * 3) / 2);
            reader
                .seek(SeekFrom::Start(entry_offset))
                .map_err(|e| StageError::Io(format!("failed to seek FAT12 entry: {e}")))?;
            let mut buf = [0u8; 2];
            reader
                .read_exact(&mut buf)
                .map_err(|e| StageError::Io(format!("failed to read FAT12 entry: {e}")))?;
            let raw = u16::from_le_bytes(buf);
            let val = if (cluster & 1) == 0 {
                (raw & 0x0FFF) as u32
            } else {
                (raw >> 4) as u32
            };
            if !(2..0x0FF8).contains(&val) {
                Ok(None)
            } else {
                Ok(Some(val))
            }
        }
    }
}

pub fn read_cluster_chain<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    bpb: &FatBootSector,
    start_cluster: u32,
    max_clusters: usize,
) -> Result<Vec<u32>, StageError> {
    if start_cluster < 2 {
        return Ok(Vec::new());
    }

    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current = start_cluster;

    while chain.len() < max_clusters && visited.insert(current) {
        chain.push(current);
        match read_next_cluster(reader, partition_offset, bpb, current)? {
            Some(next) => current = next,
            None => break,
        }
    }

    Ok(chain)
}

pub fn cluster_to_byte_offset(
    partition_offset: u64,
    bpb: &FatBootSector,
    first_data_sector: u64,
    cluster: u32,
) -> u64 {
    partition_offset.saturating_add(
        (first_data_sector + ((cluster as u64).saturating_sub(2)) * bpb.sectors_per_cluster as u64)
            * bpb.bytes_per_sector as u64,
    )
}

pub fn read_chain_data<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    bpb: &FatBootSector,
    first_data_sector: u64,
    chain: &[u32],
    max_bytes: usize,
) -> Result<Vec<u8>, StageError> {
    let cluster_bytes = bpb.sectors_per_cluster as usize * bpb.bytes_per_sector as usize;
    let mut out = Vec::new();

    for &c in chain {
        if out.len() >= max_bytes {
            break;
        }

        let offset = cluster_to_byte_offset(partition_offset, bpb, first_data_sector, c);
        if reader.seek(SeekFrom::Start(offset)).is_err() {
            break;
        }

        let read_len = (max_bytes - out.len()).min(cluster_bytes);
        let mut buf = vec![0u8; read_len];
        if reader.read_exact(&mut buf).is_err() {
            break;
        }
        out.extend_from_slice(&buf);
    }

    Ok(out)
}
