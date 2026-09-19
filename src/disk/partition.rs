use crate::core::StageError;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Partition {
    pub index: u32,
    pub start_lba: u64,
    pub end_lba: u64,
    pub total_sectors: u64,
    pub type_guid: Option<String>,
    pub type_byte: Option<u8>,
    pub bootable: bool,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionTableType {
    Mbr,
    Gpt,
    Hybrid,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskLayout {
    pub sector_size: u32,
    pub total_sectors: u64,
    pub table_type: PartitionTableType,
    pub partitions: Vec<Partition>,
    pub has_protective_mbr: bool,
    pub primary_gpt_valid: bool,
    pub backup_gpt_valid: bool,
    pub gpt_differs_from_backup: bool,
    pub backup_gpt_lba_mismatch: bool,
    pub mbr_partition_count: usize,
    pub gpt_partition_count: usize,
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDBA_BC40 & mask);
        }
    }
    !crc
}

pub fn parse_disk_layout<R: Read + Seek>(
    reader: &mut R,
    total_bytes: u64,
    sector_size: u32,
) -> Result<DiskLayout, StageError> {
    if sector_size == 0 || total_bytes < sector_size as u64 {
        return Err(StageError::Parse(format!(
            "invalid disk size {total_bytes} or sector size {sector_size}"
        )));
    }

    let total_sectors = total_bytes / sector_size as u64;

    let (has_mbr_sig, mbr_partitions, has_protective_mbr) = parse_mbr(reader, sector_size)?;

    let (
        primary_gpt_valid,
        backup_gpt_valid,
        gpt_differs_from_backup,
        backup_gpt_lba_mismatch,
        gpt_partitions,
    ) = parse_gpt(reader, total_sectors, sector_size)?;

    let mbr_partition_count = mbr_partitions.len();
    let gpt_partition_count = gpt_partitions.len();

    let table_type = if primary_gpt_valid || backup_gpt_valid {
        let non_protective_mbr = mbr_partitions.iter().any(|p| p.type_byte != Some(0xEE));
        if non_protective_mbr {
            PartitionTableType::Hybrid
        } else {
            PartitionTableType::Gpt
        }
    } else if has_mbr_sig && mbr_partition_count > 0 {
        PartitionTableType::Mbr
    } else {
        PartitionTableType::None
    };

    let partitions = match table_type {
        PartitionTableType::Gpt | PartitionTableType::Hybrid => gpt_partitions,
        PartitionTableType::Mbr => mbr_partitions,
        PartitionTableType::None => Vec::new(),
    };

    Ok(DiskLayout {
        sector_size,
        total_sectors,
        table_type,
        partitions,
        has_protective_mbr,
        primary_gpt_valid,
        backup_gpt_valid,
        gpt_differs_from_backup,
        backup_gpt_lba_mismatch,
        mbr_partition_count,
        gpt_partition_count,
    })
}

fn parse_mbr<R: Read + Seek>(
    reader: &mut R,
    sector_size: u32,
) -> Result<(bool, Vec<Partition>, bool), StageError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| StageError::Io(format!("seek to MBR failed: {e}")))?;

    let mut sector0 = vec![0u8; sector_size as usize];
    reader
        .read_exact(&mut sector0)
        .map_err(|e| StageError::Io(format!("read MBR failed: {e}")))?;

    if sector0.len() < 512 {
        return Ok((false, Vec::new(), false));
    }

    let has_sig = sector0[510] == 0x55 && sector0[511] == 0xAA;
    if !has_sig {
        return Ok((false, Vec::new(), false));
    }

    let mut partitions = Vec::new();
    let mut has_protective_mbr = false;

    for i in 0..4 {
        let offset = 446 + i * 16;
        let entry = &sector0[offset..offset + 16];

        let boot_indicator = entry[0];
        let type_byte = entry[4];
        let lba_start = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
        let sector_count = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;

        if type_byte == 0xEE {
            has_protective_mbr = true;
        }

        if type_byte != 0x00 {
            let end_lba = if sector_count > 0 {
                lba_start.saturating_add(sector_count).saturating_sub(1)
            } else {
                lba_start
            };
            partitions.push(Partition {
                index: i as u32 + 1,
                start_lba: lba_start,
                end_lba,
                total_sectors: sector_count,
                type_guid: None,
                type_byte: Some(type_byte),
                bootable: boot_indicator == 0x80,
                name: None,
            });
        }
    }

    let mut extended_partitions = Vec::new();
    for p in &partitions {
        if let Some(t) = p.type_byte {
            if t == 0x05 || t == 0x0F || t == 0x85 {
                extended_partitions.push((p.start_lba, p.total_sectors));
            }
        }
    }

    let mut next_logical_index = 5u32;
    for (ext_base_lba, ext_total_sectors) in extended_partitions {
        let mut current_ebr_lba = ext_base_lba;
        let mut visited_ebrs = std::collections::HashSet::new();
        let max_logical_partitions = 64;

        while visited_ebrs.len() < max_logical_partitions && visited_ebrs.insert(current_ebr_lba) {
            let ebr_offset = current_ebr_lba.saturating_mul(sector_size as u64);
            if reader.seek(SeekFrom::Start(ebr_offset)).is_err() {
                break;
            }

            let mut ebr_buf = vec![0u8; 512];
            if reader.read_exact(&mut ebr_buf).is_err() {
                break;
            }

            if ebr_buf[510] != 0x55 || ebr_buf[511] != 0xAA {
                break;
            }

            let entry0 = &ebr_buf[446..462];
            let entry0_type = entry0[4];
            let entry0_rel_lba =
                u32::from_le_bytes([entry0[8], entry0[9], entry0[10], entry0[11]]) as u64;
            let entry0_sectors =
                u32::from_le_bytes([entry0[12], entry0[13], entry0[14], entry0[15]]) as u64;

            if entry0_type != 0x00 && entry0_sectors > 0 {
                let logical_start = current_ebr_lba.saturating_add(entry0_rel_lba);
                let logical_end = logical_start
                    .saturating_add(entry0_sectors)
                    .saturating_sub(1);

                partitions.push(Partition {
                    index: next_logical_index,
                    start_lba: logical_start,
                    end_lba: logical_end,
                    total_sectors: entry0_sectors,
                    type_guid: None,
                    type_byte: Some(entry0_type),
                    bootable: entry0[0] == 0x80,
                    name: None,
                });
                next_logical_index += 1;
            }

            let entry1 = &ebr_buf[462..478];
            let entry1_type = entry1[4];
            let entry1_rel_lba =
                u32::from_le_bytes([entry1[8], entry1[9], entry1[10], entry1[11]]) as u64;

            if (entry1_type == 0x05 || entry1_type == 0x0F || entry1_type == 0x85)
                && entry1_rel_lba > 0
            {
                current_ebr_lba = ext_base_lba.saturating_add(entry1_rel_lba);
                if current_ebr_lba >= ext_base_lba.saturating_add(ext_total_sectors) {
                    break;
                }
            } else {
                break;
            }
        }
    }

    Ok((true, partitions, has_protective_mbr))
}

fn parse_gpt<R: Read + Seek>(
    reader: &mut R,
    total_sectors: u64,
    sector_size: u32,
) -> Result<(bool, bool, bool, bool, Vec<Partition>), StageError> {
    if total_sectors < 3 {
        return Ok((false, false, false, false, Vec::new()));
    }

    let (primary_valid, primary_partitions, backup_lba) =
        parse_gpt_header_and_entries(reader, 1, sector_size)?;

    let backup_target_lba = total_sectors.saturating_sub(1);
    let backup_gpt_lba_mismatch = primary_valid && backup_lba != backup_target_lba;

    let (backup_valid, backup_partitions, _) =
        parse_gpt_header_and_entries(reader, backup_target_lba, sector_size)?;

    let gpt_differs_from_backup = if primary_valid && backup_valid {
        primary_partitions != backup_partitions
    } else {
        false
    };

    let partitions = if primary_valid {
        primary_partitions
    } else if backup_valid {
        backup_partitions
    } else {
        Vec::new()
    };

    Ok((
        primary_valid,
        backup_valid,
        gpt_differs_from_backup,
        backup_gpt_lba_mismatch,
        partitions,
    ))
}

fn parse_gpt_header_and_entries<R: Read + Seek>(
    reader: &mut R,
    header_lba: u64,
    sector_size: u32,
) -> Result<(bool, Vec<Partition>, u64), StageError> {
    let offset = header_lba.saturating_mul(sector_size as u64);
    if reader.seek(SeekFrom::Start(offset)).is_err() {
        return Ok((false, Vec::new(), 0));
    }

    let mut header_buf = vec![0u8; sector_size as usize];
    if reader.read_exact(&mut header_buf).is_err() {
        return Ok((false, Vec::new(), 0));
    }

    if header_buf.len() < 92 || &header_buf[0..8] != b"EFI PART" {
        return Ok((false, Vec::new(), 0));
    }

    let header_size = u32::from_le_bytes([
        header_buf[12],
        header_buf[13],
        header_buf[14],
        header_buf[15],
    ]) as usize;
    if header_size < 92 || header_size > header_buf.len() {
        return Ok((false, Vec::new(), 0));
    }

    let recorded_crc = u32::from_le_bytes([
        header_buf[16],
        header_buf[17],
        header_buf[18],
        header_buf[19],
    ]);
    let mut header_copy = header_buf[..header_size].to_vec();
    header_copy[16] = 0;
    header_copy[17] = 0;
    header_copy[18] = 0;
    header_copy[19] = 0;
    if crc32(&header_copy) != recorded_crc {
        return Ok((false, Vec::new(), 0));
    }

    let backup_lba = u64::from_le_bytes([
        header_buf[32],
        header_buf[33],
        header_buf[34],
        header_buf[35],
        header_buf[36],
        header_buf[37],
        header_buf[38],
        header_buf[39],
    ]);

    let entries_lba = u64::from_le_bytes([
        header_buf[72],
        header_buf[73],
        header_buf[74],
        header_buf[75],
        header_buf[76],
        header_buf[77],
        header_buf[78],
        header_buf[79],
    ]);

    let num_entries = u32::from_le_bytes([
        header_buf[80],
        header_buf[81],
        header_buf[82],
        header_buf[83],
    ]) as usize;

    let entry_size = u32::from_le_bytes([
        header_buf[84],
        header_buf[85],
        header_buf[86],
        header_buf[87],
    ]) as usize;

    let entries_crc = u32::from_le_bytes([
        header_buf[88],
        header_buf[89],
        header_buf[90],
        header_buf[91],
    ]);

    if entry_size < 128 || num_entries > 1024 {
        return Ok((false, Vec::new(), backup_lba));
    }

    let total_entries_bytes = match num_entries.checked_mul(entry_size) {
        Some(b) => b,
        None => return Ok((false, Vec::new(), backup_lba)),
    };

    let entries_offset = entries_lba.saturating_mul(sector_size as u64);
    if reader.seek(SeekFrom::Start(entries_offset)).is_err() {
        return Ok((false, Vec::new(), backup_lba));
    }

    let mut entries_buf = vec![0u8; total_entries_bytes];
    if reader.read_exact(&mut entries_buf).is_err() {
        return Ok((false, Vec::new(), backup_lba));
    }

    if crc32(&entries_buf) != entries_crc {
        return Ok((false, Vec::new(), backup_lba));
    }

    let mut partitions = Vec::new();
    for i in 0..num_entries {
        let entry_start = i * entry_size;
        let entry_bytes = &entries_buf[entry_start..entry_start + entry_size];

        let type_guid_bytes = &entry_bytes[0..16];
        if type_guid_bytes.iter().all(|&b| b == 0) {
            continue;
        }

        let type_guid = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            type_guid_bytes[3], type_guid_bytes[2], type_guid_bytes[1], type_guid_bytes[0],
            type_guid_bytes[5], type_guid_bytes[4],
            type_guid_bytes[7], type_guid_bytes[6],
            type_guid_bytes[8], type_guid_bytes[9],
            type_guid_bytes[10], type_guid_bytes[11], type_guid_bytes[12], type_guid_bytes[13], type_guid_bytes[14], type_guid_bytes[15]
        );

        let start_lba = u64::from_le_bytes([
            entry_bytes[32],
            entry_bytes[33],
            entry_bytes[34],
            entry_bytes[35],
            entry_bytes[36],
            entry_bytes[37],
            entry_bytes[38],
            entry_bytes[39],
        ]);

        let end_lba = u64::from_le_bytes([
            entry_bytes[40],
            entry_bytes[41],
            entry_bytes[42],
            entry_bytes[43],
            entry_bytes[44],
            entry_bytes[45],
            entry_bytes[46],
            entry_bytes[47],
        ]);

        let total_sectors = if end_lba >= start_lba {
            end_lba.saturating_sub(start_lba).saturating_add(1)
        } else {
            0
        };

        let raw_name = &entry_bytes[56..128];
        let name_utf16: Vec<u16> = raw_name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let name = String::from_utf16(&name_utf16).ok();

        partitions.push(Partition {
            index: i as u32 + 1,
            start_lba,
            end_lba,
            total_sectors,
            type_guid: Some(type_guid),
            type_byte: None,
            bootable: false,
            name,
        });
    }

    Ok((true, partitions, backup_lba))
}
