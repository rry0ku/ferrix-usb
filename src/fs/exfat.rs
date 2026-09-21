use crate::core::StageError;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatBootSector {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub volume_length_sectors: u64,
    pub fat_offset_sectors: u32,
    pub fat_length_sectors: u32,
    pub cluster_heap_offset_sectors: u32,
    pub cluster_count: u32,
    pub root_dir_first_cluster: u32,
    pub num_fats: u8,
}

pub fn parse_exfat_boot_sector(sector: &[u8]) -> Result<ExfatBootSector, StageError> {
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

    if &sector[3..11] != b"EXFAT   " {
        return Err(StageError::Parse("invalid exFAT OEM ID".to_string()));
    }

    let is_jump = sector[0] == 0xEB && sector[1] == 0x76 && sector[2] == 0x90;
    if !is_jump {
        return Err(StageError::Parse(
            "invalid exFAT jump instruction".to_string(),
        ));
    }

    let volume_length_sectors = u64::from_le_bytes([
        sector[72], sector[73], sector[74], sector[75], sector[76], sector[77], sector[78],
        sector[79],
    ]);

    let fat_offset_sectors = u32::from_le_bytes([sector[80], sector[81], sector[82], sector[83]]);
    let fat_length_sectors = u32::from_le_bytes([sector[84], sector[85], sector[86], sector[87]]);
    let cluster_heap_offset_sectors =
        u32::from_le_bytes([sector[88], sector[89], sector[90], sector[91]]);
    let cluster_count = u32::from_le_bytes([sector[92], sector[93], sector[94], sector[95]]);
    let root_dir_first_cluster =
        u32::from_le_bytes([sector[96], sector[97], sector[98], sector[99]]);

    let bytes_per_sector_shift = sector[108];
    let sectors_per_cluster_shift = sector[109];
    let num_fats = sector[110];

    if !(9..=12).contains(&bytes_per_sector_shift) {
        return Err(StageError::Parse(format!(
            "invalid bytes_per_sector_shift {bytes_per_sector_shift}"
        )));
    }

    if sectors_per_cluster_shift > (25 - bytes_per_sector_shift) {
        return Err(StageError::Parse(format!(
            "invalid sectors_per_cluster_shift {sectors_per_cluster_shift}"
        )));
    }

    if num_fats != 1 && num_fats != 2 {
        return Err(StageError::Parse(format!("invalid num_fats {num_fats}")));
    }

    let bytes_per_sector = 1u32 << bytes_per_sector_shift;
    let sectors_per_cluster = 1u32 << sectors_per_cluster_shift;

    Ok(ExfatBootSector {
        bytes_per_sector,
        sectors_per_cluster,
        volume_length_sectors,
        fat_offset_sectors,
        fat_length_sectors,
        cluster_heap_offset_sectors,
        cluster_count,
        root_dir_first_cluster,
        num_fats,
    })
}

pub fn check_exfat_backup_boot_sector<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    bpb: &ExfatBootSector,
) -> Result<bool, StageError> {
    let primary_offset = partition_offset;
    let backup_offset = partition_offset.saturating_add(12 * bpb.bytes_per_sector as u64);

    reader
        .seek(SeekFrom::Start(primary_offset))
        .map_err(|e| StageError::Io(format!("failed to seek to exFAT primary boot sector: {e}")))?;
    let mut primary_buf = vec![0u8; 512];
    reader
        .read_exact(&mut primary_buf)
        .map_err(|e| StageError::Io(format!("failed to read exFAT primary boot sector: {e}")))?;

    reader
        .seek(SeekFrom::Start(backup_offset))
        .map_err(|e| StageError::Io(format!("failed to seek to exFAT backup boot sector: {e}")))?;
    let mut backup_buf = vec![0u8; 512];
    reader
        .read_exact(&mut backup_buf)
        .map_err(|e| StageError::Io(format!("failed to read exFAT backup boot sector: {e}")))?;

    Ok(primary_buf == backup_buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub cluster: u32,
    pub attributes: u16,
    pub no_fat_chain: bool,
}

pub fn exfat_cluster_to_offset(
    partition_offset: u64,
    bpb: &ExfatBootSector,
    cluster: u32,
) -> Option<u64> {
    if cluster < 2 {
        return None;
    }
    let cluster_size = (bpb.bytes_per_sector as u64).saturating_mul(bpb.sectors_per_cluster as u64);
    let heap_offset = partition_offset.saturating_add(
        (bpb.cluster_heap_offset_sectors as u64).saturating_mul(bpb.bytes_per_sector as u64),
    );
    Some(heap_offset.saturating_add(((cluster - 2) as u64).saturating_mul(cluster_size)))
}

pub fn read_exfat_cluster_chain<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    bpb: &ExfatBootSector,
    start_cluster: u32,
    max_clusters: usize,
) -> Result<Vec<u32>, StageError> {
    if start_cluster < 2 {
        return Ok(Vec::new());
    }
    let mut chain = Vec::new();
    let mut curr = start_cluster;
    let fat_offset = partition_offset.saturating_add(
        (bpb.fat_offset_sectors as u64).saturating_mul(bpb.bytes_per_sector as u64),
    );
    let mut visited = std::collections::HashSet::new();

    while curr >= 2 && chain.len() < max_clusters {
        if !visited.insert(curr) {
            break;
        }
        chain.push(curr);
        let entry_offset = fat_offset.saturating_add((curr as u64).saturating_mul(4));
        reader
            .seek(SeekFrom::Start(entry_offset))
            .map_err(|e| StageError::Io(e.to_string()))?;
        let mut buf = [0u8; 4];
        reader
            .read_exact(&mut buf)
            .map_err(|e| StageError::Io(e.to_string()))?;
        let next = u32::from_le_bytes(buf);
        if next >= 0xFFFF_FFF8 || next == 0xFFFF_FFF7 || next < 2 {
            break;
        }
        curr = next;
    }
    Ok(chain)
}

pub fn parse_exfat_directory(data: &[u8]) -> Vec<ExfatEntry> {
    let mut entries = Vec::new();
    let mut i = 0;

    while i + 32 <= data.len() {
        let entry_type = data[i];
        if entry_type == 0x00 {
            break;
        }
        if entry_type == 0x85 {
            let secondary_count = data[i + 1] as usize;
            let attributes = u16::from_le_bytes([data[i + 4], data[i + 5]]);
            let is_dir = (attributes & 0x10) != 0;

            let mut stream_info: Option<(u64, u32, bool)> = None;
            let mut name_parts: Vec<u16> = Vec::new();

            for s in 1..=secondary_count {
                let sec_offset = i.saturating_add(s.saturating_mul(32));
                if sec_offset + 32 > data.len() {
                    break;
                }
                let sec_type = data[sec_offset];
                if sec_type == 0xC0 {
                    let flags = data[sec_offset + 1];
                    let no_fat_chain = (flags & 0x02) != 0;
                    let size = u64::from_le_bytes([
                        data[sec_offset + 8],
                        data[sec_offset + 9],
                        data[sec_offset + 10],
                        data[sec_offset + 11],
                        data[sec_offset + 12],
                        data[sec_offset + 13],
                        data[sec_offset + 14],
                        data[sec_offset + 15],
                    ]);
                    let first_cluster = u32::from_le_bytes([
                        data[sec_offset + 20],
                        data[sec_offset + 21],
                        data[sec_offset + 22],
                        data[sec_offset + 23],
                    ]);
                    stream_info = Some((size, first_cluster, no_fat_chain));
                } else if sec_type == 0xC1 {
                    for chunk in data[sec_offset + 2..sec_offset + 32].as_chunks::<2>().0 {
                        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
                        if ch != 0 {
                            name_parts.push(ch);
                        }
                    }
                }
            }

            if let Some((size, cluster, no_fat_chain)) = stream_info {
                let name = String::from_utf16_lossy(&name_parts);
                if !name.is_empty() {
                    entries.push(ExfatEntry {
                        name,
                        is_dir,
                        size,
                        cluster,
                        attributes,
                        no_fat_chain,
                    });
                }
            }
            i = i.saturating_add((secondary_count + 1).saturating_mul(32));
        } else {
            i += 32;
        }
    }
    entries
}
