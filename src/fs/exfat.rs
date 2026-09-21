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
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
}

pub fn format_exfat_datetime(date: u16, time: u16, utc_offset_byte: u8) -> Option<String> {
    if date == 0 && time == 0 {
        return None;
    }
    let year = 1980 + ((date >> 9) & 0x7F) as u32;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;

    let hour = ((time >> 11) & 0x1F) as u32;
    let minute = ((time >> 5) & 0x3F) as u32;
    let second = ((time & 0x1F) * 2) as u32;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let dt = format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}");

    if utc_offset_byte & 0x80 != 0 {
        let offset_val = if (utc_offset_byte & 0x40) != 0 {
            (utc_offset_byte | 0x80) as i8
        } else {
            (utc_offset_byte & 0x3F) as i8
        };
        let total_mins = offset_val as i32 * 15;
        let tz_sign = if total_mins >= 0 { '+' } else { '-' };
        let tz_hours = (total_mins.abs()) / 60;
        let tz_mins = (total_mins.abs()) % 60;
        Some(format!("{dt} UTC{tz_sign}{tz_hours:02}:{tz_mins:02}"))
    } else {
        Some(dt)
    }
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

            let c_time = u16::from_le_bytes([data[i + 8], data[i + 9]]);
            let c_date = u16::from_le_bytes([data[i + 10], data[i + 11]]);
            let c_utc = if i + 22 < data.len() { data[i + 22] } else { 0 };
            let created = format_exfat_datetime(c_date, c_time, c_utc);

            let m_time = u16::from_le_bytes([data[i + 12], data[i + 13]]);
            let m_date = u16::from_le_bytes([data[i + 14], data[i + 15]]);
            let m_utc = if i + 23 < data.len() { data[i + 23] } else { 0 };
            let modified = format_exfat_datetime(m_date, m_time, m_utc);

            let a_time = u16::from_le_bytes([data[i + 16], data[i + 17]]);
            let a_date = u16::from_le_bytes([data[i + 18], data[i + 19]]);
            let a_utc = if i + 24 < data.len() { data[i + 24] } else { 0 };
            let accessed = format_exfat_datetime(a_date, a_time, a_utc);

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
                        created,
                        modified,
                        accessed,
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
