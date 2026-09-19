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
