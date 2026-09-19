use crate::core::StageError;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mft_mirr_lcn: u64,
}

pub fn parse_ntfs_boot_sector(sector: &[u8]) -> Result<NtfsBootSector, StageError> {
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

    if &sector[3..11] != b"NTFS    " {
        return Err(StageError::Parse("invalid NTFS OEM ID".to_string()));
    }

    let is_jump = sector[0] == 0xEB && sector[1] == 0x52 && sector[2] == 0x90;
    if !is_jump {
        return Err(StageError::Parse(
            "invalid NTFS jump instruction".to_string(),
        ));
    }

    let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
    let sectors_per_cluster = sector[13];

    if ![512, 1024, 2048, 4096].contains(&bytes_per_sector) {
        return Err(StageError::Parse(format!(
            "invalid bytes_per_sector {bytes_per_sector}"
        )));
    }

    if sectors_per_cluster == 0 || (sectors_per_cluster & (sectors_per_cluster - 1)) != 0 {
        return Err(StageError::Parse(format!(
            "invalid sectors_per_cluster {sectors_per_cluster}"
        )));
    }

    let total_sectors = u64::from_le_bytes([
        sector[40], sector[41], sector[42], sector[43], sector[44], sector[45], sector[46],
        sector[47],
    ]);

    let mft_lcn = u64::from_le_bytes([
        sector[48], sector[49], sector[50], sector[51], sector[52], sector[53], sector[54],
        sector[55],
    ]);

    let mft_mirr_lcn = u64::from_le_bytes([
        sector[56], sector[57], sector[58], sector[59], sector[60], sector[61], sector[62],
        sector[63],
    ]);

    Ok(NtfsBootSector {
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors,
        mft_lcn,
        mft_mirr_lcn,
    })
}

pub fn check_ntfs_backup_boot_sector<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    partition_sectors: u64,
    bpb: &NtfsBootSector,
) -> Result<bool, StageError> {
    if partition_sectors == 0 {
        return Ok(true);
    }

    let primary_offset = partition_offset;
    let backup_sector_idx = partition_sectors.saturating_sub(1);
    let backup_offset = partition_offset
        .saturating_add(backup_sector_idx.saturating_mul(bpb.bytes_per_sector as u64));

    reader
        .seek(SeekFrom::Start(primary_offset))
        .map_err(|e| StageError::Io(format!("failed to seek to NTFS primary boot sector: {e}")))?;
    let mut primary_buf = vec![0u8; 512];
    reader
        .read_exact(&mut primary_buf)
        .map_err(|e| StageError::Io(format!("failed to read NTFS primary boot sector: {e}")))?;

    reader
        .seek(SeekFrom::Start(backup_offset))
        .map_err(|e| StageError::Io(format!("failed to seek to NTFS backup boot sector: {e}")))?;
    let mut backup_buf = vec![0u8; 512];
    reader
        .read_exact(&mut backup_buf)
        .map_err(|e| StageError::Io(format!("failed to read NTFS backup boot sector: {e}")))?;

    Ok(primary_buf == backup_buf)
}
