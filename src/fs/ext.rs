use crate::core::StageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtSuperblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub block_size: u32,
    pub total_bytes: u64,
}

pub fn parse_ext_superblock(data: &[u8]) -> Result<ExtSuperblock, StageError> {
    if data.len() < 1024 {
        return Err(StageError::Parse(
            "superblock buffer smaller than 1024 bytes".to_string(),
        ));
    }

    let magic = u16::from_le_bytes([data[56], data[57]]);
    if magic != 0xEF53 {
        return Err(StageError::Parse("invalid ext magic signature".to_string()));
    }

    let inodes_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let blocks_count_lo = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
    let log_block_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

    if log_block_size > 6 {
        return Err(StageError::Parse(format!(
            "invalid log_block_size {log_block_size}"
        )));
    }

    let block_size = 1024u32.checked_shl(log_block_size).unwrap_or(4096);

    let blocks_count_hi = if data.len() >= 340 {
        u32::from_le_bytes([data[336], data[337], data[338], data[339]]) as u64
    } else {
        0
    };

    let blocks_count = (blocks_count_hi << 32) | blocks_count_lo;
    let total_bytes = blocks_count.saturating_mul(block_size as u64);

    Ok(ExtSuperblock {
        inodes_count,
        blocks_count,
        block_size,
        total_bytes,
    })
}
