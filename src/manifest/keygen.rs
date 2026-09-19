use crate::core::StageError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn hex_decode(input: &[u8]) -> Result<Vec<u8>, StageError> {
    if !input.len().is_multiple_of(2) {
        return Err(StageError::Parse("odd length in hex string".to_string()));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_chunks::<2>().0 {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, StageError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StageError::Parse(format!(
            "invalid hex character: '{}'",
            b as char
        ))),
    }
}

fn random_32_bytes() -> Result<[u8; 32], StageError> {
    let mut f = File::open("/dev/urandom")
        .map_err(|e| StageError::Io(format!("failed to open /dev/urandom: {e}")))?;
    let mut bytes = [0u8; 32];
    f.read_exact(&mut bytes)
        .map_err(|e| StageError::Io(format!("failed to read from /dev/urandom: {e}")))?;
    Ok(bytes)
}

pub fn generate_station_keypair(
    out_dir: &Path,
    force: bool,
) -> Result<(PathBuf, PathBuf), StageError> {
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir).map_err(|e| {
            StageError::Io(format!(
                "failed to create key directory {}: {e}",
                out_dir.display()
            ))
        })?;
    }

    let key_path = out_dir.join("station.key");
    let pub_path = out_dir.join("station.pub");

    if (key_path.exists() || pub_path.exists()) && !force {
        return Err(StageError::Io(format!(
            "station key files already exist in {} (use --force to overwrite)",
            out_dir.display()
        )));
    }

    let seed = random_32_bytes()?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let mut key_file = {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(&key_path).map_err(|e| {
            StageError::Io(format!(
                "failed to write station key {}: {e}",
                key_path.display()
            ))
        })?
    };

    let key_hex = hex_encode(&signing_key.to_bytes());
    key_file.write_all(key_hex.as_bytes()).map_err(|e| {
        StageError::Io(format!(
            "failed to write station key {}: {e}",
            key_path.display()
        ))
    })?;

    let mut pub_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pub_path)
        .map_err(|e| {
            StageError::Io(format!(
                "failed to write station pubkey {}: {e}",
                pub_path.display()
            ))
        })?;

    let pub_hex = hex_encode(verifying_key.as_bytes());
    pub_file.write_all(pub_hex.as_bytes()).map_err(|e| {
        StageError::Io(format!(
            "failed to write station pubkey {}: {e}",
            pub_path.display()
        ))
    })?;

    Ok((key_path, pub_path))
}

pub fn load_station_signing_key(key_path: &Path) -> Result<SigningKey, StageError> {
    let data = std::fs::read(key_path).map_err(|e| {
        StageError::Io(format!(
            "failed to read station key {}: {e}",
            key_path.display()
        ))
    })?;
    let trimmed = data.trim_ascii();
    let bytes = if trimmed.len() == 64 {
        hex_decode(trimmed)?
    } else {
        data
    };
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        StageError::Parse("invalid station key length (expected 32 bytes)".to_string())
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn load_station_verifying_key(pubkey_path: &Path) -> Result<VerifyingKey, StageError> {
    let data = std::fs::read(pubkey_path).map_err(|e| {
        StageError::Io(format!(
            "failed to read station public key {}: {e}",
            pubkey_path.display()
        ))
    })?;
    let trimmed = data.trim_ascii();
    let bytes = if trimmed.len() == 64 {
        hex_decode(trimmed)?
    } else {
        data
    };
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        StageError::Parse("invalid station public key length (expected 32 bytes)".to_string())
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| StageError::Parse(format!("invalid station public key: {e}")))
}
