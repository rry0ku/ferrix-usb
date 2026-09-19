use crate::core::StageError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::fs;
use std::path::Path;

pub fn verify_ed25519_signature(
    data: &[u8],
    signature_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Result<(), StageError> {
    let key_array: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
        StageError::Parse("invalid Ed25519 public key length (expected 32 bytes)".to_string())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| StageError::Parse(format!("invalid Ed25519 public key: {e}")))?;

    let sig_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        StageError::Parse("invalid Ed25519 signature length (expected 64 bytes)".to_string())
    })?;

    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(data, &signature)
        .map_err(|e| StageError::Parse(format!("Ed25519 signature verification failed: {e}")))?;

    Ok(())
}

pub fn verify_policy_file(policy_path: &Path, pubkey_path: &Path) -> Result<Vec<u8>, StageError> {
    let policy_data = fs::read(policy_path).map_err(|e| {
        StageError::Io(format!(
            "failed to read policy file {}: {e}",
            policy_path.display()
        ))
    })?;

    let pubkey_data = fs::read(pubkey_path).map_err(|e| {
        StageError::Io(format!(
            "failed to read public key {}: {e}",
            pubkey_path.display()
        ))
    })?;

    let sig_path = policy_path.with_extension(format!(
        "{}.sig",
        policy_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("yaml")
    ));

    let sig_data = if sig_path.exists() {
        fs::read(&sig_path).map_err(|e| {
            StageError::Io(format!(
                "failed to read policy signature file {}: {e}",
                sig_path.display()
            ))
        })?
    } else {
        let alt_sig_path = policy_path.with_extension("sig");
        fs::read(&alt_sig_path).map_err(|e| {
            StageError::Io(format!(
                "missing policy signature file (checked {} and {}): {e}",
                sig_path.display(),
                alt_sig_path.display()
            ))
        })?
    };

    let pubkey_trimmed = pubkey_data.trim_ascii();
    let pubkey_bytes = if pubkey_trimmed.len() == 64 {
        hex_decode(pubkey_trimmed)?
    } else {
        pubkey_data
    };

    let sig_trimmed = sig_data.trim_ascii();
    let sig_bytes = if sig_trimmed.len() == 128 {
        hex_decode(sig_trimmed)?
    } else {
        sig_data
    };

    verify_ed25519_signature(&policy_data, &sig_bytes, &pubkey_bytes)?;

    Ok(policy_data)
}

fn hex_decode(input: &[u8]) -> Result<Vec<u8>, StageError> {
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
