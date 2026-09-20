use crate::core::{Finding, StageError, Verdict};
use crate::device::descriptors::{UsbDevice, UsbInterface};
use crate::disk::partition::DiskLayout;
use crate::manifest::Manifest;
use crate::policy::verify::verify_ed25519_signature;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicDeviceReport {
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub interfaces: Vec<UsbInterface>,
}

impl From<&UsbDevice> for ForensicDeviceReport {
    fn from(d: &UsbDevice) -> Self {
        Self {
            vendor_id: Some(d.vendor_id.clone()),
            product_id: Some(d.product_id.clone()),
            serial: d.serial.clone(),
            manufacturer: d.manufacturer.clone(),
            product_name: d.product_name.clone(),
            interfaces: d.interfaces.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicAcquisitionReport {
    pub sha256: String,
    pub blake3: String,
    pub timestamp: u64,
    pub total_sectors: u64,
    pub total_bytes: u64,
    pub sector_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicPartitionInfo {
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
pub struct ForensicReport {
    pub ferrix_version: String,
    pub station_id: String,
    pub report_id: String,
    pub generated_at: u64,
    pub device: Option<ForensicDeviceReport>,
    pub acquisition: ForensicAcquisitionReport,
    pub partitions: Vec<ForensicPartitionInfo>,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
    pub policy_hash: String,
    pub signature: Option<String>,
}

impl ForensicReport {
    pub fn new(
        station_id: String,
        device: Option<&UsbDevice>,
        acquisition: ForensicAcquisitionReport,
        layout: &DiskLayout,
        findings: Vec<Finding>,
        verdict: Verdict,
        policy_hash: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let partitions = layout
            .partitions
            .iter()
            .map(|p| ForensicPartitionInfo {
                index: p.index,
                start_lba: p.start_lba,
                end_lba: p.end_lba,
                total_sectors: p.total_sectors,
                type_guid: p.type_guid.clone(),
                type_byte: p.type_byte,
                bootable: p.bootable,
                name: p.name.clone(),
            })
            .collect();

        let report_id = format!("FX-REP-{now:x}");

        Self {
            ferrix_version: env!("CARGO_PKG_VERSION").to_string(),
            station_id,
            report_id,
            generated_at: now,
            device: device.map(ForensicDeviceReport::from),
            acquisition,
            partitions,
            findings,
            verdict,
            policy_hash,
            signature: None,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StageError> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(|e| {
            StageError::Internal(format!("failed to serialize report for signing: {e}"))
        })
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), StageError> {
        let bytes = self.canonical_bytes()?;
        let sig = key.sign(&bytes);
        self.signature = Some(hex_encode(&sig.to_bytes()));
        Ok(())
    }

    pub fn verify_signature(&self, pubkey: &VerifyingKey) -> Result<(), StageError> {
        let sig_str = self
            .signature
            .as_ref()
            .ok_or_else(|| StageError::Parse("report signature is missing".to_string()))?;
        let sig_bytes = hex_decode(sig_str.as_bytes())?;
        let canonical = self.canonical_bytes()?;
        verify_ed25519_signature(&canonical, &sig_bytes, pubkey.as_bytes())
    }

    pub fn to_text_summary(&self) -> String {
        let mut out = String::new();
        out.push_str("Ferrix Inspection Report\n\n");

        if let Some(ref dev) = self.device {
            out.push_str("Device:\n");
            if let Some(ref vid) = dev.vendor_id {
                out.push_str(&format!("  VID: 0x{vid}\n"));
            }
            if let Some(ref pid) = dev.product_id {
                out.push_str(&format!("  PID: 0x{pid}\n"));
            }
            if let Some(ref s) = dev.serial {
                out.push_str(&format!("  Serial: {s}\n"));
            }
            if let Some(ref m) = dev.manufacturer {
                out.push_str(&format!("  Manufacturer: {m}\n"));
            }
            if let Some(ref p) = dev.product_name {
                out.push_str(&format!("  Product: {p}\n"));
            }
            out.push('\n');
        }

        out.push_str("Acquisition:\n");
        if !self.acquisition.sha256.is_empty() {
            out.push_str(&format!("  SHA-256: {}\n", self.acquisition.sha256));
        }
        out.push_str(&format!("  BLAKE3: {}\n", self.acquisition.blake3));
        out.push_str(&format!("  Timestamp: {}\n", self.acquisition.timestamp));
        out.push_str(&format!("  Bytes: {}\n\n", self.acquisition.total_bytes));

        out.push_str("Partitions:\n");
        if self.partitions.is_empty() {
            out.push_str("  (No partitions detected)\n");
        } else {
            for p in &self.partitions {
                let name = p.name.as_deref().unwrap_or("unnamed");
                out.push_str(&format!(
                    "  Partition {}: {} (LBA {}-{}, {} sectors)\n",
                    p.index, name, p.start_lba, p.end_lba, p.total_sectors
                ));
            }
        }
        out.push('\n');

        out.push_str("Findings:\n");
        if self.findings.is_empty() {
            out.push_str("  (Clean - no findings)\n");
        } else {
            for f in &self.findings {
                out.push_str(&format!("  ⚠ [{}] {} - {}\n", f.severity, f.id, f.reason));
            }
        }
        out.push('\n');

        out.push_str(&format!("Decision:\n  {}\n", self.verdict));

        if let Some(ref sig) = self.signature {
            out.push_str(&format!("\nSignature:\n  {sig}\n"));
        }

        out
    }
}

pub fn generate_evidence_bundle(
    report: &ForensicReport,
    manifest: &Manifest,
    out_dir: &Path,
) -> Result<(), StageError> {
    let evidence_dir = out_dir.join("evidence");
    fs::create_dir_all(&evidence_dir).map_err(|e| {
        StageError::Io(format!(
            "failed to create evidence directory {}: {e}",
            evidence_dir.display()
        ))
    })?;

    let device_json = serde_json::to_string_pretty(&report.device).map_err(|e| {
        StageError::Internal(format!("failed to serialize device evidence: {e}"))
    })?;
    fs::write(evidence_dir.join("device.json"), device_json).map_err(|e| {
        StageError::Io(format!("failed to write device.json: {e}"))
    })?;

    let partitions_json = serde_json::to_string_pretty(&report.partitions).map_err(|e| {
        StageError::Internal(format!("failed to serialize partitions evidence: {e}"))
    })?;
    fs::write(evidence_dir.join("partitions.json"), partitions_json).map_err(|e| {
        StageError::Io(format!("failed to write partitions.json: {e}"))
    })?;

    let files_json = serde_json::to_string_pretty(&manifest.files).map_err(|e| {
        StageError::Internal(format!("failed to serialize files evidence: {e}"))
    })?;
    fs::write(evidence_dir.join("files.json"), files_json).map_err(|e| {
        StageError::Io(format!("failed to write files.json: {e}"))
    })?;

    let findings_json = serde_json::to_string_pretty(&report.findings).map_err(|e| {
        StageError::Internal(format!("failed to serialize findings evidence: {e}"))
    })?;
    fs::write(evidence_dir.join("findings.json"), findings_json).map_err(|e| {
        StageError::Io(format!("failed to write findings.json: {e}"))
    })?;

    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| {
        StageError::Internal(format!("failed to serialize manifest evidence: {e}"))
    })?;
    fs::write(evidence_dir.join("manifest.json"), manifest_json).map_err(|e| {
        StageError::Io(format!("failed to write manifest.json: {e}"))
    })?;

    if let Some(ref sig) = manifest.signature {
        fs::write(evidence_dir.join("manifest.sig"), sig).map_err(|e| {
            StageError::Io(format!("failed to write manifest.sig: {e}"))
        })?;
    }

    let report_json = serde_json::to_string_pretty(&report).map_err(|e| {
        StageError::Internal(format!("failed to serialize forensic report: {e}"))
    })?;
    fs::write(evidence_dir.join("report.json"), report_json).map_err(|e| {
        StageError::Io(format!("failed to write report.json: {e}"))
    })?;

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(bytes: &[u8]) -> Result<Vec<u8>, StageError> {
    if bytes.len() % 2 != 0 {
        return Err(StageError::Parse("hex string has odd length".to_string()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let s = std::str::from_utf8(chunk)
            .map_err(|e| StageError::Parse(format!("invalid utf8 in hex: {e}")))?;
        let b = u8::from_str_radix(s, 16)
            .map_err(|e| StageError::Parse(format!("invalid hex digit: {e}")))?;
        out.push(b);
    }
    Ok(out)
}
