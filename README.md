# ferrix-usb

**Air-gap and offline security station for removable media.**

`ferrix-usb` is an offline security tool that inspects USB drives, SD cards, and external disks before they cross a security perimeter, and verifies that media is clean before leaving. It treats the **media itself as the attack surface**, analyzing hardware descriptors, partition tables, and raw filesystem structures without ever mounting hostile filesystems.

> The crate is published as `ferrix-usb`. Install with `cargo install ferrix-usb`. The executable command is `ferrix`.

---

## Contents

1. [Overview](#1-overview)
2. [Operating Model](#2-operating-model)
3. [Key Capabilities](#3-key-capabilities)
4. [Inspection Layers](#4-inspection-layers)
5. [Hardening & Defense-in-Depth](#5-hardening--defense-in-depth)
6. [Threat Model & Limits](#6-threat-model--limits)
7. [Commands & CLI](#7-commands--cli)
8. [Terminal User Interface (TUI)](#8-terminal-user-interface-tui)
9. [Policy Configuration](#9-policy-configuration)
10. [Two-Station Custody Workflow](#10-two-station-custody-workflow)
11. [Project Layout](#11-project-layout)
12. [License](#12-license)

---

## 1. Overview

Traditional security tools rely on antivirus software that scans files inside mounted filesystems. In an air-gapped or high-security facility, this leaves critical blind spots:

- **BadUSB attacks:** Devices that declare themselves as storage while simultaneously acting as HID keyboards or network adapters.
- **Filesystem driver vulnerabilities:** Hostile, crafted filesystems that exploit the operating system kernel when mounted.
- **Partition anomalies:** Data stashed in unallocated gaps, hidden partition types, or overlapping structures.
- **Residual data leakage:** Remnants of sensitive files remaining in unallocated space or slack areas when media leaves.

`ferrix-usb` runs on a dedicated, offline **checking station**. It parses raw storage structures in userspace, enforces strict default-deny policies, isolates parsing inside Landlock and seccomp sandboxes, and issues cryptographically signed manifests.

---

## 2. Operating Model

`ferrix-usb` operates in two primary modes:

- **Ingress (Incoming Media):** Vets media before it crosses into the secure network. Verifies USB descriptors, hashes every sector into an immutable snapshot, checks partition layouts, parses filesystem structures read-only, scans files for hostile patterns, and issues a signed manifest.
- **Egress (Outgoing Media):** Inspects media before it leaves the secure facility. Scans unallocated sectors for deleted file remnants, computes Shannon entropy to verify forensic wipes, and detects leftover metadata (EXIF, PDF, Office author info).

---

## 3. Key Capabilities

- **Zero Mounting:** Analyzes FAT12/16/32, exFAT, NTFS, and ext2/3/4 filesystems directly from raw block devices or images without mounting.
- **Snapshot-First Scanning:** Reads the device sequentially once into an image, computes a whole-device BLAKE3 hash, and scans only the snapshot to eliminate Time-of-Check to Time-of-Use (TOCTOU) exploits.
- **BadUSB Detection:** Queries USB device and interface descriptors to catch composite devices masquerading as mass storage while providing HID endpoints.
- **Landlock & Seccomp Hardening:** Drops privileges immediately after opening block devices and enters a restricted sandbox with zero network access and limited syscall access.
- **Cryptographic Custody:** Generates Ed25519-signed manifests and maintains a tamper-evident, hash-chained audit log.
- **Interactive TUI & Scriptable CLI:** Ships with a full-featured keyboard-driven TUI alongside deterministic CLI subcommands.

---

## 4. Inspection Layers

| Layer | Checks Performed | Finding ID Prefix | Target Threats |
|---|---|---|---|
| **Device Layer** | Descriptors, composite interfaces (Mass Storage + HID), vendor/product allowlist | `FX-DEV-` | BadUSB, Rubber Ducky, unauthorized hardware |
| **Partition Layer** | MBR/GPT parsing, protective MBR mismatch, overlapping partitions, unallocated gaps | `FX-PART-` | Partition table attacks, hidden partitions, steganography |
| **Filesystem Layer** | FAT/exFAT/NTFS/ext boot records, polyglot filesystems, cluster allocation, duplicate entries | `FX-FS-` | Polyglot disks, filesystem driver exploits, structure tampering |
| **File Layer** | Magic byte vs extension mismatch, autorun triggers, RTLO bidi overrides, zip bombs/traversal, Office macros, PDF JavaScript | `FX-FILE-` | Disguised executables, macro malware, archive traversal, autorun exploits |
| **Egress Layer** | Deleted remnants in unallocated space, wipe pattern verification via Shannon entropy, document metadata | `FX-EGR-` | Data leakage, improper media wipes, sensitive author metadata |

---

## 5. Hardening & Defense-in-Depth

`ferrix-usb` is engineered to parse hostile, adversarial data safely:

1. **Zero Network:** Built without any networking crates or sockets. Enforced by compiler and CI bans.
2. **Fail Closed:** Any parse failure, stage timeout, or unrecognized structure results in `QUARANTINE` or `FAIL`, never `PASS`.
3. **Strict Bounds Checking:** Pure safe Rust without `unwrap()` or `expect()` on untrusted media data.
4. **Least Privilege:** Drops `root` privileges to `nobody` or the calling user immediately after opening device handles.
5. **Seccomp BPF Filtering:** Syscall filter returns `EPERM` on any attempted socket, process execution, or unauthorized syscall.
6. **Landlock Filesystem Sandbox:** Restricts filesystem operations to approved paths only.
7. **Terminal Sanitization:** Strips ANSI escape sequences and escapes Unicode bidirectional overrides (RTLO) before rendering untrusted media filenames in the TUI or terminal.

---

## 6. Threat Model & Limits

`ferrix-usb` is a specialized offline media vetting station, not an antivirus scanner or firmware auditor.

### What it stops:
- Malicious partition tables, overlapping partitions, and hidden sectors.
- Polyglot disk images and hostile filesystem structures.
- BadUSB devices that combine mass storage with HID interfaces.
- Executables disguised as documents, double extensions, and RTLO character tricks.
- Archive directory traversal and zip bombs.
- Leftover sensitive file remnants and incomplete wipes.

### Explicit limits:
- **Host USB Controller Attacks:** Malicious USB devices that exploit kernel-level USB host controllers during hardware enumeration cannot be stopped by userspace software. Use a dedicated, sacrificial offline checking station.
- **Drive Firmware Implants:** Compromised drive microcontrollers (e.g. modified flash controllers) can deceive software.
- **Zero-Day Payloads:** Content heuristics flag risky formats (macros, scripts, JavaScript in PDFs), but `ferrix-usb` is not a signature-based antivirus engine.

Full documentation is available in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## 7. Commands & CLI

### Installation

```bash
cargo install ferrix-usb
```

### Build from Source

```bash
git clone https://github.com/rry0ku/ferrix-usb
cd ferrix-usb
cargo build --release
```

### Command Reference

```bash
# Launch interactive TUI
ferrix

# Ingress scan: inspect media or raw image before crossing into secure network
ferrix scan /dev/sdb
ferrix scan /path/to/disk.raw --out ./reports --json

# Egress scan: verify wipe patterns and check for leftover remnants
ferrix egress /dev/sdb --verify-wipe

# Two-station custody verification against a signed manifest
ferrix verify /dev/sdb --manifest ./reports/scan-manifest.json

# Generate station Ed25519 signing keypair
ferrix keygen --key-dir /etc/ferrix

# Export JSON or HTML report from a previous scan ID
ferrix report scan-1700000000-abcd --html --out ./reports

# List active false-positive suppressions
ferrix triage --list
```

### Exit Codes

- `0` - `PASS` (Clean, meets policy)
- `10` - `QUARANTINE` (Suspicious, unparseable, or requires operator review)
- `20` - `FAIL` (Critical finding or hostile pattern detected)
- `1` - Internal error or invalid arguments

---

## 8. Terminal User Interface (TUI)

Running `ferrix` without arguments in an interactive terminal launches the Ratatui TUI:

1. **Device Selection:** Discovers removable block devices from sysfs and local disk images. Supports manual path entry.
2. **Mode Selection:** Select Ingress or Egress mode and view active policy limits.
3. **Live Monitor:** Asynchronous scanning worker thread streams stage-by-stage progress without blocking the interface.
4. **Results Screen:** Displays the verdict banner (`PASS`, `QUARANTINE`, `FAIL`), severity-badged findings, and detailed evidence panes.
5. **False Positive Triage:** Allows operators to review findings and create scoped, signed 90-day suppressions for approved internal files.
6. **Report Export:** Exports standalone JSON or HTML5 reports directly from the interface.

---

## 9. Policy Configuration

Security policies are defined in YAML. `ferrix-usb` includes a built-in strict default policy, or can load a station policy via `--policy <file>`:

```yaml
name: strict-ingress
allowed_filesystems:
  - fat32
  - exfat
max_partitions: 1
max_file_size_mb: 512
allowed_types:
  - pdf
  - txt
  - png
  - jpg
  - docx
archives:
  max_depth: 3
  max_expansion_ratio: 100
on_high: quarantine
on_critical: fail
```

Policies are default-deny: any filesystem or file type not explicitly listed is blocked. Unknown configuration keys cause the policy parser to fail closed.

---

## 10. Two-Station Custody Workflow

To prevent media tampering or drive swapping between the checking station and the secure network:

1. **Checking Station A:**
   ```bash
   ferrix scan /dev/sdb --out /staging/manifests
   ```
   Computes the full-device BLAKE3 hash, file hashes, and signs the manifest with the station's private key (`station.key`).

2. **Secure Workstation B:**
   ```bash
   ferrix verify /dev/sdb --manifest /staging/manifests/scan-manifest.json
   ```
   Verifies the station signature with `station.pub` and re-hashes `/dev/sdb`. If even a single byte differs, verification fails and the media is rejected.

---

## 11. Project Layout

```
src/
  device/      USB descriptor parsing, sysfs authorization, BadUSB detection
  disk/        raw block access, MBR/GPT parsing, partition anomalies, snapshotting
  fs/          read-only FAT/exFAT/NTFS/ext parsers (zero mounting)
  scan/        content detection, magic vs extension, autorun, archives, macros
  egress/      remnants in unallocated space, Shannon entropy wipe check, metadata
  policy/      YAML policy parser, default-deny evaluation, signature verification
  triage/      scoped false-positive suppressions and audit logging
  manifest/    Ed25519 signing keypair generation and verification
  audit/       hash-chained, tamper-evident JSONL audit log
  report/      machine-readable JSON and standalone HTML5 reports
  sandbox/     Landlock filesystem sandbox, seccomp BPF filters, privilege drop
  tui/         Ratatui terminal UI, async scan worker, sanitized string rendering
  cli.rs       Clap CLI definitions
  main.rs      CLI dispatcher and main entry point
tests/         Integration test suites for all layers (80 tests)
```

---

## 12. License

This project is licensed under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)**. See the [LICENSE](LICENSE) file for details.
