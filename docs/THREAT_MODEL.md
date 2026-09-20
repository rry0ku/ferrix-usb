# Threat Model

This document specifies the threat model for `ferrix-usb`. It defines the trust assumptions, attacker profiles, in-scope attack surfaces, defensive architecture, threat mitigations, and honest limitations of the system.

---

## 1. Executive Summary & Security Philosophy

Traditional removable media security relies on host antivirus scanners operating on mounted filesystems. In high-assurance, defense, critical infrastructure, and air-gapped environments, this model has critical flaws:

1. **Kernel Attack Surface:** Mounting a hostile filesystem requires kernel filesystem drivers to parse complex, untrusted binary metadata with kernel privileges. A single memory corruption or integer overflow bug in kernel filesystem drivers grants ring-0 code execution.
2. **Hardware & Bus Exploits:** Hostile hardware can present itself as a storage device while simultaneously providing a HID keyboard or Ethernet adapter (the BadUSB paradigm).
3. **Time-of-Check to Time-of-Use (TOCTOU):** Adversarial flash controllers or dual-personality devices can return benign data when scanned by an antivirus tool, and serve malicious payloads when accessed by the user.
4. **Remnant & Metadata Leakage:** Simply deleting files from media leaving a secure perimeter leaves recoverable data in unallocated sectors and file slack space.

**`ferrix-usb` treats the media itself as the attack surface.** Removable media is treated as completely untrusted and hostile across every layer: electrical bus descriptors, partition tables, filesystem structures, file metadata, and file content.

---

## 2. Attacker Profiles & Capabilities

| Threat Actor | Motivation | Technical Capabilities | Example Scenarios |
|---|---|---|---|
| **Opportunistic / Commodity** | Financial gain, malware propagation | Standard file malware, double extensions, autorun scripts, macro payloads, zip bombs | Infected commercial thumb drives, disguised executables, macro-laden documents |
| **Malicious Insider / Egress Exfiltration** | Data theft, corporate espionage, sabotage | Intentional data hiding in unallocated space, file slack space, covert metadata | Copying confidential documents to unallocated sectors or metadata fields |
| **Targeted / Advanced Persistent Threat (APT)** | Espionage, air-gap crossing, system compromise | Custom BadUSB hardware, polyglot filesystems, parser differential attacks, TOCTOU flash controllers | Specially crafted partition tables, corrupted filesystem superblocks, dual-personality flash memory |

---

## 3. Threat Vectors & Attack Surface Breakdown

### 3.1 Physical & Bus Layer (USB Subsystem)
- **BadUSB & Composite Device Attacks:** Devices presenting a USB Mass Storage class (`0x08`) alongside Human Interface Device (HID, `0x03`) or Communications/Ethernet (`0x02`, `0x0A`) interfaces. Upon connection, the device attempts to inject keystrokes or hijack network routing.
- **Descriptor Spoofing:** Altered vendor IDs (VID), product IDs (PID), serial numbers, and device descriptors attempting to masquerade as authorized hardware or exploit descriptor parsing.

### 3.2 Partition & Layout Layer
- **MBR / GPT Differential Attacks:** Discrepancies between the Protective MBR and GPT partition arrays, or differences between primary and backup GPT headers.
- **Overlapping & Out-of-Bounds Partitions:** Partition entries specifying overlapping sector ranges or sector addresses extending beyond the physical boundary of the media.
- **Hidden & Unallocated Gaps:** Concealed volumes or data placed in gaps between partitions, in sector space preceding the first partition, or beyond the last partition.

### 3.3 Filesystem Layer
- **Kernel Filesystem Exploits:** Malformed superblocks, B-trees, inode tables, or allocation bitmaps designed to trigger buffer overflows, out-of-bounds reads/writes, or null-pointer dereferences in operating system filesystem drivers.
- **Polyglot Disks:** Regions containing valid signatures for multiple distinct filesystems (e.g. FAT boot sector and ext4 superblock in the same offset), causing the checking station to parse one filesystem while the destination OS mounts another.
- **Structural Inconsistencies:** Mismatched partition size vs. filesystem declared volume size, circular directory links, corrupted FAT cluster chains, or conflicting directory entries.

### 3.4 File & Content Layer
- **Extension vs. Content Spoofing:** Executable binaries (PE, ELF, Mach-O) disguised as harmless files (e.g., `.jpg`, `.pdf`, `.txt`) using deceptive extensions or double extensions (`document.pdf.exe`).
- **Unicode RTLO Exploits:** Filenames utilizing Right-to-Left Override (`U+202E`) characters to visually invert displayed extensions in graphical file managers.
- **Hostile Filenames:** File paths containing terminal escape sequences, control characters, leading dashes (`-`), trailing spaces/dots, or Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`).
- **Archive Traversal & Decompression Bombs:** ZIP/tar archives containing relative path escapes (`../`), absolute paths (`/etc/passwd`), symlink escapes, or extreme compression ratios designed to exhaust disk or memory.
- **Active Document Content:** Office documents with embedded VBA macros, external template links, or executable attachments; PDF files containing embedded JavaScript or launch actions.

### 3.5 Egress & Data Remnant Layer
- **Unallocated Space Remnants:** Files deleted via standard filesystem operations whose content blocks remain intact and readable in unallocated clusters.
- **File Slack Space:** Sector space between the logical end-of-file (EOF) and the physical end of the allocated cluster holding remnants of previous data.
- **Incomplete / Fake Wipes:** Drives claimed to be forensically sanitized that contain non-zero, structured, or unverified sector data.
- **Sensitive Metadata:** Embedded metadata within files (EXIF GPS coordinates, document author names, revision history, corporate paths).

### 3.6 Operational & Transit Layer
- **TOCTOU Read Exploits:** Adversarial microcontroller firmware on the media that detects sequential scanning patterns, serves benign sectors to `ferrix-usb`, and subsequently serves malicious sectors to the receiving station.
- **Transit Tampering & Media Swapping:** Replacing vetted media with uninspected or malicious media between the checking station and the receiving host.
- **Replay Attacks:** Replaying an older, previously approved manifest for a modified or substituted physical device.

---

## 4. Defensive Architecture & Countermeasures

`ferrix-usb` implements defense-in-depth through a multi-tier security architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DEFENSIVE ARCHITECTURE                          │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Universal Automount Defense (Kernel, udev, systemd, Desktop Envs)   │
│ 2. Pre-Authorization Descriptor Inspection (BadUSB Mitigation)         │
│ 3. Privilege Drop, Landlock Filesystem Isolation & Seccomp Syscalls    │
│ 4. Sequential Snapshot-First Read & Full-Device BLAKE3 Hashing         │
│ 5. Pure Userspace Read-Only Parsers (No Kernel Mounts)                 │
│ 6. Default-Deny Content-Based Policy Enforcement                       │
│ 7. Release Hygiene Engine (POSIX Normalization, Path Sanitization)     │
│ 8. Ed25519 Cryptographic Manifests & Tamper-Evident Audit Logging      │
└────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Universal Automount Defense
To guarantee that the host operating system never invokes kernel filesystem drivers on uninspected media:
- **Kernel USB Core:** Sets `/sys/bus/usb/devices/usb*/authorized_default = 0`. New devices are detected but blocked from driver binding or block device creation until explicitly vetted.
- **Ephemeral udev Rules:** Drops `/run/udev/rules.d/99-ferrix-no-automount.rules` setting `UDISKS_AUTO="0"` and `UDISKS_IGNORE="1"`.
- **systemd Runtime Masking:** Temporarily masks and stops `udisks2` and `autofs` during checking station operations.
- **Desktop Environment Hardening:** Disables automounting across all major desktop environments (GNOME, KDE Plasma 5/6, XFCE/Thunar, Cinnamon, MATE, LXQt, LXDE).

### 4.2 Snapshot-First Scanning (TOCTOU Defense)
- When media is authorized for inspection, `ferrix-usb` reads the physical device sequentially **exactly once** into an immutable, read-only snapshot image file on the station.
- Simultaneously, a streaming BLAKE3 cryptographic hash is calculated over every byte of the raw device.
- All subsequent inspection stages (partition, filesystem, file, egress) and file release operations execute **exclusively on the snapshot image**.
- The physical device is never read a second time during analysis, completely neutralizing TOCTOU dual-personality flash controller attacks.

### 4.3 Userspace-Only Read-Only Parsers (Zero Kernel Mounts)
- `ferrix-usb` contains custom, pure userspace parsers for partition tables (MBR, GPT) and filesystems (FAT12, FAT16, FAT32, exFAT, NTFS, ext2, ext3, ext4).
- The Linux kernel `mount` syscall is never invoked during inspection.
- All parsers are hardened against malformed, circular, truncated, or adversarial structures, returning structured findings rather than panicking or crashing.

### 4.4 Privilege Separation & Sandboxing
- Elevated privileges are utilized exclusively to open the initial block device and query sysfs descriptors.
- Immediately after acquiring the necessary file descriptors, `ferrix-usb` drops root privileges to an unprivileged user.
- The process enters a restricted sandbox utilizing **Landlock** (restricting filesystem access strictly to the snapshot and output directories) and **seccomp** (blocking networking syscalls, kernel module operations, and dangerous primitives).

### 4.5 Release Hygiene Engine
When media passes inspection and files are released to a destination staging area:
- Files are extracted from the verified snapshot image only.
- Metadata and permissions are normalized: regular files to `0644`, directories to `0755`.
- Extended attributes (`xattrs`), POSIX ACLs, capabilities, setuid, setgid, and sticky bits are stripped.
- Symlinks, hardlinks, character/block devices, FIFOs, and sockets are refused.
- File paths are sanitized: control characters, terminal escape sequences, RTLO overrides, leading dashes, trailing dots/spaces, and Windows reserved names are escaped or rejected.

### 4.6 Cryptographic Custody & Anti-Replay
- Scan results are encoded into an Ed25519-signed cryptographic manifest containing:
  - Station ID and public key
  - Unique 128-bit random nonce
  - Issue timestamp and expiration timestamp
  - Full-device BLAKE3 hash and byte length
  - Partition layout hash
  - Per-file relative paths and BLAKE3 hashes
  - Policy hash and mandatory stage completion statuses
- The receiving station runs `ferrix verify` on the media against the signed manifest. Any change to any sector or file fails verification.
- Verified nonces are recorded in an append-only station log to prevent replay attacks.

---

## 5. Threat Mitigation Matrix

| Threat Category | Finding ID | Severity | Defensive Countermeasure |
|---|---|---|---|
| Composite BadUSB Device | `FX-DEV-001` | Critical | Descriptors checked before authorization; unauthorized interfaces rejected |
| Device Not in Allowlist | `FX-DEV-002` | High | Policy-based VID/PID/serial verification |
| Partition Table Anomaly | `FX-PART-001` | High | MBR/GPT validation; overlapping or out-of-bounds partitions rejected |
| Protective MBR Mismatch | `FX-PART-002` | High | Detection of MBR/GPT discrepancies |
| Unallocated Disk Data | `FX-PART-003` | Medium/High | Detection of non-zero data hidden in partition gaps |
| Filesystem Structure Tampering | `FX-FS-001` | High/Critical | Userspace parsing of boot sectors, cluster maps, and superblock headers |
| Polyglot Filesystem | `FX-FS-002` | Critical | Detection of multiple valid filesystem signatures in identical or overlapping offsets |
| Extension vs Magic Mismatch | `FX-FILE-001` | High | Content magic bytes compared against extension; executable disguised as doc blocked |
| Autorun Payload | `FX-FILE-002` | High | Detection of `autorun.inf`, `.desktop`, `.lnk`, and autorun targets |
| Unicode RTLO / Control Characters | `FX-FILE-003` | High | Detection of `U+202E` and ASCII/Unicode control characters in filenames |
| Archive Traversal / Zip Bomb | `FX-FILE-004` | High/Critical | Path traversal (`../`), symlink escapes, and expansion ratios inspected before extraction |
| Office Macro / PDF JavaScript | `FX-FILE-005` | High | OLE/VBA macro detection; PDF `/JavaScript` and `/Launch` action detection |
| Egress Unallocated Remnants | `FX-EGR-001` | Medium/High | Sector-level scanning for recoverable deleted files |
| Incomplete Media Wipe | `FX-EGR-002` | High | Shannon entropy and zero-block verification across all media sectors |
| Embedded File Metadata | `FX-EGR-003` | Low/Medium | Detection and stripping of EXIF, author, and revision metadata |

---

## 6. Honest Limits & Out-of-Scope Risks

No software running on a host CPU can fully mitigate all hardware-level or physics-level attacks. `ferrix-usb` explicitly documents the following boundaries:

### 6.1 Kernel USB Stack Enumeration Exploits
- **Limitation:** When a physical USB device is inserted, the host USB controller and kernel USB core perform low-level hardware enumeration (packet negotiation, descriptor retrieval) before userspace can inspect descriptors.
- **Risk:** Malicious USB devices engineered to exploit vulnerabilities in host USB controller drivers (xHCI/ehCI) or kernel USB core parsing can compromise the kernel before `ferrix-usb` executes.
- **Mitigation:**
  - Run `ferrix-usb` strictly on a dedicated, offline, **sacrificial checking station** that is isolated from the secure network.
  - Employ hardware USB data blockers, optical USB isolators, or hardware-enforced USB firewalls between the media and the checking station.

### 6.2 Drive Controller & Microcontroller Firmware Implants
- **Limitation:** USB flash drives and external SSDs contain internal microcontrollers executing proprietary firmware that manages the Flash Translation Layer (FTL), bad-block management, and wear leveling.
- **Risk:** Malicious firmware implants (e.g., modified FTL) can conceal data in reserved NAND flash blocks, intercept read/write commands, or execute unauthorized operations beneath the block device abstraction.
- **Mitigation:** Physical security policies requiring destruction or hardware-level analysis of suspect media; pairing `ferrix-usb` with strict hardware allowlists (vendor/product/serial).

### 6.3 Signature-Based Antivirus Coverage
- **Limitation:** `ferrix-usb` is an architectural, structural, and policy-enforcement vetting station. It is **not** a traditional antivirus engine.
- **Risk:** Novel or zero-day file-level payloads that adhere strictly to allowed file formats (e.g., a pure PDF without JavaScript or an authorized binary) will not be flagged as malware by heuristics alone.
- **Mitigation:** Strict default-deny policy (allowing only vetted types like plain text or sanitized images), station-level YARA rule scanning, and downstream analysis on the receiving host.

### 6.4 Electrical & Physical Destruction (USB Killer)
- **Limitation:** High-voltage surge devices ("USB Killers") store power from the 5V USB bus and discharge high-voltage negative pulses into the data lines.
- **Risk:** Permanent physical destruction of host checking station hardware.
- **Mitigation:** Physical inspection of connectors, optoisolated USB hubs, and replaceable surge-protected host ports.

---

## 7. Operational Guidelines for Checking Stations

To maintain the security guarantees outlined in this threat model, checking stations must observe the following rules:

1. **Station Dedication:** The checking station must be a dedicated, standalone machine running an immutable live Linux environment (e.g. read-only root filesystem on RAM).
2. **Strict Air-Gap:** The checking station must have all network interfaces (Ethernet, Wi-Fi, Bluetooth) physically removed, disabled in firmware, or disabled at the kernel level.
3. **Key Security:** Station Ed25519 signing private keys (`station.key`) must remain exclusively on the checking station with restricted file permissions (`0400`). Only the public key (`station.pub`) is distributed to receiving workstations.
4. **Policy Integrity:** Station policies (`--policy`) must be signed with the station key and verified prior to scan execution. Policies must never be loaded from the media under inspection.
5. **Fail-Closed Handling:** Any media triggering a `QUARANTINE` or `FAIL` verdict must be physically removed and quarantined according to organizational security policy. Never attempt to force release on failed media.
