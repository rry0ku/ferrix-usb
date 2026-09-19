# Threat Model

This document outlines the threat model for `ferrix-usb`, defining what is in scope, what is out of scope, and the honest physical and architectural limits of the software.

## In Scope

`ferrix-usb` is designed to detect, isolate, and mitigate threats arriving on removable media:

- **BadUSB and Composite Devices:** Devices presenting unauthorized USB interfaces (e.g., storage plus HID keyboard).
- **Hostile Partition Tables:** Malformed MBR or GPT headers, overlapping partitions, partitions exceeding device bounds, and hidden partitions.
- **Hostile Filesystem Structures:** Corrupted, malformed, or ambiguous filesystems designed to exploit kernel filesystem parsers.
- **Malicious Files and Archives:** Autorun payloads (`autorun.inf`, `.desktop`, `.lnk`), magic byte vs. extension mismatches, double extensions, Unicode RTLO (Right-to-Left Override) obfuscation, archive path traversal, zip bombs, and malicious macros.
- **Hidden Data and Remnants:** Data hidden in unallocated space, slack space, and partition gaps.
- **Egress Data Leakage:** Residual data on media leaving the perimeter, incomplete wipes, and sensitive embedded file metadata (EXIF, Office author info).

## Honest Limits

Software cannot solve every hardware- or firmware-level security challenge. The following limits are explicitly acknowledged:

1. **Kernel USB Stack Attacks During Enumeration:**
   Software running in userspace cannot fully stop a malicious device from attacking the Linux kernel USB subsystem during initial physical enumeration.
   *Mitigation:* Run `ferrix-usb` strictly on a dedicated, offline, sacrificial checking station with `authorized_default=0`, and optionally employ a hardware USB data blocker.

2. **Not an Antivirus Engine:**
   `ferrix-usb` is not a full-featured antivirus engine. It inspects structural anomalies, policy compliance, and high-risk file patterns rather than maintaining signatures for every known malware family.

3. **Controller Firmware-Level Implants:**
   Firmware-level implants inside the USB drive microcontroller (e.g. modified flash translation layer / FTL) are largely invisible to software inspection.

## Principles of Defense

- **Never trust the media:** All sector data is treated as adversarial.
- **No kernel mounting:** Block devices are parsed read-only in userspace without kernel filesystem drivers.
- **Least privilege and sandboxing:** Device file descriptors are opened with minimal privileges, dropped immediately, and isolated via Landlock and seccomp.
- **Snapshot-first scanning:** Scans and releases operate strictly on an immutable station snapshot to prevent Time-of-Check to Time-of-Use (TOCTOU) attacks.
- **Fail closed:** Any structural ambiguity, parse failure, or missing required stage produces `QUARANTINE` or `FAIL`.
