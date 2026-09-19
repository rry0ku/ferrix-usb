# ferrix-usb

**Check a USB drive before it crosses the air gap.**

ferrix-usb is an offline tool that inspects USB drives, SD cards, and external disks and tells you whether they are safe to plug into a sensitive computer. It looks at the drive itself, not just the files on it, and it never trusts what the drive says about itself.

> Not to be confused with the `ferrix` crate. Install this tool with `cargo install ferrix-usb`. The command you run is `ferrix`.

> **Status: early development.** The project structure and the verdict logic exist. The scanning features listed below are planned and are being built in order. See [Status and roadmap](#10-status-and-roadmap) for what works today.

---

## Contents

1. [What is this?](#1-what-is-this)
2. [Why does it exist?](#2-why-does-it-exist)
3. [What does it do?](#3-what-does-it-do)
4. [What it checks](#4-what-it-checks)
5. [How it works](#5-how-it-works)
6. [Verdicts](#6-verdicts)
7. [Why you can trust the tool](#7-why-you-can-trust-the-tool)
8. [What it cannot stop](#8-what-it-cannot-stop)
9. [Usage](#9-usage)
10. [Status and roadmap](#10-status-and-roadmap)
11. [Project layout](#11-project-layout)
12. [Contributing and security](#12-contributing-and-security)
13. [License](#13-license)

---

## 1. What is this?

Think of it as **airport security for USB drives**.

Before a passenger boards a plane, they go through a checkpoint. ferrix-usb is that checkpoint for removable storage. You plug a drive into a separate, offline "checking station". The tool inspects it, gives a clear answer (safe, suspicious, or unsafe), and only then does anything from the drive move on.

It works in two directions:

- **Ingress (coming in):** is this drive safe to bring into the secure side?
- **Egress (going out):** is this drive clean of leftover data before it leaves?

## 2. Why does it exist?

Some networks are deliberately cut off from the internet. These are called **air-gapped** networks, and they are used in defence, critical infrastructure, and research. The idea is that if there is no connection, nothing can get in or out.

The weak point is the USB drive. People carry files across the gap by hand, and a drive can carry more than files:

- A drive that pretends to be a keyboard and types attack commands the moment it is plugged in.
- Hidden partitions holding malware or stolen data that the operating system does not show.
- Files disguised as harmless documents, or shortcuts that run a hidden program.
- Deleted secrets that are still recoverable from the drive.

Real attacks have used exactly these tricks to cross air gaps. Most existing tools are antivirus scanners that only look at files. ferrix-usb treats the **whole drive** as the thing to inspect.

## 3. What does it do?

In plain steps:

1. **Detects** the drive and reads what kind of device it claims to be.
2. **Makes a read-only copy (snapshot)** of the drive and fingerprints every sector.
3. **Inspects the copy** in layers: device, partitions, filesystem, then files.
4. **Gives a verdict:** `PASS`, `QUARANTINE`, or `FAIL`, with the reasons.
5. **Signs a report** so the result cannot be quietly changed later.
6. **Releases files** from the verified copy only if the verdict allows it.

Everything happens offline. The tool has no network code at all.

## 4. What it checks

| Layer | What it looks for | Example attack it stops |
|---|---|---|
| **Device** | A "storage" drive that also acts as a keyboard, unapproved vendors or serial numbers | BadUSB, Rubber Ducky style drives |
| **Partitions** | Hidden partitions, data in unused gaps, overlapping or contradictory layouts | Malware stashed where the OS does not look |
| **Filesystem** | Unexpected filesystems, inconsistent structures, alternate data streams | A drive claiming to be one thing but built as another |
| **Files** | Autorun tricks, disguised executables, macros, scripts, dangerous archives, symlink escapes, hostile filenames | `invoice.pdf.exe`, zip bombs, path traversal |
| **Tampering** | Any change to the drive after it was scanned | Swapping the drive in transit |
| **Egress** | Leftover deleted data, metadata in files, failed wipes | Leaking secrets on a "clean" drive |

**It tries not to cry wolf.** A plain document, a normal PDF, or a filename in Hindi or Punjabi is not flagged. Findings must come with evidence, and noisy rules get fixed instead of ignored.

## 5. How it works

```
   Drive plugged in
         |
         v
  [ Device check ]      Is it really just storage?
         |
         v
  [ Snapshot + hash ]   Read once, make a read-only copy,
         |              fingerprint every sector
         v
  [ Partition scan ]    Hidden or contradictory layouts?
         |
         v
  [ Filesystem scan ]   Parsed directly, never mounted
         |
         v
  [ File scan ]         Risky files, archives, names
         |
         v
  [ Policy + verdict ]  PASS / QUARANTINE / FAIL
         |
         v
  [ Signed manifest ]   Tamper-evident record
         |
         v
  Files released from the verified copy (only on PASS)
```

**Two-station option.** Station A scans the drive and produces a signed manifest. The secure-side computer runs `ferrix verify` on the same drive against that manifest. If even one byte differs, verification fails.

## 6. Verdicts

| Verdict | Meaning | Exit code | What happens |
|---|---|---|---|
| `PASS` | Every required check completed and nothing serious was found | `0` | Files can be released |
| `QUARANTINE` | Something serious or uncertain was found, or a check could not finish | `10` | Nothing is released, a human reviews it |
| `FAIL` | A critical problem was found | `20` | Nothing is released |
| Error | The tool itself hit a problem | `1` | Treated as not safe |

The rule underneath: **when in doubt, it does not pass.** A crash, a skipped check, or a file the tool cannot understand can never produce a `PASS`.

## 7. Why you can trust the tool

A security tool that parses hostile data must itself be hard to attack. These are hard rules for the project:

- **Never mounts the drive to inspect it.** Filesystem drivers are attack surface, so ferrix-usb reads the raw data and parses it itself.
- **Scans a snapshot, not the live drive.** A drive cannot show clean data during the scan and different data at copy time.
- **Zero network.** No telemetry, no update checks, no network libraries. Enforced in CI.
- **Read-only by default.** It does not write to the drive under inspection.
- **Fails closed.** Unknown or unreadable means "not safe".
- **Sandboxed and least privilege.** It opens the device, then drops privileges before parsing.
- **Written in Rust**, with no `unwrap` on data from the drive and fuzz testing for every parser.
- **Supply chain checks.** Pinned toolchain, vendored dependencies, `cargo-deny`, and signed releases.
- **No silent bypass.** A test suite of evasion attempts must always be caught.

Learning from mistakes is controlled. False alarms are handled by an operator-approved, signed, expiring exception on one exact file. The tool never teaches itself from the drives it scans, because an attacker could use that to train it to trust malware.

## 8. What it cannot stop

Being honest about limits is part of the design.

- **Attacks on the computer's USB driver itself.** A malicious device can attack the host before any software runs. Use a sacrificial, offline checking station that you can reboot or reimage, and consider a hardware barrier.
- **Malicious drive firmware.** A compromised drive controller can lie to software. Ferrix reduces the risk but cannot see inside the chip.
- **Brand new malware with no known pattern.** It is not an antivirus engine.
- **Bugs in the programs you later open files with.**
- **Insiders who copy real secrets on purpose.** It checks media, not intent.
- **Physical attacks**, such as a USB killer device or an implanted cable.
- **Attacks that do not involve removable media**, such as phishing or network intrusion.

The full write-up is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## 9. Usage

> The commands below are the planned interface. Most are not implemented yet.

```
ferrix                          Launch the terminal interface (TUI)
ferrix scan <device|image>      Check a drive coming in
ferrix egress <device|image>    Check a drive going out
ferrix verify <device> --manifest <file>
                                Verify a drive against a signed manifest
ferrix keygen                   Create this station's signing key
ferrix report <scan-id>         Export a JSON or HTML report
ferrix triage                   Review findings and manage exceptions
ferrix watch                    Watch for new drives (later)
```

Useful flags: `--policy <file>`, `--json`, `--out <dir>`, `--no-tui`.

**Install (once published):**

```
cargo install ferrix-usb
```

**Build from source:**

```
git clone https://github.com/corvainx/ferrix-usb
cd ferrix-usb
cargo build --release
```

**Terminal interface.** Running `ferrix` with no arguments opens a keyboard-driven TUI with five screens: pick a device, pick a mode, watch the scan, read the results, export the report. It works over SSH and on a plain terminal. There is no graphical (GUI) version.

**Policy file.** A signed YAML file decides what is allowed. Anything not listed is blocked.

```yaml
name: default-ingress
allowed_filesystems: [exfat, fat32]
max_partitions: 1
max_file_size_mb: 512
allowed_types: [pdf, txt, png, jpg, docx]   # matched by content, not extension
archives:
  max_depth: 3
  max_expansion_ratio: 100
on_high: quarantine
on_critical: fail
```

## 10. Status and roadmap

**Done**
- [x] Project scaffold: crate, modules, CLI stubs, CI
- [x] Core types and verdict logic with tests (an error or skipped check can never pass)
- [x] Supply chain ban list for network crates

**Next (MVP)**
- [ ] Snapshot and full-device hash
- [ ] Partition parsing and anomaly checks
- [ ] FAT and exFAT reading, core file checks
- [ ] Default-deny signed policy
- [ ] JSON report
- [ ] Sample images: malicious set and a clean set that must never be flagged

**After that**
- [ ] Signed manifests and tamper-evident audit log
- [ ] Egress checks (leftovers, metadata, wipe verification)
- [ ] Sandboxing and privilege drop
- [ ] Terminal interface
- [ ] Parser differential defence, manifest replay protection, safe file release
- [ ] Triage and scoped exceptions
- [ ] Hotplug watch mode, USB authorization control
- [ ] Fuzzing, docs, release binaries, write-up

Development starts with disk image files, not real drives. It is faster, safer, and easy to test.

## 11. Project layout

```
src/
  device/      USB descriptors, BadUSB pattern detection
  disk/        raw reading, partition parsing
  fs/          read-only filesystem parsing
  scan/        file layer checks
  egress/      leftover data, wipe verification, metadata
  policy/      policy loading and evaluation
  triage/      false-positive review and exceptions
  manifest/    signed manifests and verification
  audit/       tamper-evident audit log
  report/      JSON and HTML reports
  sandbox/     sandbox setup and privilege drop
  tui/         terminal interface (display only, no security logic)
  cli.rs       command-line interface
tests/
  samples/     scripted malicious disk images
  samples/clean/  safe images that must never be flagged
  bypass/      evasion attempts that must always be caught
fuzz/          fuzz targets for every parser
docs/          threat model and design notes
AGENTS.md      rules for AI coding agents working on this repo
```

## 12. Contributing and security

- Read [`AGENTS.md`](AGENTS.md). It is the project's rulebook and applies to human contributors too.
- Every new check needs a malicious sample that triggers it and a clean sample that must not.
- Run before opening a pull request: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
- No new dependency without a stated reason. Anything with network code is rejected.
- **Found a vulnerability in ferrix-usb?** Please report it privately through GitHub Security Advisories on this repository instead of opening a public issue.

## 13. License

GPL-3.0-or-later. You are free to use, study, and modify this tool. If you distribute a modified version, you must share your changes under the same license.
