# AGENTS.md

Instructions for AI coding agents working on this repo. Read fully before making changes.

> Project name: **ferrix-usb**
> Crate name: `ferrix-usb` (the `ferrix` crate name is already taken on crates.io)
> CLI binary: `ferrix`

## 1. What this is

ferrix-usb is an offline tool that vets removable media (USB drives, SD cards, external disks) before it crosses a security boundary, and checks media is clean before it leaves.

Core idea: treat the **media itself** as the attack surface, not just the files on it. Most tools are antivirus wrappers that scan files. ferrix-usb inspects the device, the partition layout, the filesystem structures, and then the files, without ever trusting the drive.

Two modes:

- **Ingress:** is this media safe to bring into the secure side?
- **Egress:** is this media free of leftover data and metadata before it goes out?

## 2. How it works (operating model)

ferrix-usb runs on a dedicated offline **checking station**, never on the secure network itself.

### 2.1 Station setup (one time)

- ferrix-usb runs from a live USB on an offline Linux machine.
- **Automount is disabled.** If the OS auto-mounts a drive, a filesystem driver has already parsed hostile data before ferrix-usb runs.
- USB devices default to **not authorized** (`authorized_default=0` in sysfs), so the kernel does not bind drivers to a new device until ferrix-usb approves it.
- A signing key is generated with `ferrix keygen` and kept on the station. The public key is distributed to receiving machines.

### 2.2 Ingress flow (user plugs in a drive)

1. **Detect.** ferrix-usb sees the new device via local udev hotplug events (no network). MVP alternative: the user picks the device manually. The TUI shows vendor, serial, and size.
2. **Device check.** While the device is still unauthorized, read its USB descriptors from sysfs. Flag composite devices (storage plus HID keyboard is the BadUSB pattern). Flagged devices are never authorized.
3. **Authorize storage only.** If descriptors are clean, authorize only the mass storage interface and set the block device read-only at the kernel level (`blockdev --setro` equivalent), so nothing can write to it.
4. **Open, then drop privileges.** Open the raw block device file descriptor while privileged, then drop privileges and enter the sandbox (Landlock plus seccomp). Parsing runs on that fd only.
5. **Snapshot, then scan in stages, no mounting.** Read the device once into a read-only image on the station while hashing every sector, then scan that image only: partition table, partition anomalies, filesystem structures, file layer. Progress and findings stream to the UI. See section 9.
6. **Verdict.** `PASS`, `QUARANTINE`, or `FAIL`, with a findings list. ferrix-usb signs a manifest and appends to the audit log.
7. **Release.** On `PASS` the user chooses: copy verified files out of the snapshot (never from the live drive) to a staging folder, or mount the snapshot read-only with `ro,nodev,nosuid,noexec`. On `QUARANTINE` or `FAIL`, nothing is released.

### 2.3 Egress flow (drive is leaving)

Same pipeline in reverse: check for remnants of deleted files in unallocated and slack space, verify any wipe (blocks are zeroed or random), detect and optionally strip metadata (EXIF, Office author info). Any write to the media requires an explicit typed confirmation.

### 2.4 Two-station manifest flow

1. Station A scans the media and produces a **signed manifest**.
2. The secure-side machine runs `ferrix verify` on the same media against that manifest before trusting anything.
3. If the media differs from the manifest in any way, verification fails. This stops swaps and tampering in transit.

### 2.5 Privileges

ferrix-usb needs elevated rights only to read block devices and change sysfs authorization. Keep the privileged section as small as possible: open fds, then drop. Never run parsers with elevated rights.

## 3. Threat model summary

**In scope:** malicious or compromised USB media, hostile partition tables and filesystems, malicious files and archives, BadUSB-style devices, hidden data, data leakage through leftover remnants and metadata.

**Honest limits (must be stated in `docs/THREAT_MODEL.md`):**

- Software cannot fully stop a malicious device attacking the kernel USB stack during enumeration. Mitigation is physical: use a sacrificial checking station and optionally a hardware USB data blocker.
- ferrix-usb does not detect every malware family. It is not an antivirus engine.
- Firmware-level implants on the drive controller are largely invisible to software.

## 4. Non-negotiable principles

1. **Never trust the media.** All input is hostile. Every parser assumes malformed, adversarial data.
2. **Never mount to inspect.** Filesystem drivers are attack surface. Parse raw block devices read-only. Mounting is only allowed for the final release step, with `ro,nodev,nosuid,noexec`.
3. **Zero network.** No network calls, no telemetry, no update checks, no networking crates. If a dependency pulls in networking, reject it.
4. **Read-only by default.** ferrix-usb never writes to media under inspection. Only the egress wipe-verify path may write, behind an explicit confirmation.
5. **Single static binary.** Must run from a live USB on an offline machine with no install step. Prefer musl builds.
6. **Fail closed.** Unknown, unparseable, or ambiguous means `QUARANTINE` or `FAIL`, never `PASS`.
7. **Sandbox our own parsers.** Landlock and seccomp on parsing code paths. A security tool must harden itself.
8. **Least privilege.** Drop privileges right after opening the device fd.
9. **Snapshot first.** Scan and release from a read-only snapshot, never from the live drive.
10. **Precise, not noisy.** Do not flag safe files. Cut false positives with context and evidence, never by lowering detection. Learning is operator-approved and scoped, never automatic from scanned media (section 10).
11. **Continuous vulnerability defense.** Actively look for vulnerabilities and fix them all whenever changes are made. Continuously audit all modified and surrounding code paths for security weaknesses, including unchecked input, bounds violations, command and flag injection, privilege escalation, parser vulnerabilities, panics on malformed data, and TOCTOU races. Never leave an identified vulnerability unpatched.

## 5. Commands

```
ferrix                     launch TUI (default in an interactive terminal)
ferrix scan <device>       ingress scan, prints verdict and findings
ferrix egress <device>     egress checks (remnants, wipe verify, metadata)
ferrix verify <device> --manifest <file>   verify media against a signed manifest
ferrix keygen              generate station signing keypair
ferrix report <scan-id>    export JSON or HTML report
ferrix triage              review findings, propose and list scoped suppressions
ferrix watch               hotplug watch mode (post-MVP)
```

Common flags: `--policy <file>`, `--json`, `--out <dir>`, `--no-tui`.
Exit codes: `0` PASS, `10` QUARANTINE, `20` FAIL, `1` internal error (treated as not-pass by callers).

## 6. Stack

- Language: **Rust** (stable). No `unsafe` unless justified in a comment stating the invariant.
- Target: Linux first. Other platforms are out of scope.
- Likely crates: `mbrman` or `gpt`, `goblin`, `zip`, `yara-x`, `ed25519-dalek`, `blake3`, `serde`, `clap`, `ratatui`, `crossterm`, `landlock`, `seccompiler`, `thiserror`. Check any new crate for network code and maintenance status before adding.
- Test sample build scripts may use Python. The shipped tool must not.

**Packaging:** the crate is published as `ferrix-usb`, but the installed command is `ferrix`. Keep this in `Cargo.toml`:

```toml
[package]
name = "ferrix-usb"

[[bin]]
name = "ferrix"
path = "src/main.rs"
```

Install with `cargo install ferrix-usb`, run with `ferrix`. Never rename the binary to `ferrix-usb`. Release binaries and command examples always use `ferrix`.

## 7. Repo layout

```
src/
  device/      USB descriptor reading, authorization, BadUSB pattern detection
  disk/        raw block access, MBR/GPT parsing, partition anomaly detection
  fs/          read-only filesystem parsing (FAT/exFAT/NTFS/ext), no mounting
  scan/        file layer checks (autorun, magic vs extension, archives, macros, symlinks)
  egress/      remnant scan, wipe verification, metadata detection
  policy/      YAML policy loading and evaluation
  triage/      scoped suppressions, trust store, false-positive review
  manifest/    signed manifest generation and verification
  audit/       hash-chained, tamper-evident audit log
  report/      JSON and HTML report output
  sandbox/     Landlock and seccomp setup, privilege drop
  tui/         ratatui frontend (screens, widgets, event loop), no scanning logic
  cli.rs       clap commands, non-interactive mode
  main.rs
tests/
  samples/     scripted malicious disk images, plus clean/ for safe ones (see Testing)
  bypass/      evasion attempts that CI must always catch (see section 9)
fuzz/          cargo-fuzz targets for every parser
docs/
  THREAT_MODEL.md
```

## 8. Core design

The scanner is a pipeline of stages. Each stage takes the opened device and returns findings.

- `Stage` trait: `fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError>`. `Stage::run` returns the final `Result<Vec<Finding>, StageError>`, and the verdict uses only that.
- `ScanContext` provides an `EventSink` (channel sender) for live progress and finding events. The TUI reads events for live display but never decides the verdict.
- `Finding`: `id` (e.g. `FX-PART-003`), `severity`, `confidence`, `stage`, `location` (partition, path, or byte offset), `reason` (one line), `evidence` (what was seen, e.g. offset and bytes or the rule that matched).
- `Severity`: `Info`, `Low`, `Medium`, `High`, `Critical`.
- `Location`: `Device`, `Partition(u32)`, `Path(MediaPath)`, `ByteOffset(u64)`. `MediaPath` wraps raw bytes, because filenames on media are not guaranteed to be UTF-8. Its `Display` and serde output must escape control characters, terminal escape sequences, and bidi overrides.
- Finding ID prefixes: `FX-DEV-`, `FX-PART-`, `FX-FS-`, `FX-FILE-`, `FX-EGR-`.
- Stages never panic on media data. A stage error becomes a finding and pushes the verdict toward `QUARANTINE`.
- The core is a library crate. CLI and TUI are both thin frontends over it.

**Default verdict rules (policy can override):**

- Any `Critical` finding: `FAIL`
- Any `High` finding, or any stage error: `QUARANTINE`
- Only `Medium` or below: `PASS` with warnings, unless policy is stricter

## 9. Hardening requirements

Goal: no silent bypass. Every evasion attempt must either be caught or cause a visible `QUARANTINE` or `FAIL`. All of this is userspace Rust. No kernel code, no USB hardware work. Items marked **MVP** ship first.

### 9.1 Snapshot-first scanning (MVP)

- Read the device once, sequentially, into an image file on the station. After writing, set it read-only.
- All stages scan the snapshot only. Release copies files out of the snapshot only. The live device is not read again.
- Why: a drive can show clean data during the scan and different data at copy time (TOCTOU). Scanning a snapshot removes that gap.
- Optional at release: re-hash the live device and warn if it differs from the snapshot.
- Test: a harness that serves different bytes on a second read must not change the verdict or the released files.

### 9.2 Full-device hash (MVP)

- Compute BLAKE3 over every sector while taking the snapshot. Store `device_hash` and `device_size_bytes` in the manifest.
- `verify` recomputes it. Any change anywhere, including unallocated and hidden areas, fails verification.
- This hash is the real binding to the media. Device serials can be spoofed, so never rely on them alone.

### 9.3 Mandatory stages (MVP)

- The manifest lists `stages_required` and `stages_completed`, each with a status.
- `PASS` is valid only if every required stage completed with status ok.
- A skipped, crashed, timed out, or disabled stage means `QUARANTINE` at minimum.
- Core stages (snapshot and hash, partition, filesystem, file layer) cannot be removed by policy.
- Test: force each stage to error. The verdict must never be `PASS`.

### 9.4 Default-deny policy (MVP)

- Allowlist filesystems, file types, and devices. Anything not listed is blocked.
- File types are decided by detected content (magic bytes), never by extension.
- The policy file is signed with Ed25519 and verified before use. An unsigned or invalid policy is refused, and the strict built-in default is used with a visible warning.
- Policy, rules, and config are loaded only from the station, never from the media being scanned.
- The policy hash is recorded in the manifest.

### 9.5 Parser differential defense (post-MVP)

Attackers build layouts that ferrix-usb reads one way and the target OS reads another. Parse strictly and treat ambiguity as a finding (`High`), never as a guess. Do not silently repair structures. Cases to detect:

- MBR and GPT disagreement, primary and backup GPT mismatch
- Overlapping partitions, partitions extending past the device end
- Filesystem size that does not match its partition size
- Multiple valid filesystem signatures in one region (polyglot images)
- Inconsistent FAT, exFAT, or NTFS boot sector fields
- Duplicate or conflicting directory entries

Every case gets a sample image in `tests/samples/` and a matching entry in `tests/bypass/`.

### 9.6 Manifest anti-replay (post-MVP)

- Each manifest carries a random 128-bit nonce, station ID, `issued_at`, and `expires_at` (default set by policy).
- `verify` rejects: invalid signature, unknown station key, expired manifest, device hash mismatch, and any nonce it has already accepted.
- The verifier keeps a local append-only log of accepted nonces. Each manifest is accepted once by default.

### 9.7 Release hygiene (post-MVP)

When copying files out of the snapshot:

- Strip xattrs, ACLs, capabilities, and setuid, setgid, and sticky bits.
- Normalize modes to `0644` for files and `0755` for directories. No exec bit unless policy allows it.
- Refuse and flag device nodes, FIFOs, and sockets.
- Never follow symlinks. Use `openat` style copying with `O_NOFOLLOW`, confined to the staging root. No `..` in resolved paths.
- Rename or reject hostile filenames: control characters, bidi overrides (RTLO), leading dashes, trailing dots or spaces, Windows reserved names, over-long names, non-UTF-8 names.
- Record every rename in the report, showing the original name escaped.

### 9.8 Supply chain hardening (post-MVP)

- Commit `Cargo.lock`. Vendor dependencies for release builds.
- Pin the exact toolchain version in `rust-toolchain.toml`, not "stable". Reproducible builds require a fixed toolchain. Network access only happens when rustup installs the toolchain on the dev or CI machine. Principle 3 applies to the shipped binary, which must contain no network code. CI installs the pinned toolchain explicitly.
- CI runs `cargo-deny` (advisories, licenses, and a ban list that blocks network crates), `cargo-audit`, and `cargo-vet` for new dependencies.
- Reproducible builds: fixed toolchain, `SOURCE_DATE_EPOCH`, documented build steps so others can rebuild and compare hashes.
- Signed release tags, signed checksums, and a CycloneDX SBOM attached to every release.

## 10. Accuracy: do not flag safe files

Goal: operators must be able to trust a finding. Noise trains people to ignore the tool, and an ignored tool is a bypass. Ferrix must tell safe files from risky ones, and must never do it by relaxing its checks.

### 10.1 Evidence-based findings (MVP)

- Every finding needs a concrete reason and evidence: which rule matched, where, and what was seen.
- No `High` or `Critical` finding from a weak heuristic alone. Those severities require strong evidence or several correlated signals.
- Wording matters. Separate "blocked by policy" (a valid file that is not allowed) from "suspicious" (something looks malicious). An executable that policy does not allow is not the same as malware.

### 10.2 Context-aware rules (MVP)

Detect the real file type by content first, then apply checks that make sense for that type. Examples of what must not be flagged:

- **Extension vs content:** `.jpeg` vs `.jpg`, or a `.txt` that is plain UTF-8. Flag a mismatch only when it changes the risk class, such as a `.jpg` that is really a PE executable.
- **Office documents:** a plain `.docx` with no macros, no external links, and no embedded executables is `Info` at most.
- **PDFs:** flag JavaScript, launch actions, and embedded files. A plain PDF passes.
- **Archives:** flag path traversal, symlink escapes, and abnormal expansion ratio or depth. A normal zip passes.
- **Hidden files:** a dotfile alone is `Info`. Flag it only when combined with other signals, such as an autorun trigger.
- **OS artifacts:** `System Volume Information`, `$RECYCLE.BIN`, `.Trashes`, `.fseventsd`, `lost+found` and similar are recognized as expected. Still scan their contents. Flag only if the contents are anomalous.
- **Non-ASCII filenames:** Hindi, Punjabi, Chinese, Arabic, and other legitimate scripts are normal. Flag only bidi overrides, control characters, and risky look-alike characters in dangerous positions.

### 10.3 Confidence and correlation (MVP)

- Every finding has a `confidence` (`Low`, `Medium`, `High`) next to its `severity`.
- One weak signal stays at `Info` or `Low`. Several independent signals on the same object raise severity. Example: hidden file, plus autorun reference, plus executable content.
- `Info` findings never change the verdict. They are counted separately in reports.

**Fail closed still wins.** Precision applies to detection heuristics only. Parse errors, structural ambiguity (section 9.5), stage failures (section 9.3), and hash mismatches are never softened by confidence scoring or suppressions.

### 10.4 Learning: operator-approved and scoped (post-MVP)

Ferrix improves over time through controlled feedback, not through self-training.

**Never learn automatically from scanned media.** An attacker could otherwise teach the tool to trust their payload with a series of crafted drives. No baseline, model, or allowlist is ever updated from data on the media being scanned.

Two sources of knowledge:

1. **Shipped knowledge:** built-in rules and lists, versioned and signed with each release.
2. **Station trust store:** entries an operator approves, stored on the station only.

**False positive triage flow** (`ferrix triage` or the TUI):

1. The operator marks a finding as a false positive.
2. Ferrix proposes a suppression with the narrowest scope possible, preferring the exact BLAKE3 hash of the file. Otherwise it uses rule ID plus path pattern plus device.
3. A written reason is required, and the operator confirms by typing.
4. The suppression is signed with the station key, given an expiry (default 90 days), and appended to the audit log.

**Hard limits on suppressions:**

- Cannot suppress `Critical` findings.
- Cannot suppress stage errors, parse errors, ambiguity findings, or hash and manifest failures.
- Wildcard-only scopes are rejected.
- Suppressed findings still appear in the report as "suppressed", with reason, author, and suppression ID. They are never hidden.
- The suppression store is loaded from the station only, never from media.
- `ferrix triage list` shows all active suppressions and their expiry dates.

**Known-good hash allowlist (optional):** a signed list of approved file hashes, such as internal tools or standard documents. A match skips content heuristics for that file. The file is still recorded in the manifest and still subject to the type policy.

**Statistical or ML classifiers (optional, later):** advisory only. They may adjust `confidence`. They must be offline, deterministic, and shipped as a versioned model inside the signed release. They can never downgrade a `High` or `Critical` rule finding and can never produce a `PASS` on their own.

### 10.5 Measuring accuracy (MVP)

- Maintain `tests/samples/clean/` (see Testing rules). Every reported false positive becomes a new clean image plus a fix to the rule.
- Prefer fixing the rule over adding a suppression. A suppression is a local workaround. A rule fix helps every user.
- CI gates: all clean images pass with nothing above `Info`, and every `tests/bypass/` case still fails with a sample set of active suppressions loaded. Suppressions must never mask an evasion test.

## 11. Checks in scope

**Device layer:** composite devices (storage plus HID), descriptor anomalies, vendor/product/serial allowlist.

**Partition and filesystem layer:** hidden partitions, unallocated gaps containing data, protective MBR mismatch, overlapping partitions, unexpected filesystems.

**File layer:** `autorun.inf`, `.desktop`, `.lnk`, hidden files, extension vs magic byte mismatch, double extensions, Unicode RTLO tricks, symlinks escaping the media, archive path traversal, zip bombs, Office macros, PDFs with JavaScript, NTFS alternate data streams, optional offline YARA rules.

**Manifest and custody:** signed manifest, hash-chained audit log, re-verification on the receiving side.

**Egress:** remnants in unallocated and slack space, wipe verification, metadata detection and stripping.

## 12. Policy file

YAML, loaded from `--policy`. Example:

```yaml
name: default-ingress
allowed_filesystems: [exfat, fat32]
max_partitions: 1
max_file_size_mb: 512
allowed_devices:
  - vendor: "0781"
    product: "5581"
allowed_types: [pdf, txt, png, jpg, docx]   # matched by detected content, not extension
archives:
  max_depth: 3
  max_expansion_ratio: 100
on_high: quarantine
on_critical: fail
```

Unknown keys are an error. A missing policy means the strict built-in default. Policy is default-deny and must be signed (see section 9.4).

## 13. Manifest and audit log

**Manifest (JSON, signed with Ed25519):** ferrix-usb version, station ID, nonce, issued and expiry timestamps, device identity (vendor, product, serial), full-device BLAKE3 hash and size, partition layout hash, per-file BLAKE3 hashes and paths, policy hash, required and completed stages with status, verdict, signature.

**Audit log:** append-only JSONL. Each entry contains the hash of the previous entry, so any edit or deletion breaks the chain. `ferrix` can verify the chain.

Output must be deterministic for the same input so reports can be diffed and signed.

## 14. TUI

The TUI is the default interface when run with no subcommand in an interactive terminal. The CLI stays fully functional for scripting and CI.

**Rules:**

- Thin frontend. All scanning, policy, and signing logic lives in the core library. No security decisions in UI code.
- Anything doable in the TUI must be doable via CLI flags.
- Scans run on a worker thread and stream progress over a channel. The UI never blocks.
- Fail closed in the UI: never show green until the verdict is final. Errors and partial scans show as `QUARANTINE` or `FAIL`.
- Destructive actions need an explicit typed confirmation.
- Render untrusted strings safely. Filenames from media can contain escape sequences, RTLO characters, and control codes. Sanitize before drawing, or the TUI becomes an attack vector.
- Works over plain TTY and SSH, 16 colors minimum, usable monochrome fallback.
- Keyboard only, key hints in a footer, vim-style keys plus arrows.

**Screens:**

1. Device select: detected removable media with vendor, serial, size, device flags.
2. Mode select: ingress or egress, policy choice.
3. Scan: live progress by stage, findings streaming in.
4. Results: verdict banner, findings sorted by severity, detail pane. `Info` findings are collapsed by default. A finding can be marked as a false positive, which opens the triage flow (section 10.4).
5. Report: export JSON or HTML, sign manifest, view audit log.

**Look:** minimal and purposeful. Green pass, yellow quarantine, red fail. Whitespace over decoration. No animation beyond a progress bar.

## 15. Out of scope

- Network scanning or any online feature
- Being a full antivirus engine
- Windows or macOS support (for now)
- GUI of any kind (CLI and TUI only)
- Defending against firmware-level or USB-stack kernel attacks in software

## 16. Testing rules

- Every check needs a sample image that triggers it and a clean image that does not.
- Sample images are built by script (`tests/samples/build.py`), kept small, and not committed as opaque blobs where avoidable.
- Sample targets: hidden partition, autorun payload, zip bomb, path traversal archive, RTLO filename, slack-space remnants, fake composite-device descriptor, symlink escape.
- Every parser gets a `cargo-fuzz` target. Fuzzing crashes become regression tests.
- CI runs the full sample set. A check without a test does not merge.
- TUI rendering is tested with ratatui `TestBackend`, including a filename with escape sequences and RTLO characters to confirm sanitization.
- `tests/bypass/` holds evasion attempts (parser differentials, drives that return different data on re-read, forced stage crashes, replayed or expired manifests, hostile filenames on release). CI must fail if any of them ever produces a `PASS`.
- `tests/samples/clean/` holds clean images that look like real media: office documents, photos, PDFs, normal zips, code repos, non-English filenames, and OS artifacts from Windows, macOS, and Linux formatted drives. Every clean image must produce `PASS` with nothing above `Info`. CI fails on any regression.
- Never test against real malware. Use inert synthetic payloads (EICAR-style markers).

## 17. Code conventions

- `cargo fmt` and `cargo clippy -- -D warnings` must pass.
- `thiserror` in libraries, `anyhow` only in `main`.
- No `unwrap()` or `expect()` on data derived from media. Malformed input returns an error, never a panic.
- Bounds-check every offset and length read from media. Assume integer overflow attempts.
- Small functions named for what they detect, e.g. `detect_hidden_partition`.
- Comments explain why a check exists and which attack it stops, not what the code does.

## 18. Output and docs style

- CLI output is minimal and scannable: verdict first, findings after, sorted by severity.
- Every finding shows ID, severity, location, and a one-line reason.
- Docs are plain and direct. No marketing language, no filler, no em dashes.
- `docs/THREAT_MODEL.md` states what ferrix-usb catches and what it does not.
- The README must include one line near the top: "Not to be confused with the `ferrix` crate. Install this tool with `cargo install ferrix-usb`."

## 19. Agent working rules

- Before adding a feature, check it is listed in section 11. If not, ask.
- Do not add dependencies without stating why and confirming they have no network or telemetry code.
- Prefer small, reviewable changes: one check or one module at a time.
- When a design choice affects security (mounting, parsing, sandboxing, privileges), explain the tradeoff in the change description.
- If a requirement conflicts with a principle in section 4, stop and flag it instead of working around it.
- Do not skip tests to make progress. No check ships without its sample image.
- Never weaken or bypass a requirement in section 9 for convenience. If one blocks progress, flag it.
- Every new check ships with a clean sample test and a note on its false positive risk. Fix noisy rules by making them more precise, not by suppressing them.
- **Actively look for vulnerabilities and fix them all whenever changes are made.** Every code modification must include an active security audit of all touched and surrounding code paths. Remediate all discovered vulnerabilities immediately across the entire codebase.

## 20. Roadmap

**MVP (build first):** `ferrix scan /dev/sdX` on a raw device or image file. Snapshot-first scanning, full-device hash, mandatory stages, default-deny signed policy (sections 9.1 to 9.4). Partition parsing, partition anomaly checks, FAT/exFAT reading, core file checks with context-aware rules and a clean sample set (sections 10.1 to 10.3 and 10.5), verdicts, JSON report. No hotplug, no authorization control.

1. **Week 1:** raw device reading, MBR/GPT parsing, partition anomaly detection, first sample images.
2. **Week 2:** filesystem and file layer checks, policy engine, verdict logic.
3. **Week 3:** manifest signing and verification, audit log, JSON and HTML reports.
4. **Week 4:** egress checks, sandbox and privilege drop, fuzzing, docs, release binary.
5. **Week 5:** TUI (device select, scan progress, results, report). Start a skeleton earlier once the core API is stable.

**Post-MVP:** hardening 9.5 to 9.8 (parser differential defense, manifest anti-replay, release hygiene, supply chain), triage and scoped suppressions (section 10.4), hotplug watch mode, USB authorization control, station hardening guide, YARA integration, demo GIF and write-up.
