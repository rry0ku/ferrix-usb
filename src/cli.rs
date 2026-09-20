use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

pub const EXIT_PASS: i32 = 0;
pub const EXIT_QUARANTINE: i32 = 10;
pub const EXIT_FAIL: i32 = 20;
pub const EXIT_INTERNAL_ERROR: i32 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "ferrix",
    author,
    version,
    about = "Offline vetting and verification tool for removable media",
    long_about = "ferrix inspects USB drives, SD cards, and external disks at the physical, partition, filesystem, and file layers without trusting or mounting the media.\n\nAll inspection runs offline on a dedicated checking station with automount disabled and zero network access.\n\nPrivileges: Inspecting physical block devices (/dev/sdX) and managing USB device authorization in sysfs requires elevated privileges. Run with 'sudo ferrix ...' for hardware operations. ferrix opens necessary handles and immediately drops privileges to a restricted sandbox before parsing any untrusted data.",
    after_help = "Exit codes:\n  0   PASS: media passed all checks and policy rules\n  10  QUARANTINE: suspicious findings or non-critical anomalies detected\n  20  FAIL: critical threats, BadUSB, or structural violations detected\n  1   Internal error or missing required arguments\n\nRun 'sudo ferrix <command> --help' for command-specific options and examples."
)]
pub struct Cli {
    #[arg(
        short = 'p',
        long,
        global = true,
        help = "Policy file to enforce (must be signed by station key)",
        long_help = "Path to a YAML policy file to enforce. In production, policy files must be accompanied by an Ed25519 signature (.sig) signed by an authorized station key. If omitted, the strict built-in default policy is enforced."
    )]
    pub policy: Option<PathBuf>,

    #[arg(
        short = 'j',
        long,
        global = true,
        help = "Output results as JSON",
        long_help = "Output findings, scan progress, and manifests in structured JSON format instead of human-readable text. Suitable for machine parsing and automated pipelines."
    )]
    pub json: bool,

    #[arg(
        short = 'o',
        long,
        global = true,
        help = "Output directory for reports, manifests, or staged files",
        long_help = "Directory where generated manifests, scan reports, snapshots, and released staging files will be stored. Created automatically if it does not exist."
    )]
    pub out: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Disable TUI and run non-interactively",
        long_help = "Force non-interactive CLI mode. Useful for scripts, CI environments, or headless servers."
    )]
    pub no_tui: bool,

    #[arg(
        short = 'v',
        long,
        global = true,
        help = "Enable verbose output with detailed stage progress",
        long_help = "Print detailed diagnostics and stage-by-stage progress information to standard output."
    )]
    pub verbose: bool,

    #[arg(
        short = 'q',
        long,
        global = true,
        help = "Suppress non-essential informational messages and banners",
        long_help = "Suppress non-essential messages, banners, and progress bars. Only warnings, errors, and final verdicts will be displayed."
    )]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        about = "Ingress scan: inspect media before crossing into the secure side",
        long_about = "Ingress scan creates a read-only snapshot of the target device, hashes every sector with BLAKE3, and scans the physical layout, partition tables (MBR/GPT), filesystem structures (FAT, exFAT, NTFS, ext4), and individual files for threats and anomalies.\n\nFiles are never read directly from the live device after snapshot creation.\n\nNote: Scanning physical block devices (e.g. /dev/sdb) requires elevated privileges ('sudo ferrix scan /dev/sdb').",
        after_help = "Examples:\n  sudo ferrix scan /dev/sdb\n  sudo ferrix scan /dev/sdb --release --out /mnt/staging\n  ferrix scan disk.img --json\n  sudo ferrix scan /dev/sdb --policy /etc/ferrix/strict.yaml"
    )]
    Scan(ScanArgs),

    #[command(
        about = "Egress checks: check for deleted remnants, verify wipe, and detect metadata",
        long_about = "Egress scan inspects media leaving the secure side to ensure no confidential data or identifying metadata is leaked.\n\nChecks for deleted file remnants in unallocated space and slack space, verifies secure disk wiping (zeroed or random blocks), and detects/strips sensitive document/image metadata.\n\nNote: Checking physical block devices or verifying disk wipes requires elevated privileges ('sudo ferrix egress /dev/sdb').",
        after_help = "Examples:\n  sudo ferrix egress /dev/sdb\n  sudo ferrix egress /dev/sdb --verify-wipe\n  sudo ferrix egress /dev/sdb --strip-metadata"
    )]
    Egress(EgressArgs),

    #[command(
        about = "Verify media against a previously generated signed manifest",
        long_about = "Verifies removable media against an Ed25519-signed manifest generated by an ingress checking station.\n\nRe-computes the BLAKE3 full-device hash, partition layout hash, and file checksums. Detects swaps, tampering, or transit alterations.\n\nNote: Verifying raw block devices requires elevated privileges ('sudo ferrix verify /dev/sdb --manifest manifest.json').",
        after_help = "Examples:\n  sudo ferrix verify /dev/sdb --manifest manifest.json\n  sudo ferrix verify /dev/sdb --manifest manifest.json --pubkey station.pub\n  ferrix verify disk.img --manifest manifest.json"
    )]
    Verify(VerifyArgs),

    #[command(
        about = "Generate station Ed25519 signing keypair",
        long_about = "Generates a new Ed25519 keypair for signing manifests and policies on this checking station.\n\nCreates 'station.key' (private key with 0600 permissions) and 'station.pub' (public key). The public key should be distributed to receiving machines.",
        after_help = "Examples:\n  ferrix keygen\n  ferrix keygen --key-dir /etc/ferrix\n  ferrix keygen --force"
    )]
    Keygen(KeygenArgs),

    #[command(
        about = "Export JSON or HTML report for a scan ID",
        long_about = "Generates a formatted scan report from a manifest or audit log entry.\n\nSupports structured JSON for automated pipelines and self-contained HTML reports for operators and compliance archives.",
        after_help = "Examples:\n  ferrix report manifest.json\n  ferrix report manifest.json --html --out /var/reports/scan.html"
    )]
    Report(ReportArgs),

    #[command(
        about = "Review findings, propose and list scoped suppressions",
        long_about = "Manage operator-approved suppressions for known false positives.\n\nSuppressions are scoped strictly by exact BLAKE3 file hash or rule ID and path pattern. Wildcard-only patterns and Critical findings (e.g. BadUSB) cannot be suppressed. All additions are cryptographically signed and logged to the audit chain.",
        after_help = "Examples:\n  ferrix triage --list\n  ferrix triage --add --hash <blake3_hex> --reason \"Approved vendor diagnostic binary\"\n  ferrix triage --add --rule FX-FILE-004 --path-pattern \"*.log\" --reason \"Expected debug logs\" --days 30"
    )]
    Triage(TriageArgs),

    #[command(
        about = "Hotplug watch mode: monitor and vet newly inserted USB storage devices",
        long_about = "Monitors USB bus events offline via sysfs (/sys/bus/usb/devices/) while default authorization is locked (authorized_default=0).\n\nInspects device descriptors for BadUSB patterns (storage + HID keyboard) before authorizing. Clean storage devices are authorized with their block device set to read-only.\n\nNote: Managing USB authorization in sysfs and setting block devices read-only requires elevated privileges ('sudo ferrix watch').",
        after_help = "Examples:\n  sudo ferrix watch\n  sudo ferrix watch --auto-scan\n  sudo ferrix watch --auto-scan --interval 1"
    )]
    Watch(WatchArgs),

    #[command(
        about = "Mount an external media partition safely",
        long_about = "Mounts an externally connected partition (e.g. /dev/sdb1) to a designated mount point. By default, media is mounted read-only with 'ro,nodev,nosuid,noexec' to prevent execution of untrusted binaries.\n\nNote: Primary host OS and internal drives are strictly refused. Mounting requires elevated privileges ('sudo ferrix mount ...').",
        after_help = "Examples:\n  sudo ferrix mount /dev/sdb1\n  sudo ferrix mount /dev/sdb1 /mnt/usb\n  sudo ferrix mount /dev/sdb1 /mnt/usb --rw"
    )]
    Mount(MountArgs),

    #[command(
        about = "Restore system USB automount defaults and services",
        long_about = "Restores system-wide USB automount defaults: reloads udev rules, removes any temporary automount blocks, unmasks and restarts udisks2 and autofs, resets USB controller authorizations, and re-enables desktop environment automounting.",
        after_help = "Examples:\n  sudo ferrix restore"
    )]
    Restore,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[arg(
        help = "Path to block device (e.g. /dev/sdb) or raw disk image file",
        long_help = "Path to the target block device (e.g. /dev/sdb, /dev/nvme0n1) or raw disk image file (.img, .bin, .raw). Physical block devices require elevated privileges (run with 'sudo'). The target is inspected read-only through a sequentially generated station snapshot."
    )]
    pub device: PathBuf,

    #[arg(
        short = 'r',
        long,
        help = "Release verified files from snapshot to staging folder on PASS",
        long_help = "Automatically extract verified files from the read-only snapshot into the output staging folder if the final scan verdict is PASS. Normalizes permissions to 0644/0755 and sanitizes filenames."
    )]
    pub release: bool,

    #[arg(
        long,
        default_value = "512",
        help = "Sector size in bytes (e.g. 512, 4096)",
        long_help = "Logical sector size of the media in bytes. Defaults to 512 bytes."
    )]
    pub sector_size: u32,

    #[arg(
        long,
        help = "Path to custom YARA rules file or directory",
        long_help = "Path to a .yar/.yara rule file or directory containing YARA rules to match against scanned files."
    )]
    pub yara: Option<PathBuf>,

    #[arg(
        long,
        help = "Enable ClamAV antivirus inspection via local socket or clamscan",
        long_help = "Enable local offline ClamAV inspection through clamd Unix domain socket or local clamscan CLI."
    )]
    pub clamav: bool,

    #[arg(
        long,
        help = "Path to local clamd Unix domain socket",
        long_help = "Path to the clamd Unix domain socket (e.g. /run/clamav/clamd.ctl)."
    )]
    pub clamav_socket: Option<String>,

    #[arg(
        long,
        help = "Enable deep file carving on unallocated and raw space",
        long_help = "Scan unallocated sectors and raw disk space to carve hidden files (JPEG, PNG, PDF, ZIP, ELF, PE, SQLite)."
    )]
    pub carve: bool,

    #[arg(
        long,
        help = "Use a disposable, ephemeral memory-backed inspection environment",
        long_help = "Acquire and inspect media in an ephemeral, memory-backed workspace that is cryptographically wiped upon exit."
    )]
    pub disposable: bool,

    #[arg(
        long,
        help = "Generate a reproducible forensic evidence bundle in the output directory",
        long_help = "Create an evidence/ directory containing device.json, partitions.json, files.json, findings.json, manifest.json, and manifest.sig."
    )]
    pub bundle: bool,
}

#[derive(Args, Debug)]
pub struct EgressArgs {
    #[arg(
        help = "Path to block device or disk image file",
        long_help = "Path to the removable media being prepared for egress across the security boundary. Physical block devices require elevated privileges (run with 'sudo')."
    )]
    pub device: PathBuf,

    #[arg(
        short = 'w',
        long,
        help = "Verify wipe patterns (blocks must be zeroed or random)",
        long_help = "Scan unallocated space and partition blocks to ensure media has been securely wiped with all zeros or cryptographic random patterns."
    )]
    pub verify_wipe: bool,

    #[arg(
        short = 's',
        long,
        help = "Detect and strip metadata from files",
        long_help = "Inspect files for identifying metadata (EXIF in images, author/revisions in Office/PDF documents) and strip or flag them."
    )]
    pub strip_metadata: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(
        help = "Path to block device, disk image, or signed report.json file",
        long_help = "Path to the target device, disk image, or standalone signed report.json file to verify. If a report.json is provided, verifies its station signature directly."
    )]
    pub target: PathBuf,

    #[arg(
        short = 'm',
        long,
        help = "Path to signed manifest file to verify against",
        long_help = "Path to the manifest.json file containing the Ed25519 signature, BLAKE3 device hash, partition layout hash, and file checksums."
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        short = 'k',
        long,
        help = "Path to station public key (station.pub)",
        long_help = "Path to the station Ed25519 public key file used to verify the manifest or report digital signature. Defaults to looking in the manifest's directory or the current directory."
    )]
    pub pubkey: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    #[arg(
        short = 'd',
        long,
        help = "Directory to write keypair (defaults to station config directory)",
        long_help = "Directory where station.key (private signing key) and station.pub (public verification key) will be generated."
    )]
    pub key_dir: Option<PathBuf>,

    #[arg(
        short = 'f',
        long,
        help = "Force overwrite of existing station keypair",
        long_help = "Overwrite existing station.key and station.pub if they already exist in the target directory."
    )]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    #[arg(
        help = "Scan ID or path to scan manifest/audit log",
        long_help = "Scan ID or path to the manifest.json / audit.jsonl log to generate a report for."
    )]
    pub scan_id: String,

    #[arg(
        long,
        help = "Output report in HTML format instead of default JSON",
        long_help = "Generate a self-contained, offline HTML report with styled findings tables and integrity hashes."
    )]
    pub html: bool,

    #[arg(
        long,
        help = "Generate a reproducible forensic evidence bundle in the output directory",
        long_help = "Create an evidence/ directory containing device.json, partitions.json, files.json, findings.json, manifest.json, and manifest.sig."
    )]
    pub bundle: bool,
}

#[derive(Args, Debug)]
pub struct TriageArgs {
    #[arg(
        short = 'l',
        long,
        help = "List all active suppressions and their expiration dates",
        long_help = "Display all currently active suppressions stored in suppressions.json, including rule IDs, path patterns, hashes, reasons, authors, and expiration dates."
    )]
    pub list: bool,

    #[arg(
        short = 'a',
        long,
        help = "Add a new suppression (requires --rule, --path-pattern or --hash, --reason)",
        long_help = "Add an operator-approved scoped suppression. Must be scoped by exact file BLAKE3 hash (--hash) or rule ID and path pattern (--rule and --path-pattern). Requires a written reason (--reason)."
    )]
    pub add: bool,

    #[arg(
        short = 'r',
        long,
        help = "Rule ID to suppress (e.g. FX-FILE-004)",
        long_help = "Specific rule ID to suppress. Cannot be used to suppress Critical findings such as BadUSB (FX-DEV-001) or structural ambiguity."
    )]
    pub rule: Option<String>,

    #[arg(
        short = 'P',
        long,
        help = "Path pattern to suppress (e.g. *.log, docs/*)",
        long_help = "File path pattern to match for suppression. Wildcard-only patterns ('*', '**', '/*') are strictly rejected."
    )]
    pub path_pattern: Option<String>,

    #[arg(
        short = 'H',
        long,
        help = "Exact file BLAKE3 hash to suppress (64 hex characters)",
        long_help = "64-character hexadecimal BLAKE3 hash of the specific file to suppress. Recommended for narrowest possible scoping."
    )]
    pub hash: Option<String>,

    #[arg(
        short = 'm',
        long,
        help = "Written justification for suppression",
        long_help = "Mandatory human-readable explanation explaining why this finding is safe to suppress. Recorded in the audit log."
    )]
    pub reason: Option<String>,

    #[arg(
        short = 'd',
        long,
        default_value = "90",
        help = "Suppression duration in days (default: 90)",
        long_help = "Number of days until the suppression expires. Suppressions cannot be permanent."
    )]
    pub days: u64,
}

#[derive(Args, Debug)]
pub struct WatchArgs {
    #[arg(
        short = 'a',
        long,
        help = "Automatically trigger scan when clean storage device is authorized",
        long_help = "Immediately run an ingress scan upon authorizing a newly inserted clean mass storage device."
    )]
    pub auto_scan: bool,

    #[arg(
        short = 'i',
        long,
        default_value = "2",
        help = "Polling interval in seconds",
        long_help = "Frequency in seconds at which the watcher inspects /sys/bus/usb/devices/ for newly inserted media."
    )]
    pub interval: u64,
}

#[derive(Args, Debug, Clone)]
pub struct MountArgs {
    #[arg(
        help = "Path to block device or partition to mount (e.g. /dev/sdb1)",
        long_help = "Path to the externally connected block device or partition (e.g. /dev/sdb1). Primary host OS drives and internal drives are strictly refused."
    )]
    pub device: PathBuf,

    #[arg(
        help = "Destination mount directory (defaults to /media/<user>/<dev> or /mnt/<dev>)",
        long_help = "Target directory where the media will be mounted. Created automatically if it does not exist. Defaults to /media/<user>/<dev> if running under sudo or /mnt/<dev>."
    )]
    pub mountpoint: Option<PathBuf>,

    #[arg(
        long,
        help = "Mount read-write instead of the secure read-only default (ro,nodev,nosuid,noexec)",
        long_help = "Mount the filesystem with read-write permissions ('rw,nodev,nosuid'). By default, ferrix mounts read-only ('ro,nodev,nosuid,noexec') to protect the system."
    )]
    pub rw: bool,
}
