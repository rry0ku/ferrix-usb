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
    long_about = "ferrix inspects USB drives, SD cards, and external disks at the physical, partition, filesystem, and file layers without trusting or mounting the media."
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Policy file to enforce (must be signed by station key)"
    )]
    pub policy: Option<PathBuf>,

    #[arg(long, global = true, help = "Output results as JSON")]
    pub json: bool,

    #[arg(
        long,
        global = true,
        help = "Output directory for reports, manifests, or staged files"
    )]
    pub out: Option<PathBuf>,

    #[arg(long, global = true, help = "Disable TUI and run non-interactively")]
    pub no_tui: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Ingress scan: inspect media before crossing into the secure side")]
    Scan(ScanArgs),

    #[command(
        about = "Egress checks: check for deleted remnants, verify wipe, and detect metadata"
    )]
    Egress(EgressArgs),

    #[command(about = "Verify media against a previously generated signed manifest")]
    Verify(VerifyArgs),

    #[command(about = "Generate station Ed25519 signing keypair")]
    Keygen(KeygenArgs),

    #[command(about = "Export JSON or HTML report for a scan ID")]
    Report(ReportArgs),

    #[command(about = "Review findings, propose and list scoped suppressions")]
    Triage(TriageArgs),

    #[command(about = "Hotplug watch mode (post-MVP)")]
    Watch(WatchArgs),
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[arg(help = "Path to block device (e.g. /dev/sdb) or raw disk image file")]
    pub device: PathBuf,
}

#[derive(Args, Debug)]
pub struct EgressArgs {
    #[arg(help = "Path to block device or disk image file")]
    pub device: PathBuf,

    #[arg(long, help = "Verify wipe patterns (blocks must be zeroed or random)")]
    pub verify_wipe: bool,

    #[arg(long, help = "Detect and strip metadata from files")]
    pub strip_metadata: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(help = "Path to block device or disk image file")]
    pub device: PathBuf,

    #[arg(long, help = "Path to signed manifest file to verify against")]
    pub manifest: PathBuf,
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    #[arg(
        long,
        help = "Directory to write keypair (defaults to station config directory)"
    )]
    pub key_dir: Option<PathBuf>,

    #[arg(long, help = "Force overwrite of existing station keypair")]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    #[arg(help = "Scan ID or path to scan manifest/audit log")]
    pub scan_id: String,

    #[arg(long, help = "Output report in HTML format instead of default JSON")]
    pub html: bool,
}

#[derive(Args, Debug)]
pub struct TriageArgs {
    #[arg(long, help = "List all active suppressions and their expiration dates")]
    pub list: bool,
}

#[derive(Args, Debug)]
pub struct WatchArgs {}
