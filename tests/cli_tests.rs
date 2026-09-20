use clap::Parser;
use ferrix_usb::cli::{Cli, Commands};
use std::path::PathBuf;

#[test]
fn test_cli_help_flag() {
    let res = Cli::try_parse_from(["ferrix", "--help"]);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    let output = err.to_string();
    assert!(output.contains("ferrix"));
    assert!(output.contains("Exit codes:"));
    assert!(output.contains("PASS"));
    assert!(output.contains("QUARANTINE"));
    assert!(output.contains("FAIL"));
}

#[test]
fn test_cli_scan_args_parsing() {
    let cli = Cli::try_parse_from([
        "ferrix",
        "scan",
        "/dev/sdb",
        "-r",
        "-o",
        "/staging",
        "--sector-size",
        "4096",
    ])
    .unwrap();

    assert_eq!(cli.out, Some(PathBuf::from("/staging")));
    match cli.command {
        Some(Commands::Scan(args)) => {
            assert_eq!(args.device, PathBuf::from("/dev/sdb"));
            assert!(args.release);
            assert_eq!(args.sector_size, 4096);
        }
        _ => panic!("expected Scan command"),
    }
}

#[test]
fn test_cli_verify_args_parsing() {
    let cli = Cli::try_parse_from([
        "ferrix",
        "verify",
        "/dev/sdb",
        "-m",
        "manifest.json",
        "-k",
        "station.pub",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Verify(args)) => {
            assert_eq!(args.device, PathBuf::from("/dev/sdb"));
            assert_eq!(args.manifest, PathBuf::from("manifest.json"));
            assert_eq!(args.pubkey, Some(PathBuf::from("station.pub")));
        }
        _ => panic!("expected Verify command"),
    }
}

#[test]
fn test_cli_triage_args_parsing() {
    let cli_list = Cli::try_parse_from(["ferrix", "triage", "-l"]).unwrap();
    match cli_list.command {
        Some(Commands::Triage(args)) => {
            assert!(args.list);
            assert!(!args.add);
        }
        _ => panic!("expected Triage command"),
    }

    let cli_add_hash = Cli::try_parse_from([
        "ferrix",
        "triage",
        "-a",
        "-H",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "-m",
        "vendor binary",
        "-d",
        "45",
    ])
    .unwrap();
    match cli_add_hash.command {
        Some(Commands::Triage(args)) => {
            assert!(args.add);
            assert_eq!(
                args.hash,
                Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
                )
            );
            assert_eq!(args.reason, Some("vendor binary".to_string()));
            assert_eq!(args.days, 45);
        }
        _ => panic!("expected Triage command"),
    }

    let cli_add_rule = Cli::try_parse_from([
        "ferrix",
        "triage",
        "-a",
        "-r",
        "FX-FILE-004",
        "-P",
        "*.log",
        "-m",
        "debug log",
    ])
    .unwrap();
    match cli_add_rule.command {
        Some(Commands::Triage(args)) => {
            assert!(args.add);
            assert_eq!(args.rule, Some("FX-FILE-004".to_string()));
            assert_eq!(args.path_pattern, Some("*.log".to_string()));
            assert_eq!(args.reason, Some("debug log".to_string()));
        }
        _ => panic!("expected Triage command"),
    }
}

#[test]
fn test_cli_egress_and_keygen_parsing() {
    let cli_egress = Cli::try_parse_from(["ferrix", "egress", "/dev/sdb", "-w", "-s"]).unwrap();
    match cli_egress.command {
        Some(Commands::Egress(args)) => {
            assert_eq!(args.device, PathBuf::from("/dev/sdb"));
            assert!(args.verify_wipe);
            assert!(args.strip_metadata);
        }
        _ => panic!("expected Egress command"),
    }

    let cli_keygen = Cli::try_parse_from(["ferrix", "keygen", "-d", "/etc/ferrix", "-f"]).unwrap();
    match cli_keygen.command {
        Some(Commands::Keygen(args)) => {
            assert_eq!(args.key_dir, Some(PathBuf::from("/etc/ferrix")));
            assert!(args.force);
        }
        _ => panic!("expected Keygen command"),
    }

    let cli_watch = Cli::try_parse_from(["ferrix", "watch", "-a", "-i", "5"]).unwrap();
    match cli_watch.command {
        Some(Commands::Watch(args)) => {
            assert!(args.auto_scan);
            assert_eq!(args.interval, 5);
        }
        _ => panic!("expected Watch command"),
    }
}
