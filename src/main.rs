use clap::Parser;
use ferrix_usb::cli::{Cli, Commands, EXIT_FAIL, EXIT_INTERNAL_ERROR, EXIT_PASS};
use ferrix_usb::manifest::{
    compute_layout_hash, generate_nonce, hash_discovered_files, load_station_signing_key,
    load_station_verifying_key, Manifest,
};
use ferrix_usb::Stage;
use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let args = Cli::parse();

    match args.command {
        None => {
            if args.no_tui {
                eprintln!("Error: no command specified and --no-tui was requested");
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }
            match ferrix_usb::tui::run_tui() {
                Ok(_) => ExitCode::from(EXIT_PASS as u8),
                Err(e) => {
                    eprintln!("TUI error: {e}");
                    ExitCode::from(EXIT_INTERNAL_ERROR as u8)
                }
            }
        }
        Some(Commands::Scan(scan_args)) => {
            if !scan_args.device.exists() {
                eprintln!(
                    "Error: target '{}' does not exist",
                    scan_args.device.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            let mut ctx = ferrix_usb::core::ScanContext::new(scan_args.device.clone());
            let (policy, warning) = ferrix_usb::policy::load_policy(args.policy.as_deref(), None);
            if let Some(warn) = warning {
                eprintln!("{warn}");
            }

            let is_block_device = {
                use std::os::unix::fs::FileTypeExt;
                scan_args.device.starts_with("/dev/")
                    || scan_args
                        .device
                        .metadata()
                        .map(|m| m.file_type().is_block_device())
                        .unwrap_or(false)
            };

            let temp_snapshot_path = if is_block_device {
                let snap_path = args
                    .out
                    .as_ref()
                    .map(|o| o.join("snapshot.img"))
                    .unwrap_or_else(|| {
                        std::env::temp_dir()
                            .join(format!("ferrix-snapshot-{}.img", std::process::id()))
                    });
                if !args.json {
                    println!(
                        "Creating read-only snapshot of block device {}...",
                        scan_args.device.display()
                    );
                }
                match ferrix_usb::disk::snapshot::create_snapshot(
                    &scan_args.device,
                    &snap_path,
                    &ctx.event_sink,
                ) {
                    Ok(s) => {
                        ctx.snapshot_path = Some(s.path.clone());
                        Some(s.path)
                    }
                    Err(e) => {
                        eprintln!("Error creating device snapshot: {e}");
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                }
            } else {
                None
            };

            if let Some(ref out_dir) = args.out {
                if !out_dir.exists() {
                    let _ = std::fs::create_dir_all(out_dir);
                }
            }

            let scan_target = ctx.snapshot_path.as_ref().unwrap_or(&ctx.target_path);
            let mut read_paths: Vec<&std::path::Path> =
                vec![scan_target.as_path(), scan_args.device.as_path()];
            if let Some(ref p) = args.policy {
                read_paths.push(p.as_path());
            }

            let mut write_paths: Vec<&std::path::Path> = Vec::new();
            if let Some(ref o) = args.out {
                write_paths.push(o.as_path());
            }

            let _ = ferrix_usb::sandbox::enter_sandbox(&read_paths, &write_paths);

            let device_stage = ferrix_usb::device::DeviceScanStage::new(policy.clone());
            let partition_stage = ferrix_usb::disk::PartitionScanStage::default();
            let fs_stage = ferrix_usb::fs::FilesystemScanStage::default();
            let file_stage = ferrix_usb::scan::FileScanStage::default();
            let policy_stage = ferrix_usb::policy::PolicyScanStage::new(policy.clone());

            let mut completed_stages = Vec::new();
            let mut all_findings = Vec::new();

            for stage in [
                &device_stage as &dyn Stage,
                &partition_stage as &dyn Stage,
                &fs_stage as &dyn Stage,
                &file_stage as &dyn Stage,
                &policy_stage as &dyn Stage,
            ] {
                let stage_result = match stage.run(&ctx) {
                    Ok(findings) => {
                        all_findings.extend(findings.clone());
                        ferrix_usb::core::StageResult {
                            stage_id: stage.id().to_string(),
                            status: ferrix_usb::core::StageStatus::Ok,
                            findings,
                        }
                    }
                    Err(e) => ferrix_usb::core::StageResult {
                        stage_id: stage.id().to_string(),
                        status: ferrix_usb::core::StageStatus::Error(e.to_string()),
                        findings: Vec::new(),
                    },
                };
                completed_stages.push(stage_result);
            }

            let required_stages = [
                device_stage.id(),
                partition_stage.id(),
                fs_stage.id(),
                file_stage.id(),
                policy_stage.id(),
            ];
            let verdict = ferrix_usb::core::resolve_verdict(
                &required_stages,
                &completed_stages,
                &all_findings,
            );

            let scan_id = format!(
                "scan-{}-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                generate_nonce()
            );

            if let Some(ref out_dir) = args.out {
                if !out_dir.exists() {
                    let _ = std::fs::create_dir_all(out_dir);
                }

                let (device_hash, device_size_bytes) =
                    ferrix_usb::disk::snapshot::hash_device_or_image(scan_target)
                        .unwrap_or_else(|_| (String::new(), 0));

                let (partition_layout_hash, files) = {
                    let file_res = File::open(scan_target);
                    if let Ok(mut f) = file_res {
                        let layout = ferrix_usb::disk::partition::parse_disk_layout(
                            &mut f,
                            device_size_bytes,
                            512,
                        )
                        .ok();
                        let layout_hash =
                            layout.as_ref().map(compute_layout_hash).unwrap_or_default();
                        let discovered = ferrix_usb::fs::extract_filesystem_files(
                            &mut f,
                            device_size_bytes,
                            512,
                        )
                        .unwrap_or_default();
                        let file_entries =
                            hash_discovered_files(&mut f, &discovered).unwrap_or_default();
                        (layout_hash, file_entries)
                    } else {
                        (String::new(), Vec::new())
                    }
                };

                let now_ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let mut manifest = Manifest {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    station_id: "station-local".to_string(),
                    nonce: generate_nonce(),
                    issued_at: now_ts,
                    expires_at: now_ts + 86400,
                    device_identity: None,
                    device_size_bytes,
                    device_hash: device_hash.clone(),
                    partition_layout_hash,
                    files,
                    policy_hash: policy.compute_hash(),
                    stages_required: required_stages.iter().map(|s| s.to_string()).collect(),
                    stages_completed: completed_stages.clone(),
                    verdict,
                    signature: None,
                };

                let station_key_path = PathBuf::from("station.key");
                if station_key_path.exists() {
                    if let Ok(sk) = load_station_signing_key(&station_key_path) {
                        let _ = manifest.sign(&sk);
                    }
                }

                let manifest_path = out_dir.join(format!("{scan_id}-manifest.json"));
                if let Ok(json_str) = serde_json::to_string_pretty(&manifest) {
                    let _ = std::fs::write(&manifest_path, json_str);
                    if !args.json {
                        println!("Manifest written to: {}", manifest_path.display());
                    }
                }

                let audit_path = out_dir.join("audit.jsonl");
                let _ = ferrix_usb::audit::append_audit_entry(
                    &audit_path,
                    "scan",
                    Some(&scan_id),
                    Some(&device_hash),
                    Some(verdict),
                    serde_json::json!({
                        "device": scan_args.device.display().to_string(),
                        "findings_count": all_findings.len(),
                    }),
                );
            }

            if args.json {
                let output = serde_json::json!({
                    "scan_id": scan_id,
                    "verdict": verdict,
                    "findings": all_findings,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_default()
                );
            } else {
                println!("Scan target: {}", scan_args.device.display());
                println!("Verdict: {verdict}");
                if !all_findings.is_empty() {
                    println!("\nFindings ({}):", all_findings.len());
                    for f in &all_findings {
                        println!(
                            "  [{}] {} ({}) - {}",
                            f.severity, f.id, f.location, f.reason
                        );
                        println!("    Evidence: {}", f.evidence);
                    }
                }
            }

            if args.out.is_none() {
                if let Some(ref p) = temp_snapshot_path {
                    let _ = std::fs::remove_file(p);
                }
            }

            ExitCode::from(verdict.exit_code() as u8)
        }
        Some(Commands::Egress(egress_args)) => {
            if !egress_args.device.exists() {
                eprintln!(
                    "Error: target '{}' does not exist",
                    egress_args.device.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            let ctx = ferrix_usb::core::ScanContext::new(egress_args.device.clone());
            let egress_stage = ferrix_usb::egress::EgressScanStage::new()
                .with_verify_wipe(egress_args.verify_wipe);

            let findings = match egress_stage.run(&ctx) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Egress scan failed with error: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let stage_result = ferrix_usb::core::StageResult {
                stage_id: egress_stage.id().to_string(),
                status: ferrix_usb::core::StageStatus::Ok,
                findings: findings.clone(),
            };

            let required_stages = [egress_stage.id()];
            let completed_stages = [stage_result];
            let verdict =
                ferrix_usb::core::resolve_verdict(&required_stages, &completed_stages, &findings);

            if args.json {
                let output = serde_json::json!({
                    "verdict": verdict,
                    "findings": findings,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_default()
                );
            } else {
                println!("Egress target: {}", egress_args.device.display());
                println!("Verdict: {verdict}");
                if !findings.is_empty() {
                    println!("\nFindings ({}):", findings.len());
                    for f in &findings {
                        println!(
                            "  [{}] {} ({}) - {}",
                            f.severity, f.id, f.location, f.reason
                        );
                        println!("    Evidence: {}", f.evidence);
                    }
                }
            }

            ExitCode::from(verdict.exit_code() as u8)
        }
        Some(Commands::Verify(verify_args)) => {
            if !verify_args.device.exists() {
                eprintln!(
                    "Error: target device '{}' does not exist",
                    verify_args.device.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }
            if !verify_args.manifest.exists() {
                eprintln!(
                    "Error: manifest file '{}' does not exist",
                    verify_args.manifest.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            let manifest_data = match std::fs::read(&verify_args.manifest) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error reading manifest: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let manifest: Manifest = match serde_json::from_slice(&manifest_data) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error parsing manifest JSON: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let pubkey_path = verify_args
                .manifest
                .parent()
                .map(|p| p.join("station.pub"))
                .filter(|p| p.exists())
                .unwrap_or_else(|| PathBuf::from("station.pub"));

            let pubkey = match load_station_verifying_key(&pubkey_path) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!(
                        "Error loading station public key from '{}': {e}",
                        pubkey_path.display()
                    );
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let nonce_log_path = verify_args
                .manifest
                .parent()
                .map(|p| p.join("accepted_nonces.log"))
                .unwrap_or_else(|| PathBuf::from("accepted_nonces.log"));

            match manifest.verify_against_media_with_nonce_log(
                &verify_args.device,
                &pubkey,
                Some(&nonce_log_path),
            ) {
                Ok(report) => {
                    if args.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&report).unwrap_or_default()
                        );
                    } else if report.valid {
                        println!(
                            "PASS: media '{}' matches manifest from station '{}'",
                            verify_args.device.display(),
                            report.manifest_station_id
                        );
                        println!("Original scan verdict: {}", report.manifest_verdict);
                    } else {
                        println!(
                            "FAIL: media '{}' failed verification against manifest",
                            verify_args.device.display()
                        );
                        println!("\nMismatches ({}):", report.mismatches.len());
                        for m in &report.mismatches {
                            println!(
                                "  [{}] expected: {}, actual: {}",
                                m.component, m.expected, m.actual
                            );
                        }
                    }

                    if report.valid {
                        ExitCode::from(EXIT_PASS as u8)
                    } else {
                        ExitCode::from(EXIT_FAIL as u8)
                    }
                }
                Err(e) => {
                    eprintln!("Verification failed with error: {e}");
                    ExitCode::from(EXIT_INTERNAL_ERROR as u8)
                }
            }
        }
        Some(Commands::Keygen(keygen_args)) => {
            let key_dir = keygen_args.key_dir.unwrap_or_else(|| PathBuf::from("."));

            match ferrix_usb::manifest::generate_station_keypair(&key_dir, keygen_args.force) {
                Ok((key_path, pub_path)) => {
                    println!("Station keypair generated successfully:");
                    println!("  Private key: {}", key_path.display());
                    println!("  Public key:  {}", pub_path.display());
                    ExitCode::from(EXIT_PASS as u8)
                }
                Err(e) => {
                    eprintln!("Error generating station keypair: {e}");
                    ExitCode::from(EXIT_INTERNAL_ERROR as u8)
                }
            }
        }
        Some(Commands::Report(report_args)) => {
            let search_dir = args.out.clone().unwrap_or_else(|| PathBuf::from("."));
            let manifest = match ferrix_usb::report::load_scan_manifest(
                &report_args.scan_id,
                &[&search_dir, std::path::Path::new(".")],
            ) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error loading manifest for report: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let mut findings = Vec::new();
            for stage in &manifest.stages_completed {
                findings.extend(stage.findings.clone());
            }

            let report_content = if report_args.html {
                match ferrix_usb::report::generate_html_report(&manifest, &findings) {
                    Ok(html) => html,
                    Err(e) => {
                        eprintln!("Error generating HTML report: {e}");
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                }
            } else {
                match ferrix_usb::report::generate_json_report(&manifest, &findings) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Error generating JSON report: {e}");
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                }
            };

            if let Some(ref out_path) = args.out {
                let target_file = if out_path.is_dir() {
                    let ext = if report_args.html { "html" } else { "json" };
                    out_path.join(format!("{}-report.{}", report_args.scan_id, ext))
                } else {
                    out_path.clone()
                };

                if let Err(e) = std::fs::write(&target_file, &report_content) {
                    eprintln!("Error writing report to '{}': {e}", target_file.display());
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
                println!("Report written to: {}", target_file.display());
            } else {
                println!("{report_content}");
            }

            ExitCode::from(EXIT_PASS as u8)
        }
        Some(Commands::Triage(triage_args)) => {
            let store_path = PathBuf::from("suppressions.json");
            let store = match ferrix_usb::triage::SuppressionStore::load(&store_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error loading suppression store: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let now = ferrix_usb::triage::current_timestamp();
            let active = store.list_active(now);

            if triage_args.list {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&active).unwrap_or_default()
                    );
                } else {
                    println!("Active Suppressions ({}):", active.len());
                    if active.is_empty() {
                        println!("  No active suppressions.");
                    } else {
                        for s in &active {
                            let remaining_days = (s.expires_at.saturating_sub(now)) / 86400;
                            println!(
                                "  [{}] Author: {}, Expires in: {}d",
                                s.id, s.author, remaining_days
                            );
                            match &s.scope {
                                ferrix_usb::triage::SuppressionScope::FileHash(h) => {
                                    println!("    Scope: file_hash={h}");
                                }
                                ferrix_usb::triage::SuppressionScope::RuleAndPath {
                                    rule_id,
                                    path_pattern,
                                } => {
                                    println!("    Scope: rule={rule_id}, path={path_pattern}");
                                }
                            }
                            println!("    Reason: {}", s.reason);
                        }
                    }
                }
            } else {
                println!("Usage: ferrix triage --list to view active suppressions.");
            }

            ExitCode::from(EXIT_PASS as u8)
        }
        Some(Commands::Watch(_)) => {
            eprintln!("Watch mode not implemented yet.");
            ExitCode::from(EXIT_INTERNAL_ERROR as u8)
        }
    }
}
