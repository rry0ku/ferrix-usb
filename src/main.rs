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
    ferrix_usb::device::register_exit_and_signal_cleanup();
    let args = Cli::parse();

    match args.command {
        None => {
            if args.no_tui {
                eprintln!("Error: no command specified and --no-tui was requested");
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }
            let _station_guard = ferrix_usb::device::StationProtectionGuard::enable();
            match ferrix_usb::tui::run_tui() {
                Ok(_) => ExitCode::from(EXIT_PASS as u8),
                Err(e) => {
                    eprintln!("TUI error: {e}");
                    ExitCode::from(EXIT_INTERNAL_ERROR as u8)
                }
            }
        }
        Some(Commands::Scan(scan_args)) => {
            let _station_guard = ferrix_usb::device::StationProtectionGuard::enable();
            if !scan_args.device.exists() {
                eprintln!(
                    "Error: target '{}' does not exist",
                    scan_args.device.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            let (event_tx, event_rx) = std::sync::mpsc::channel();
            let mut ctx = ferrix_usb::core::ScanContext::new(scan_args.device.clone())
                .with_event_sink(ferrix_usb::core::EventSink::new(event_tx));
            let is_json = args.json;
            let progress_handle = std::thread::spawn(move || {
                let mut stage_start_time = std::time::Instant::now();
                let mut current_stage = String::new();
                let mut last_update = std::time::Instant::now();
                let mut last_render = std::time::Instant::now();
                let mut last_bytes = 0u64;
                let mut smoothed_speed = 0.0f64;
                let mut current_eta_sec: Option<u64> = None;
                while let Ok(event) = event_rx.recv() {
                    if is_json {
                        continue;
                    }
                    if let ferrix_usb::core::ScanEvent::Progress {
                        stage_id,
                        current,
                        total,
                        message,
                    } = event
                    {
                        if stage_id != current_stage {
                            current_stage = stage_id.clone();
                            stage_start_time = std::time::Instant::now();
                            last_update = std::time::Instant::now();
                            last_bytes = 0;
                            if stage_id == "snapshot" {
                                smoothed_speed = 0.0;
                                current_eta_sec = None;
                            } else {
                                smoothed_speed = 0.0;
                                current_eta_sec = Some(1);
                            }
                        }

                        let dt = last_update.elapsed().as_secs_f64();
                        if stage_id == "snapshot" {
                            if dt >= 0.5 {
                                let bytes_delta = current.saturating_sub(last_bytes);
                                let instant_speed = (bytes_delta as f64) / dt;
                                let stage_elapsed = stage_start_time.elapsed().as_secs_f64();
                                let cumulative_speed = if stage_elapsed > 0.5 && current > 0 {
                                    (current as f64) / stage_elapsed
                                } else {
                                    instant_speed
                                };

                                if smoothed_speed <= 0.0 {
                                    smoothed_speed = instant_speed;
                                } else {
                                    let ema = 0.75 * smoothed_speed + 0.25 * instant_speed;
                                    smoothed_speed = 0.7 * ema + 0.3 * cumulative_speed;
                                }

                                if smoothed_speed > 1024.0 {
                                    if let Some(tot) = total {
                                        let remaining = tot.saturating_sub(current) as f64;
                                        let raw_eta = remaining / smoothed_speed;
                                        let new_eta = raw_eta.round() as u64;
                                        current_eta_sec = Some(match current_eta_sec {
                                            Some(prev) if prev > 0 && new_eta > 0 => {
                                                if new_eta > prev + 5 {
                                                    prev + 2
                                                } else if prev > new_eta + 5 {
                                                    prev - 2
                                                } else {
                                                    new_eta
                                                }
                                            }
                                            _ => new_eta,
                                        });
                                    }
                                }
                                last_bytes = current;
                                last_update = std::time::Instant::now();
                            }
                        } else if let Some(tot) = total {
                            smoothed_speed = 0.0;
                            let stage_elapsed = stage_start_time.elapsed().as_secs_f64();
                            if stage_elapsed >= 0.5 && current > 0 {
                                let rate = (current as f64) / stage_elapsed;
                                if rate > 0.0 {
                                    let remaining = tot.saturating_sub(current) as f64;
                                    current_eta_sec = Some((remaining / rate).round() as u64);
                                }
                            } else if current == tot {
                                current_eta_sec = Some(0);
                            } else {
                                current_eta_sec = Some(1);
                            }
                        }

                        let is_final_chunk = total.map(|t| current == t).unwrap_or(false);
                        let should_render =
                            last_render.elapsed().as_millis() >= 100 || is_final_chunk;
                        if should_render {
                            let speed_str = if stage_id == "snapshot" && smoothed_speed > 1024.0 {
                                format!(" ({:.1} MB/s)", smoothed_speed / (1024.0 * 1024.0))
                            } else {
                                String::new()
                            };

                            let eta_str = if let Some(eta_sec) = current_eta_sec {
                                if eta_sec >= 3600 {
                                    format!(
                                        " [ETA: {:02}:{:02}:{:02}]",
                                        eta_sec / 3600,
                                        (eta_sec % 3600) / 60,
                                        eta_sec % 60
                                    )
                                } else {
                                    format!(" [ETA: {:02}:{:02}]", eta_sec / 60, eta_sec % 60)
                                }
                            } else {
                                String::new()
                            };

                            let pct_str = if let Some(tot) = total {
                                if tot > 0 {
                                    format!("{:.1}%", (current as f64 / tot as f64) * 100.0)
                                } else {
                                    String::new()
                                }
                            } else {
                                String::new()
                            };

                            let msg = message.unwrap_or_else(|| stage_id.clone());
                            use std::io::Write;
                            let _ = write!(
                                std::io::stderr(),
                                "\r\x1b[2K[{pct_str}]{speed_str}{eta_str} {msg}"
                            );
                            let _ = std::io::stderr().flush();
                            last_render = std::time::Instant::now();
                        }
                    }
                }
                if !is_json {
                    use std::io::Write;
                    let _ = write!(std::io::stderr(), "\r\x1b[2K");
                    let _ = std::io::stderr().flush();
                }
            });
            let (mut policy, warning) =
                ferrix_usb::policy::load_policy(args.policy.as_deref(), None);
            if let Some(warn) = warning {
                eprintln!("{warn}");
            }

            if let Some(ref yara_path) = scan_args.yara {
                policy.yara_rules.push(yara_path.display().to_string());
            }
            if scan_args.clamav {
                policy.clamav.enabled = true;
            }
            if let Some(ref sock) = scan_args.clamav_socket {
                policy.clamav.socket_path = Some(sock.clone());
            }
            if scan_args.carve {
                policy.carve.enabled = true;
            }

            let disposable_env = if scan_args.disposable {
                match ferrix_usb::disk::DisposableEnvironment::create("session") {
                    Ok(env) => Some(env),
                    Err(e) => {
                        eprintln!("Error creating disposable environment: {e}");
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                }
            } else {
                None
            };

            let is_block_device = {
                use std::os::unix::fs::FileTypeExt;
                scan_args.device.starts_with("/dev/")
                    || scan_args
                        .device
                        .metadata()
                        .map(|m| m.file_type().is_block_device())
                        .unwrap_or(false)
            };

            if is_block_device
                && (ferrix_usb::device::is_system_device(&scan_args.device)
                    || !ferrix_usb::device::is_external_device(&scan_args.device))
            {
                eprintln!(
                    "SECURITY ERROR: Refusing to inspect '{}'. Ferrix only inspects externally connected removable media, never host system or internal drives.",
                    scan_args.device.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            if is_block_device && !nix::unistd::Uid::effective().is_root() {
                eprintln!("Note: inspecting physical block devices typically requires elevated privileges. If access fails, re-run with 'sudo ferrix scan ...'.");
            }

            let test_file = match ferrix_usb::disk::open_device_or_file_with_retry(
                &scan_args.device,
                std::time::Duration::from_secs(3),
            ) {
                Ok(f) => f,
                Err(e) => {
                    let msg = match e.raw_os_error() {
                        Some(6) => format!(
                            "Error: No media inserted in device '{}' (os error 6: ENXIO).",
                            scan_args.device.display()
                        ),
                        Some(13) => format!(
                            "Error: Permission denied accessing '{}' (os error 13: EACCES). Re-run with 'sudo ferrix scan ...'.",
                            scan_args.device.display()
                        ),
                        _ => format!(
                            "Error: Cannot access scan target '{}': {e}",
                            scan_args.device.display()
                        ),
                    };
                    eprintln!("{msg}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let device_size =
                ferrix_usb::disk::snapshot::get_device_or_file_size(&test_file, &scan_args.device);
            if device_size == 0 {
                eprintln!(
                    "Error: Target '{}' has 0 bytes (no media inserted or device is empty).",
                    scan_args.device.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            let temp_snapshot_path = if let Some(ref env) = disposable_env {
                let snap_path = env.snapshot_path();
                if !args.json {
                    println!(
                        "Creating disposable snapshot in memory-backed workspace: {}...",
                        snap_path.display()
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
            } else if is_block_device {
                let snap_path = match args.out.as_ref() {
                    Some(o) if !o.is_dir() => o.clone(),
                    _ => {
                        let snap_dir = match ferrix_usb::disk::resolve_snapshot_directory(
                            device_size,
                            args.out.as_deref(),
                        ) {
                            Ok(d) => d,
                            Err(e) => {
                                eprintln!("Error resolving snapshot location: {e}");
                                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                            }
                        };
                        let nonce = ferrix_usb::manifest::generate_nonce();
                        snap_dir.join(format!("ferrix-snapshot-{nonce}.img"))
                    }
                };
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

            let effective_sector_size = if scan_args.sector_size == 512 && is_block_device {
                ferrix_usb::device::read_block_device_sector_size(&scan_args.device).unwrap_or(512)
            } else {
                scan_args.sector_size
            };

            let (dev_vendor, dev_model, dev_serial) =
                ferrix_usb::device::read_block_device_identity(&scan_args.device);

            let usb_dev =
                ferrix_usb::device::find_usb_device_sysfs_for_block_device(&scan_args.device)
                    .and_then(|p| ferrix_usb::device::read_usb_device_from_sysfs(&p).ok());

            let device_identity =
                if !dev_vendor.is_empty() || !dev_model.is_empty() || !dev_serial.is_empty() {
                    Some(ferrix_usb::manifest::DeviceIdentity {
                        vendor: if dev_vendor.is_empty() {
                            None
                        } else {
                            Some(dev_vendor.clone())
                        },
                        product: if dev_model.is_empty() {
                            None
                        } else {
                            Some(dev_model.clone())
                        },
                        serial: if dev_serial.is_empty() {
                            None
                        } else {
                            Some(dev_serial.clone())
                        },
                    })
                } else {
                    usb_dev
                        .as_ref()
                        .map(|u| ferrix_usb::manifest::DeviceIdentity {
                            vendor: u.manufacturer.clone().or_else(|| Some(u.vendor_id.clone())),
                            product: u
                                .product_name
                                .clone()
                                .or_else(|| Some(u.product_id.clone())),
                            serial: u.serial.clone(),
                        })
                };

            let station_key_path = PathBuf::from("station.key");
            let station_key = if station_key_path.exists() {
                load_station_signing_key(&station_key_path).ok()
            } else {
                None
            };

            let device_stage = ferrix_usb::device::DeviceScanStage::new(policy.clone());
            let mut completed_stages = Vec::new();
            let mut all_findings = Vec::new();

            let device_result = match device_stage.run(&ctx) {
                Ok(findings) => {
                    all_findings.extend(findings.clone());
                    ferrix_usb::core::StageResult {
                        stage_id: device_stage.id().to_string(),
                        status: ferrix_usb::core::StageStatus::Ok,
                        findings,
                    }
                }
                Err(e) => ferrix_usb::core::StageResult {
                    stage_id: device_stage.id().to_string(),
                    status: ferrix_usb::core::StageStatus::Error(e.to_string()),
                    findings: Vec::new(),
                },
            };
            completed_stages.push(device_result);

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
            let released_dir = PathBuf::from("released");
            if scan_args.release && args.out.is_none() {
                let _ = std::fs::create_dir_all(&released_dir);
                write_paths.push(&released_dir);
            }

            if let Err(e) = ferrix_usb::sandbox::enter_sandbox(&read_paths, &write_paths) {
                if nix::unistd::getuid().as_raw() == 0 {
                    eprintln!("Error: failed to enforce sandbox environment as root: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                } else {
                    eprintln!("Warning: failed to enforce sandbox environment: {e}");
                }
            }

            let partition_stage = ferrix_usb::disk::PartitionScanStage::new(effective_sector_size);
            let fs_stage = ferrix_usb::fs::FilesystemScanStage::new(effective_sector_size);
            let file_stage = ferrix_usb::scan::FileScanStage::new(effective_sector_size)
                .with_policy(policy.clone());
            let policy_stage = ferrix_usb::policy::PolicyScanStage::new(policy.clone())
                .with_sector_size(effective_sector_size);

            for stage in [
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
            ctx.event_sink = ferrix_usb::core::EventSink::noop();
            let _ = progress_handle.join();

            let required_stages = [
                device_stage.id(),
                partition_stage.id(),
                fs_stage.id(),
                file_stage.id(),
                policy_stage.id(),
            ];
            let verdict = ferrix_usb::policy::resolve_verdict_with_policy(
                &required_stages,
                &completed_stages,
                &all_findings,
                &policy,
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
                            effective_sector_size,
                        )
                        .ok();
                        let layout_hash =
                            layout.as_ref().map(compute_layout_hash).unwrap_or_default();
                        let discovered = ferrix_usb::fs::extract_filesystem_files(
                            &mut f,
                            device_size_bytes,
                            effective_sector_size,
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
                    device_identity,
                    device_size_bytes,
                    device_hash: device_hash.clone(),
                    partition_layout_hash,
                    files,
                    policy_hash: policy.compute_hash(),
                    stages_required: required_stages.iter().map(|s| s.to_string()).collect(),
                    stages_completed: completed_stages.clone(),
                    verdict,
                    sector_size: effective_sector_size,
                    signature: None,
                };

                if let Some(ref sk) = station_key {
                    let _ = manifest.sign(sk);
                }

                let eff_sec = if effective_sector_size == 0 {
                    512
                } else {
                    effective_sector_size as u64
                };
                let acq_report = ferrix_usb::report::ForensicAcquisitionReport {
                    sha256: String::new(),
                    blake3: device_hash.clone(),
                    timestamp: now_ts,
                    total_sectors: device_size_bytes / eff_sec,
                    total_bytes: device_size_bytes,
                    sector_size: effective_sector_size,
                };

                let dummy_layout = ferrix_usb::disk::partition::DiskLayout {
                    sector_size: effective_sector_size,
                    total_sectors: acq_report.total_sectors,
                    table_type: ferrix_usb::disk::partition::PartitionTableType::None,
                    partitions: Vec::new(),
                    has_protective_mbr: false,
                    primary_gpt_valid: false,
                    backup_gpt_valid: false,
                    gpt_differs_from_backup: false,
                    backup_gpt_lba_mismatch: false,
                    mbr_partition_count: 0,
                    gpt_partition_count: 0,
                };

                let mut forensic_report = ferrix_usb::report::ForensicReport::new(
                    "station-local".to_string(),
                    usb_dev.as_ref(),
                    acq_report,
                    &dummy_layout,
                    all_findings.clone(),
                    verdict,
                    policy.compute_hash(),
                );

                if let Some(ref mut d) = forensic_report.device {
                    if d.serial.is_none() && !dev_serial.is_empty() {
                        d.serial = Some(dev_serial.clone());
                    }
                    if d.manufacturer.is_none() && !dev_vendor.is_empty() {
                        d.manufacturer = Some(dev_vendor.clone());
                    }
                    if d.product_name.is_none() && !dev_model.is_empty() {
                        d.product_name = Some(dev_model.clone());
                    }
                } else if !dev_vendor.is_empty() || !dev_model.is_empty() || !dev_serial.is_empty()
                {
                    forensic_report.device = Some(ferrix_usb::report::ForensicDeviceReport {
                        vendor_id: None,
                        product_id: None,
                        serial: if dev_serial.is_empty() {
                            None
                        } else {
                            Some(dev_serial.clone())
                        },
                        manufacturer: if dev_vendor.is_empty() {
                            None
                        } else {
                            Some(dev_vendor.clone())
                        },
                        product_name: if dev_model.is_empty() {
                            None
                        } else {
                            Some(dev_model.clone())
                        },
                        interfaces: Vec::new(),
                    });
                }

                if let Some(ref sk) = station_key {
                    let _ = forensic_report.sign(sk);
                }

                if scan_args.bundle {
                    let _ = ferrix_usb::report::generate_evidence_bundle(
                        &forensic_report,
                        &manifest,
                        out_dir,
                    );
                    if !args.json {
                        println!(
                            "Evidence bundle generated at: {}",
                            out_dir.join("evidence").display()
                        );
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

            if scan_args.release {
                if verdict == ferrix_usb::core::Verdict::Pass {
                    let snap_to_release = temp_snapshot_path.as_ref().unwrap_or(scan_target);
                    let dest_dir = args
                        .out
                        .as_ref()
                        .map(|o| o.join("released"))
                        .unwrap_or_else(|| PathBuf::from("released"));
                    match ferrix_usb::release::release_snapshot_files(
                        snap_to_release,
                        &dest_dir,
                        effective_sector_size,
                    ) {
                        Ok(rel_report) => {
                            if !args.json {
                                println!(
                                    "\nRelease successful: {} files ({} bytes) extracted to '{}'",
                                    rel_report.files_released,
                                    rel_report.bytes_released,
                                    rel_report.destination_dir.display()
                                );
                                if !rel_report.renames.is_empty() {
                                    println!("Sanitized filenames ({}):", rel_report.renames.len());
                                    for r in &rel_report.renames {
                                        println!(
                                            "  '{}' -> '{}' ({})",
                                            r.original, r.sanitized, r.reason
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error during file release: {e}");
                        }
                    }
                } else {
                    eprintln!(
                        "Warning: release requested but media verdict is {verdict}. No files released (fail closed)."
                    );
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

            let is_block_device = egress_args.device.starts_with("/dev/")
                || egress_args
                    .device
                    .metadata()
                    .map(|m| {
                        use std::os::unix::fs::FileTypeExt;
                        m.file_type().is_block_device()
                    })
                    .unwrap_or(false);

            if is_block_device
                && (ferrix_usb::device::is_system_device(&egress_args.device)
                    || !ferrix_usb::device::is_external_device(&egress_args.device))
            {
                eprintln!(
                    "SECURITY ERROR: Refusing to inspect '{}'. Ferrix only inspects externally connected removable media, never host system or internal drives.",
                    egress_args.device.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            if is_block_device && !nix::unistd::Uid::effective().is_root() {
                eprintln!("Note: inspecting physical block devices typically requires elevated privileges. If access fails, re-run with 'sudo ferrix egress ...'.");
            }

            let detected_sector_size = if is_block_device {
                ferrix_usb::device::read_block_device_sector_size(&egress_args.device)
                    .unwrap_or(512)
            } else {
                512
            };

            let ctx = ferrix_usb::core::ScanContext::new(egress_args.device.clone());
            let egress_stage = ferrix_usb::egress::EgressScanStage::new()
                .with_verify_wipe(egress_args.verify_wipe)
                .with_sector_size(detected_sector_size);

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
            if !verify_args.target.exists() {
                eprintln!(
                    "Error: target '{}' does not exist",
                    verify_args.target.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            let pubkey_path = verify_args
                .pubkey
                .clone()
                .or_else(|| {
                    verify_args
                        .manifest
                        .as_ref()
                        .and_then(|m| m.parent().map(|p| p.join("station.pub")))
                        .filter(|p| p.exists())
                })
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

            if verify_args.manifest.is_none()
                && (verify_args
                    .target
                    .extension()
                    .map(|e| e == "json")
                    .unwrap_or(false)
                    || verify_args.target.to_string_lossy().contains("report"))
            {
                match ferrix_usb::manifest::verify_forensic_report_file(
                    &verify_args.target,
                    &pubkey,
                ) {
                    Ok(true) => {
                        println!(
                            "PASS: report '{}' is validly signed by station public key '{}'",
                            verify_args.target.display(),
                            pubkey_path.display()
                        );
                        return ExitCode::from(EXIT_PASS as u8);
                    }
                    Ok(false) => {
                        println!(
                            "FAIL: report '{}' failed cryptographic verification: signature is invalid",
                            verify_args.target.display()
                        );
                        return ExitCode::from(EXIT_FAIL as u8);
                    }
                    Err(e) => {
                        println!(
                            "FAIL: report '{}' failed cryptographic verification: {e}",
                            verify_args.target.display()
                        );
                        return ExitCode::from(EXIT_FAIL as u8);
                    }
                }
            }

            let manifest_path = match verify_args.manifest {
                Some(ref m) => m.clone(),
                None => {
                    eprintln!("Error: --manifest is required when verifying media");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            if !manifest_path.exists() {
                eprintln!(
                    "Error: manifest file '{}' does not exist",
                    manifest_path.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            let is_block_device = verify_args.target.starts_with("/dev/")
                || verify_args
                    .target
                    .metadata()
                    .map(|m| {
                        use std::os::unix::fs::FileTypeExt;
                        m.file_type().is_block_device()
                    })
                    .unwrap_or(false);

            if is_block_device
                && (ferrix_usb::device::is_system_device(&verify_args.target)
                    || !ferrix_usb::device::is_external_device(&verify_args.target))
            {
                eprintln!(
                    "SECURITY ERROR: Refusing to verify '{}'. Ferrix only inspects externally connected removable media, never host system or internal drives.",
                    verify_args.target.display()
                );
                return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
            }

            if is_block_device && !nix::unistd::Uid::effective().is_root() {
                eprintln!("Note: verifying physical block devices typically requires elevated privileges. If access fails, re-run with 'sudo ferrix verify ...'.");
            }

            let manifest_data = match std::fs::read(&manifest_path) {
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

            let nonce_log_path = manifest_path
                .parent()
                .map(|p| p.join("accepted_nonces.log"))
                .unwrap_or_else(|| PathBuf::from("accepted_nonces.log"));

            match manifest.verify_against_media_with_nonce_log(
                &verify_args.target,
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
                            verify_args.target.display(),
                            report.manifest_station_id
                        );
                        println!("Original scan verdict: {}", report.manifest_verdict);
                    } else {
                        println!(
                            "FAIL: media '{}' failed verification against manifest",
                            verify_args.target.display()
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
            let mut store = match ferrix_usb::triage::SuppressionStore::load(&store_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error loading suppression store: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }
            };

            let now = ferrix_usb::triage::current_timestamp();

            if triage_args.add {
                let reason = match triage_args.reason {
                    Some(ref r) if !r.trim().is_empty() => r.trim().to_string(),
                    _ => {
                        eprintln!("Error: --reason is required when adding a suppression");
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                };

                let scope = if let Some(ref h) = triage_args.hash {
                    let clean_h = h.trim();
                    if clean_h.len() != 64 || !clean_h.chars().all(|c| c.is_ascii_hexdigit()) {
                        eprintln!("Error: --hash must be a 64-character hex BLAKE3 hash");
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                    ferrix_usb::triage::SuppressionScope::FileHash(clean_h.to_lowercase())
                } else if let (Some(ref r), Some(ref p)) =
                    (&triage_args.rule, &triage_args.path_pattern)
                {
                    let clean_r = r.trim().to_uppercase();
                    let clean_p = p.trim().to_string();
                    if clean_p == "*" || clean_p == "**" || clean_p == "/*" {
                        eprintln!("Error: wildcard-only path patterns are rejected");
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                    if clean_r == "FX-DEV-001" {
                        eprintln!(
                            "Error: Critical BadUSB findings (FX-DEV-001) cannot be suppressed"
                        );
                        return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                    }
                    ferrix_usb::triage::SuppressionScope::RuleAndPath {
                        rule_id: clean_r,
                        path_pattern: clean_p,
                    }
                } else {
                    eprintln!("Error: adding a suppression requires either --hash or both --rule and --path-pattern");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                };

                let author = std::env::var("USER").unwrap_or_else(|_| "operator".to_string());
                let duration_secs = triage_args.days.saturating_mul(86400);
                let expiry = now.saturating_add(duration_secs);

                let id_input = format!("{author}:{now}:{reason}");
                let supp_id = format!(
                    "SUP-{}",
                    blake3::hash(id_input.as_bytes()).to_hex()[..8].to_uppercase()
                );

                let station_key_path = PathBuf::from("station.key");
                let signature = if station_key_path.exists() {
                    if let Ok(sk) = load_station_signing_key(&station_key_path) {
                        use ed25519_dalek::Signer;
                        let msg = format!("{supp_id}:{author}:{now}:{expiry}:{reason}");
                        let sig = sk.sign(msg.as_bytes());
                        Some(ferrix_usb::manifest::hex_encode(&sig.to_bytes()))
                    } else {
                        None
                    }
                } else {
                    None
                };

                let supp = ferrix_usb::triage::Suppression {
                    id: supp_id,
                    scope,
                    reason,
                    author,
                    created_at: now,
                    expires_at: expiry,
                    signature,
                };

                if let Err(e) = store.add_suppression(supp.clone()) {
                    eprintln!("Error adding suppression: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }

                if let Err(e) = store.save(&store_path) {
                    eprintln!("Error saving suppression store: {e}");
                    return ExitCode::from(EXIT_INTERNAL_ERROR as u8);
                }

                let audit_path = PathBuf::from("audit.jsonl");
                let _ = ferrix_usb::audit::append_audit_entry(
                    &audit_path,
                    "suppression_added",
                    Some(&supp.id),
                    None,
                    None,
                    serde_json::json!({
                        "suppression_id": supp.id,
                        "author": supp.author,
                        "scope": supp.scope,
                        "reason": supp.reason,
                        "expires_at": supp.expires_at,
                    }),
                );

                println!("Suppression added successfully:");
                println!("  ID:         {}", supp.id);
                println!("  Author:     {}", supp.author);
                println!("  Reason:     {}", supp.reason);
                println!("  Expires at: {}", supp.expires_at);
                return ExitCode::from(EXIT_PASS as u8);
            }

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
                println!("Usage: ferrix triage --list to view active suppressions, or ferrix triage --add [options]");
            }

            ExitCode::from(EXIT_PASS as u8)
        }
        Some(Commands::Watch(watch_args)) => {
            if !nix::unistd::Uid::effective().is_root() {
                eprintln!("Warning: USB authorization management in watch mode requires root privileges. Please re-run with 'sudo ferrix watch'.");
            }
            let _station_guard = ferrix_usb::device::StationProtectionGuard::enable();

            println!(
                "Starting ferrix offline hotplug watch mode (polling interval: {}s)...",
                watch_args.interval
            );
            println!("Monitoring /sys/bus/usb/devices/ for removable media (Ctrl+C to stop)...");

            let (policy, warning) = ferrix_usb::policy::load_policy(args.policy.as_deref(), None);
            if let Some(warn) = warning {
                eprintln!("{warn}");
            }

            let mut seen_devices = std::collections::HashSet::new();

            loop {
                if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
                    for entry_res in entries {
                        let entry = match entry_res {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let p = entry.path();
                        if p.join("idVendor").exists() && p.join("idProduct").exists() {
                            let dev_key = p
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                            if seen_devices.contains(&dev_key) {
                                continue;
                            }

                            let auth_file = p.join("authorized");
                            let is_unauthorized = std::fs::read_to_string(&auth_file)
                                .map(|s| s.trim() == "0")
                                .unwrap_or(false);

                            if is_unauthorized {
                                seen_devices.insert(dev_key.clone());
                                println!(
                                    "\n[HOTPLUG] Detected unauthorized USB device: {}",
                                    p.display()
                                );

                                if let Ok(usb_dev) =
                                    ferrix_usb::device::read_usb_device_from_sysfs(&p)
                                {
                                    println!("  Vendor ID:    {}", usb_dev.vendor_id);
                                    println!("  Product ID:   {}", usb_dev.product_id);
                                    if let Some(ref m) = usb_dev.manufacturer {
                                        println!("  Manufacturer: {m}");
                                    }
                                    if let Some(ref pr) = usb_dev.product_name {
                                        println!("  Product:      {pr}");
                                    }
                                    if let Some(ref s) = usb_dev.serial {
                                        println!("  Serial:       {s}");
                                    }

                                    let pre_findings = ferrix_usb::device::check_device_anomalies(
                                        &usb_dev, &policy,
                                    );
                                    let is_badusb = pre_findings.iter().any(|f| {
                                        f.severity == ferrix_usb::core::Severity::Critical
                                    });

                                    if is_badusb {
                                        eprintln!(
                                            "  ALERT: BadUSB composite device detected! Storage + HID keyboard/mouse. Device will NEVER be authorized."
                                        );
                                        continue;
                                    }

                                    let has_storage = usb_dev.interfaces.iter().any(|i| {
                                        i.interface_class
                                            == ferrix_usb::device::USB_CLASS_MASS_STORAGE
                                    }) || usb_dev.interfaces.is_empty();

                                    if !has_storage {
                                        println!(
                                            "  Device does not expose mass storage. Skipping."
                                        );
                                        continue;
                                    }

                                    println!(
                                        "  Descriptors clean. Mass storage interface approved."
                                    );

                                    if watch_args.auto_scan {
                                        println!("  Authorizing USB mass storage...");
                                        if let Err(e) = ferrix_usb::device::authorize_device(&p) {
                                            eprintln!("  Failed to authorize USB device: {e}");
                                            continue;
                                        }

                                        let mut block_dev = None;
                                        for _ in 0..25 {
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                            if let Some(b) =
                                                ferrix_usb::device::find_block_device_for_usb_sysfs(
                                                    &p,
                                                )
                                            {
                                                block_dev = Some(b);
                                                break;
                                            }
                                        }

                                        if let Some(b) = block_dev {
                                            let _ =
                                                ferrix_usb::device::set_block_device_readonly(&b);
                                            println!(
                                                "  Block device bound: {} (set read-only)",
                                                b.display()
                                            );
                                            println!(
                                                "  Ready for scan: ferrix scan {}",
                                                b.display()
                                            );
                                        } else {
                                            eprintln!(
                                                "  Timed out waiting for block device after authorization."
                                            );
                                        }
                                    } else {
                                        println!(
                                            "  Ready for inspection. Run: ferrix scan {} (or launch ferrix TUI)",
                                            p.display()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                std::thread::sleep(std::time::Duration::from_secs(watch_args.interval));
            }
        }
        Some(Commands::Mount(mount_args)) => {
            if !nix::unistd::Uid::effective().is_root() {
                eprintln!("Note: mounting devices typically requires elevated privileges. If access fails, re-run with 'sudo ferrix mount ...'.");
            }
            match ferrix_usb::device::mount_external_device(
                &mount_args.device,
                mount_args.mountpoint.as_deref(),
                mount_args.rw,
            ) {
                Ok(mounted_dir) => {
                    let mode_str = if mount_args.rw {
                        "read-write (rw,nodev,nosuid)"
                    } else {
                        "read-only (ro,nodev,nosuid,noexec)"
                    };
                    println!(
                        "Successfully mounted '{}' at '{}' [{}]",
                        mount_args.device.display(),
                        mounted_dir.display(),
                        mode_str
                    );
                    ExitCode::from(EXIT_PASS as u8)
                }
                Err(e) => {
                    eprintln!("Mount error: {e}");
                    ExitCode::from(EXIT_INTERNAL_ERROR as u8)
                }
            }
        }
        Some(Commands::Restore) => {
            if !nix::unistd::Uid::effective().is_root() {
                eprintln!("Note: restoring system services requires elevated privileges. If access fails, re-run with 'sudo ferrix restore'.");
            }
            ferrix_usb::device::restore_all_system_automount_defaults();
            println!("System USB automount defaults and services successfully restored.");
            ExitCode::from(EXIT_PASS as u8)
        }
        Some(Commands::Clean(clean_args)) => {
            if !nix::unistd::Uid::effective().is_root() {
                eprintln!("Note: cleaning system directories and restoring automount requires elevated privileges. If access fails, re-run with 'sudo ferrix clean'.");
            }

            let mut extra = Vec::new();
            if let Some(ref d) = clean_args.dir {
                extra.push(d.clone());
            }

            let report = ferrix_usb::disk::clean_all_snapshots(&extra);
            ferrix_usb::device::cleanup_lingering_station_lockdown();
            ferrix_usb::device::restore_all_system_automount_defaults();

            if args.json {
                let deleted_json: Vec<serde_json::Value> = report
                    .deleted_files
                    .iter()
                    .map(|(p, s)| {
                        serde_json::json!({
                            "path": p.display().to_string(),
                            "size_bytes": s,
                        })
                    })
                    .collect();

                let errors_json: Vec<serde_json::Value> = report
                    .errors
                    .iter()
                    .map(|(p, e)| {
                        serde_json::json!({
                            "path": p.display().to_string(),
                            "error": e,
                        })
                    })
                    .collect();

                let out = serde_json::json!({
                    "status": "ok",
                    "deleted_snapshots": deleted_json,
                    "total_deleted": report.deleted_files.len(),
                    "total_bytes_freed": report.total_bytes_freed,
                    "errors": errors_json,
                    "station_restored": true,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            } else {
                println!("Ferrix Cleanup");
                println!("==============");
                if report.deleted_files.is_empty() {
                    println!("No lingering snapshot files or temporary workspaces found in candidate directories (/var/tmp, /tmp, .).");
                } else {
                    println!("Deleted snapshots & temporary workspaces:");
                    for (path, size) in &report.deleted_files {
                        let size_gb = (*size as f64) / 1_073_741_824.0;
                        if size_gb >= 0.01 {
                            println!("  - {} ({:.2} GB)", path.display(), size_gb);
                        } else {
                            let size_mb = (*size as f64) / 1_048_576.0;
                            println!("  - {} ({:.2} MB)", path.display(), size_mb);
                        }
                    }
                    let total_gb = (report.total_bytes_freed as f64) / 1_073_741_824.0;
                    println!(
                        "\nTotal deleted: {} ({:.2} GB freed)",
                        report.deleted_files.len(),
                        total_gb
                    );
                }

                if !report.errors.is_empty() {
                    println!("\nErrors encountered:");
                    for (path, err) in &report.errors {
                        println!("  - {}: {err}", path.display());
                    }
                }

                println!("System USB automount defaults and udev rules restored.");
            }

            ExitCode::from(EXIT_PASS as u8)
        }
    }
}
