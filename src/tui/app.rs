use crate::core::{Finding, Severity, Stage, StageResult, StageStatus, Verdict};
use crate::policy::Policy;
use crate::triage::{current_timestamp, Suppression, SuppressionScope, SuppressionStore};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    DeviceSelect,
    ModeSelect,
    Scanning,
    Results,
    Report,
    Triage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    pub path: PathBuf,
    pub name: String,
    pub size_bytes: u64,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub is_removable: bool,
    pub is_system_drive: bool,
    pub mount_points: Vec<String>,
}

pub enum ScanEvent {
    StageStarted {
        name: String,
        index: usize,
        total: usize,
    },
    Progress {
        stage_id: String,
        current: u64,
        total: Option<u64>,
        message: Option<String>,
    },
    FindingFound(Finding),
    StageFinished(StageResult),
    ScanFinished {
        verdict: Verdict,
        stages: Vec<StageResult>,
        findings: Vec<Finding>,
        scan_id: String,
        target_path: PathBuf,
    },
    ScanFailed(String),
}

pub struct App {
    pub screen: Screen,
    pub devices: Vec<DeviceEntry>,
    pub selected_device_idx: usize,
    pub manual_device_input: String,
    pub is_entering_manual_device: bool,
    pub mode: ScanMode,
    pub policy: Policy,
    pub policy_path: Option<PathBuf>,
    pub is_scanning: bool,
    pub scan_progress_pct: u16,
    pub current_stage_name: String,
    pub current_stage_index: usize,
    pub total_stages: usize,
    pub scan_activity_log: Vec<String>,
    pub completed_stages: Vec<StageResult>,
    pub all_findings: Vec<Finding>,
    pub selected_finding_idx: usize,
    pub show_info_findings: bool,
    pub verdict: Option<Verdict>,
    pub scan_id: Option<String>,
    pub snapshot_path: Option<PathBuf>,
    pub rx_event: Option<Receiver<ScanEvent>>,
    pub status_message: Option<String>,
    pub triage_reason_input: String,
    pub triage_author_input: String,
    pub triage_focus_field: usize,
    pub report_export_path: Option<String>,
    pub last_device_refresh: std::time::Instant,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        let mut app = Self {
            screen: Screen::DeviceSelect,
            devices: Vec::new(),
            selected_device_idx: 0,
            manual_device_input: String::new(),
            is_entering_manual_device: false,
            mode: ScanMode::Ingress,
            policy: Policy::strict_default(),
            policy_path: None,
            is_scanning: false,
            scan_progress_pct: 0,
            current_stage_name: String::new(),
            current_stage_index: 0,
            total_stages: 0,
            scan_activity_log: Vec::new(),
            completed_stages: Vec::new(),
            all_findings: Vec::new(),
            selected_finding_idx: 0,
            show_info_findings: false,
            verdict: None,
            scan_id: None,
            snapshot_path: None,
            rx_event: None,
            status_message: None,
            triage_reason_input: String::new(),
            triage_author_input: "sec-admin".to_string(),
            triage_focus_field: 0,
            report_export_path: None,
            last_device_refresh: std::time::Instant::now(),
            should_quit: false,
        };
        app.refresh_devices();
        app
    }
}

impl App {
    pub fn refresh_devices(&mut self) {
        let mut list = Vec::new();

        if let Ok(entries) = fs::read_dir("/sys/class/block") {
            for entry_res in entries {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
                    continue;
                }

                let sys_path = entry.path();
                let is_partition = sys_path.join("partition").exists();
                if is_partition {
                    continue;
                }

                let is_removable = fs::read_to_string(sys_path.join("removable"))
                    .map(|s| s.trim() == "1")
                    .unwrap_or(false);

                let size_bytes = fs::read_to_string(sys_path.join("size"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|sectors| sectors * 512)
                    .unwrap_or(0);

                let vendor = fs::read_to_string(sys_path.join("device/vendor"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                let model = fs::read_to_string(sys_path.join("device/model"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                let serial = fs::read_to_string(sys_path.join("device/serial"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                let dev_path = PathBuf::from(format!("/dev/{name}"));
                let is_system_drive = crate::device::auth::is_system_device(&dev_path);
                let mount_points = crate::device::auth::check_device_mounts(&dev_path)
                    .into_iter()
                    .map(|(_, mp)| mp)
                    .collect();

                list.push(DeviceEntry {
                    path: dev_path,
                    name,
                    size_bytes,
                    vendor,
                    model,
                    serial,
                    is_removable,
                    is_system_drive,
                    mount_points,
                });
            }
        }

        if let Ok(entries) = fs::read_dir(".") {
            for entry_res in entries {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let path = entry.path();
                if path.is_file() {
                    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                    if ext == "raw" || ext == "img" {
                        let size_bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                        let name = path
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| "image.raw".to_string());
                        list.push(DeviceEntry {
                            path: path.clone(),
                            name,
                            size_bytes,
                            vendor: "Local File".to_string(),
                            model: "Disk Image".to_string(),
                            serial: String::new(),
                            is_removable: true,
                            is_system_drive: false,
                            mount_points: Vec::new(),
                        });
                    }
                }
            }
        }

        if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
            for entry_res in entries {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let p = entry.path();
                if p.join("idVendor").exists() && p.join("idProduct").exists() {
                    let auth_file = p.join("authorized");
                    let is_unauthorized = fs::read_to_string(&auth_file)
                        .map(|s| s.trim() == "0")
                        .unwrap_or(false);
                    if is_unauthorized {
                        if let Ok(usb_dev) = crate::device::read_usb_device_from_sysfs(&p) {
                            let has_storage = usb_dev.interfaces.iter().any(|i| {
                                i.interface_class == crate::device::USB_CLASS_MASS_STORAGE
                            }) || usb_dev.interfaces.is_empty();
                            if has_storage {
                                let vendor = usb_dev
                                    .manufacturer
                                    .unwrap_or_else(|| usb_dev.vendor_id.clone());
                                let model = usb_dev
                                    .product_name
                                    .unwrap_or_else(|| usb_dev.product_id.clone());
                                let serial = usb_dev.serial.unwrap_or_default();
                                let name = format!("usb:{}", entry.file_name().to_string_lossy());
                                list.push(DeviceEntry {
                                    path: p,
                                    name,
                                    size_bytes: 0,
                                    vendor,
                                    model,
                                    serial,
                                    is_removable: true,
                                    is_system_drive: false,
                                    mount_points: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        self.devices = list;
        if self.selected_device_idx >= self.devices.len() && !self.devices.is_empty() {
            self.selected_device_idx = self.devices.len() - 1;
        }
    }

    pub fn selected_device(&self) -> Option<&DeviceEntry> {
        self.devices.get(self.selected_device_idx)
    }

    pub fn filtered_findings(&self) -> Vec<&Finding> {
        let mut list: Vec<&Finding> = if self.show_info_findings {
            self.all_findings.iter().collect()
        } else {
            self.all_findings
                .iter()
                .filter(|f| f.severity != Severity::Info)
                .collect()
        };

        list.sort_by_key(|a| std::cmp::Reverse(a.severity));
        list
    }

    pub fn start_scan(&mut self) {
        let target_path = if self.is_entering_manual_device {
            PathBuf::from(self.manual_device_input.trim())
        } else if let Some(dev) = self.selected_device() {
            dev.path.clone()
        } else {
            return;
        };

        if !target_path.exists() {
            self.status_message = Some(format!("Target does not exist: {}", target_path.display()));
            return;
        }

        self.screen = Screen::Scanning;
        self.is_scanning = true;
        self.scan_progress_pct = 0;
        self.current_stage_name = "Initializing scan...".to_string();
        self.current_stage_index = 0;
        self.total_stages = 0;
        self.scan_activity_log.clear();
        self.scan_activity_log
            .push(format!("Starting scan on: {}", target_path.display()));
        self.completed_stages.clear();
        self.all_findings.clear();
        self.verdict = None;
        self.status_message = None;

        let (tx, rx): (Sender<ScanEvent>, Receiver<ScanEvent>) = channel();
        self.rx_event = Some(rx);

        let mode = self.mode;
        let policy = self.policy.clone();

        thread::spawn(move || {
            let (core_tx, core_rx) = channel::<crate::core::ScanEvent>();
            let mut ctx = crate::core::ScanContext::new(target_path.clone());
            ctx.event_sink = crate::core::EventSink::new(core_tx);

            let tx_fwd = tx.clone();
            thread::spawn(move || {
                while let Ok(evt) = core_rx.recv() {
                    match evt {
                        crate::core::ScanEvent::Progress {
                            stage_id,
                            current,
                            total,
                            message,
                        } => {
                            let _ = tx_fwd.send(ScanEvent::Progress {
                                stage_id,
                                current,
                                total,
                                message,
                            });
                        }
                        crate::core::ScanEvent::Finding(f) => {
                            let _ = tx_fwd.send(ScanEvent::FindingFound(f));
                        }
                    }
                }
            });

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let scan_id = format!("scan-{now}-{}", crate::manifest::generate_nonce());

            let is_unauthorized_usb = target_path.starts_with("/sys/bus/usb/devices/");
            if is_unauthorized_usb {
                let _ = tx.send(ScanEvent::Progress {
                    stage_id: "device_scan".to_string(),
                    current: 1,
                    total: Some(3),
                    message: Some(
                        "Inspecting unauthorized USB descriptors before authorization..."
                            .to_string(),
                    ),
                });

                if let Ok(usb_dev) = crate::device::read_usb_device_from_sysfs(&target_path) {
                    let pre_findings = crate::device::check_device_anomalies(&usb_dev, &policy);
                    let has_critical = pre_findings
                        .iter()
                        .any(|f| f.severity == Severity::Critical);
                    for f in pre_findings {
                        let _ = tx.send(ScanEvent::FindingFound(f));
                    }
                    if has_critical {
                        let _ = tx.send(ScanEvent::ScanFailed(
                            "Device rejected: BadUSB composite device pattern detected. Never authorized."
                                .to_string(),
                        ));
                        return;
                    }
                }

                let _ = tx.send(ScanEvent::Progress {
                    stage_id: "device_scan".to_string(),
                    current: 2,
                    total: Some(3),
                    message: Some("Authorizing USB mass storage in sysfs...".to_string()),
                });

                if let Err(e) = crate::device::authorize_device(&target_path) {
                    let _ = tx.send(ScanEvent::ScanFailed(format!(
                        "Failed to authorize USB device: {e}"
                    )));
                    return;
                }

                let mut block_dev = None;
                for _ in 0..25 {
                    thread::sleep(std::time::Duration::from_millis(100));
                    if let Some(b) = crate::device::find_block_device_for_usb_sysfs(&target_path) {
                        block_dev = Some(b);
                        break;
                    }
                }

                if let Some(b) = block_dev {
                    let _ = crate::device::set_block_device_readonly(&b);
                    ctx.target_path = b;
                } else {
                    let _ = tx.send(ScanEvent::ScanFailed(
                        "Timed out waiting for block device after authorization".to_string(),
                    ));
                    return;
                }
            }

            match mode {
                ScanMode::Ingress => {
                    let device_stage = crate::device::DeviceScanStage::new(policy.clone());
                    let partition_stage = crate::disk::PartitionScanStage::default();
                    let fs_stage = crate::fs::FilesystemScanStage::default();
                    let file_stage =
                        crate::scan::FileScanStage::default().with_policy(policy.clone());
                    let policy_stage = crate::policy::PolicyScanStage::new(policy.clone());

                    let stages: [&dyn Stage; 5] = [
                        &device_stage,
                        &partition_stage,
                        &fs_stage,
                        &file_stage,
                        &policy_stage,
                    ];
                    let total = stages.len();
                    let mut completed = Vec::new();
                    let mut findings = Vec::new();

                    for (idx, stage) in stages.iter().enumerate() {
                        let _ = tx.send(ScanEvent::StageStarted {
                            name: stage.name().to_string(),
                            index: idx + 1,
                            total,
                        });

                        let stage_result = match stage.run(&ctx) {
                            Ok(found) => {
                                for f in &found {
                                    let _ = tx.send(ScanEvent::FindingFound(f.clone()));
                                }
                                findings.extend(found.clone());
                                StageResult {
                                    stage_id: stage.id().to_string(),
                                    status: StageStatus::Ok,
                                    findings: found,
                                }
                            }
                            Err(e) => {
                                let err_finding = Finding {
                                    id: format!("FX-ERR-{}", stage.id().to_uppercase()),
                                    severity: Severity::High,
                                    confidence: crate::core::Confidence::High,
                                    stage: stage.id().to_string(),
                                    location: crate::core::Location::Device,
                                    reason: format!("Stage '{}' failed execution", stage.name()),
                                    evidence: e.to_string(),
                                };
                                let _ = tx.send(ScanEvent::FindingFound(err_finding.clone()));
                                findings.push(err_finding.clone());
                                StageResult {
                                    stage_id: stage.id().to_string(),
                                    status: StageStatus::Error(e.to_string()),
                                    findings: vec![err_finding],
                                }
                            }
                        };

                        let _ = tx.send(ScanEvent::StageFinished(stage_result.clone()));
                        completed.push(stage_result);
                    }

                    let required = [
                        device_stage.id(),
                        partition_stage.id(),
                        fs_stage.id(),
                        file_stage.id(),
                        policy_stage.id(),
                    ];
                    let verdict = crate::policy::resolve_verdict_with_policy(
                        &required, &completed, &findings, &policy,
                    );

                    let target_path = ctx.snapshot_path.unwrap_or(ctx.target_path);
                    let _ = tx.send(ScanEvent::ScanFinished {
                        verdict,
                        stages: completed,
                        findings,
                        scan_id,
                        target_path,
                    });
                }
                ScanMode::Egress => {
                    let egress_stage = crate::egress::EgressScanStage::new().with_verify_wipe(true);
                    let _ = tx.send(ScanEvent::StageStarted {
                        name: egress_stage.name().to_string(),
                        index: 1,
                        total: 1,
                    });

                    let mut findings = Vec::new();
                    let stage_result = match egress_stage.run(&ctx) {
                        Ok(found) => {
                            for f in &found {
                                let _ = tx.send(ScanEvent::FindingFound(f.clone()));
                            }
                            findings.extend(found.clone());
                            StageResult {
                                stage_id: egress_stage.id().to_string(),
                                status: StageStatus::Ok,
                                findings: found,
                            }
                        }
                        Err(e) => {
                            let err_finding = Finding {
                                id: format!("FX-ERR-{}", egress_stage.id().to_uppercase()),
                                severity: Severity::High,
                                confidence: crate::core::Confidence::High,
                                stage: egress_stage.id().to_string(),
                                location: crate::core::Location::Device,
                                reason: format!("Stage '{}' failed execution", egress_stage.name()),
                                evidence: e.to_string(),
                            };
                            let _ = tx.send(ScanEvent::FindingFound(err_finding.clone()));
                            findings.push(err_finding.clone());
                            StageResult {
                                stage_id: egress_stage.id().to_string(),
                                status: StageStatus::Error(e.to_string()),
                                findings: vec![err_finding],
                            }
                        }
                    };

                    let _ = tx.send(ScanEvent::StageFinished(stage_result.clone()));
                    let required = [egress_stage.id()];
                    let completed = vec![stage_result.clone()];
                    let verdict = crate::core::resolve_verdict(&required, &completed, &findings);

                    let _ = tx.send(ScanEvent::ScanFinished {
                        verdict,
                        stages: completed,
                        findings,
                        scan_id,
                        target_path: ctx.target_path,
                    });
                }
            }
        });
    }

    pub fn poll_scan_events(&mut self) {
        if self.screen == Screen::DeviceSelect
            && !self.is_entering_manual_device
            && self.last_device_refresh.elapsed() >= std::time::Duration::from_millis(1000)
        {
            self.refresh_devices();
            self.last_device_refresh = std::time::Instant::now();
        }

        if let Some(ref rx) = self.rx_event {
            while let Ok(event) = rx.try_recv() {
                match event {
                    ScanEvent::StageStarted { name, index, total } => {
                        self.current_stage_name = name.clone();
                        self.current_stage_index = index;
                        self.total_stages = total;
                        if total > 0 && index > 0 {
                            self.scan_progress_pct =
                                (((index - 1) as f32 / total as f32) * 100.0) as u16;
                        } else {
                            self.scan_progress_pct = 0;
                        }
                        self.scan_activity_log
                            .push(format!("[Stage {index}/{total}] Started: {name}"));
                    }
                    ScanEvent::Progress {
                        stage_id: _,
                        current,
                        total,
                        message,
                    } => {
                        if let Some(tot) = total {
                            if tot > 0 && self.total_stages > 0 && self.current_stage_index > 0 {
                                let base_pct = ((self.current_stage_index - 1) as f32
                                    / self.total_stages as f32)
                                    * 100.0;
                                let stage_slice = 100.0 / self.total_stages as f32;
                                let frac = (current as f32 / tot as f32).clamp(0.0, 1.0);
                                self.scan_progress_pct = (base_pct + frac * stage_slice) as u16;
                            }
                        }
                        if let Some(ref msg) = message {
                            if let Some(tot) = total {
                                self.current_stage_name = format!("{msg} ({current}/{tot})");
                            } else {
                                self.current_stage_name = msg.clone();
                            }
                            self.scan_activity_log.push(format!("  -> {msg}"));
                            if self.scan_activity_log.len() > 300 {
                                self.scan_activity_log.drain(0..100);
                            }
                        }
                    }
                    ScanEvent::FindingFound(f) => {
                        self.scan_activity_log.push(format!(
                            "  [!] Finding: {} - {} ({:?})",
                            f.id, f.reason, f.severity
                        ));
                        self.all_findings.push(f);
                    }
                    ScanEvent::StageFinished(res) => {
                        self.scan_activity_log.push(format!(
                            "[Stage Completed] {} ({} finding(s))",
                            res.stage_id,
                            res.findings.len()
                        ));
                        self.completed_stages.push(res);
                        if self.total_stages > 0 && self.current_stage_index > 0 {
                            self.scan_progress_pct =
                                ((self.current_stage_index as f32 / self.total_stages as f32)
                                    * 100.0) as u16;
                        }
                    }
                    ScanEvent::ScanFinished {
                        verdict,
                        stages,
                        findings,
                        scan_id,
                        target_path,
                    } => {
                        self.scan_activity_log
                            .push(format!("Scan completed. Final verdict: {verdict:?}"));
                        self.verdict = Some(verdict);
                        self.completed_stages = stages;
                        self.all_findings = findings;
                        self.scan_id = Some(scan_id);
                        self.snapshot_path = Some(target_path);
                        self.is_scanning = false;
                        self.scan_progress_pct = 100;
                        self.screen = Screen::Results;
                        self.selected_finding_idx = 0;
                    }
                    ScanEvent::ScanFailed(err) => {
                        self.scan_activity_log.push(format!("Scan failed: {err}"));
                        self.is_scanning = false;
                        self.status_message = Some(format!("Scan error: {err}"));
                        self.screen = Screen::Results;
                    }
                }
            }
        }
    }

    pub fn apply_triage_suppression(&mut self) -> Result<String, String> {
        let findings = self.filtered_findings();
        let finding = match findings.get(self.selected_finding_idx) {
            Some(f) => *f,
            None => return Err("No finding selected".to_string()),
        };

        if finding.severity == Severity::Critical {
            return Err("Critical findings cannot be suppressed".to_string());
        }

        if self.triage_reason_input.trim().is_empty() {
            return Err("A written reason is required".to_string());
        }

        let store_path = Path::new("suppressions.json");
        let mut store = SuppressionStore::load(store_path).unwrap_or_default();

        let now = current_timestamp();
        let expires_at = now + (90 * 86400);

        let sup_id = format!("SUP-{}", crate::manifest::generate_nonce());
        let author = if self.triage_author_input.trim().is_empty() {
            "operator".to_string()
        } else {
            self.triage_author_input.trim().to_string()
        };

        let scope = match &finding.location {
            crate::core::Location::Path(mp) => SuppressionScope::RuleAndPath {
                rule_id: finding.id.clone(),
                path_pattern: mp.to_string(),
            },
            _ => SuppressionScope::RuleAndPath {
                rule_id: finding.id.clone(),
                path_pattern: format!("location:{}", finding.location),
            },
        };

        let suppression = Suppression {
            id: sup_id.clone(),
            scope,
            reason: self.triage_reason_input.trim().to_string(),
            author,
            created_at: now,
            expires_at,
            signature: None,
        };

        store
            .add_suppression(suppression)
            .map_err(|e| format!("Failed to add suppression: {e}"))?;
        store
            .save(store_path)
            .map_err(|e| format!("Failed to save suppression: {e}"))?;

        self.triage_reason_input.clear();
        Ok(sup_id)
    }

    pub fn export_report(&mut self, html: bool) -> Result<String, String> {
        let scan_id = self.scan_id.as_deref().unwrap_or("scan-manual");
        let manifest = crate::manifest::Manifest {
            version: env!("CARGO_PKG_VERSION").to_string(),
            station_id: "station-local".to_string(),
            nonce: crate::manifest::generate_nonce(),
            issued_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + 86400,
            device_identity: None,
            device_size_bytes: 0,
            device_hash: String::new(),
            partition_layout_hash: String::new(),
            files: Vec::new(),
            policy_hash: self.policy.compute_hash(),
            stages_required: self
                .completed_stages
                .iter()
                .map(|s| s.stage_id.clone())
                .collect(),
            stages_completed: self.completed_stages.clone(),
            verdict: self.verdict.unwrap_or(Verdict::Quarantine),
            signature: None,
        };

        let ext = if html { "html" } else { "json" };
        let out_name = format!("{scan_id}-report.{ext}");
        let content = if html {
            crate::report::generate_html_report(&manifest, &self.all_findings)
                .map_err(|e| e.to_string())?
        } else {
            crate::report::generate_json_report(&manifest, &self.all_findings)
                .map_err(|e| e.to_string())?
        };

        fs::write(&out_name, content).map_err(|e| e.to_string())?;
        self.report_export_path = Some(out_name.clone());
        Ok(out_name)
    }

    pub fn release_verified_files(&mut self) -> Result<crate::release::ReleaseReport, String> {
        if self.verdict != Some(Verdict::Pass) {
            return Err("Release blocked: verdict is not PASS (fail closed).".to_string());
        }

        let snap_path = match self.snapshot_path {
            Some(ref p) => p.clone(),
            None => match self.selected_device() {
                Some(dev) => dev.path.clone(),
                None => return Err("No device or snapshot available to release.".to_string()),
            },
        };

        let dest_dir = PathBuf::from("released");
        let report = crate::release::release_snapshot_files(&snap_path, &dest_dir, 512)
            .map_err(|e| format!("Release error: {e}"))?;

        self.status_message = Some(format!(
            "Released {} files ({} bytes) to 'released/'",
            report.files_released, report.bytes_released
        ));

        Ok(report)
    }
}
