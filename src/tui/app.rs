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
}

pub enum ScanEvent {
    StageStarted {
        name: String,
        index: usize,
        total: usize,
    },
    FindingFound(Finding),
    StageFinished(StageResult),
    ScanFinished {
        verdict: Verdict,
        stages: Vec<StageResult>,
        findings: Vec<Finding>,
        scan_id: String,
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
    pub completed_stages: Vec<StageResult>,
    pub all_findings: Vec<Finding>,
    pub selected_finding_idx: usize,
    pub show_info_findings: bool,
    pub verdict: Option<Verdict>,
    pub scan_id: Option<String>,
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
            completed_stages: Vec::new(),
            all_findings: Vec::new(),
            selected_finding_idx: 0,
            show_info_findings: false,
            verdict: None,
            scan_id: None,
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

                list.push(DeviceEntry {
                    path: dev_path,
                    name,
                    size_bytes,
                    vendor,
                    model,
                    serial,
                    is_removable,
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
                        let name = path.file_name().unwrap().to_string_lossy().to_string();
                        list.push(DeviceEntry {
                            path: path.clone(),
                            name,
                            size_bytes,
                            vendor: "Local File".to_string(),
                            model: "Disk Image".to_string(),
                            serial: String::new(),
                            is_removable: true,
                        });
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
        self.completed_stages.clear();
        self.all_findings.clear();
        self.verdict = None;
        self.status_message = None;

        let (tx, rx): (Sender<ScanEvent>, Receiver<ScanEvent>) = channel();
        self.rx_event = Some(rx);

        let mode = self.mode;
        let policy = self.policy.clone();

        thread::spawn(move || {
            let ctx = crate::core::ScanContext::new(target_path.clone());

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let scan_id = format!("scan-{now}-{}", crate::manifest::generate_nonce());

            match mode {
                ScanMode::Ingress => {
                    let device_stage = crate::device::DeviceScanStage::new(policy.clone());
                    let partition_stage = crate::disk::PartitionScanStage::default();
                    let fs_stage = crate::fs::FilesystemScanStage::default();
                    let file_stage = crate::scan::FileScanStage::default();
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
                    let verdict = crate::core::resolve_verdict(&required, &completed, &findings);

                    let _ = tx.send(ScanEvent::ScanFinished {
                        verdict,
                        stages: completed,
                        findings,
                        scan_id,
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
                        self.current_stage_name = name;
                        self.scan_progress_pct = ((index as f32 / total as f32) * 100.0) as u16;
                    }
                    ScanEvent::FindingFound(f) => {
                        self.all_findings.push(f);
                    }
                    ScanEvent::StageFinished(res) => {
                        self.completed_stages.push(res);
                    }
                    ScanEvent::ScanFinished {
                        verdict,
                        stages,
                        findings,
                        scan_id,
                    } => {
                        self.verdict = Some(verdict);
                        self.completed_stages = stages;
                        self.all_findings = findings;
                        self.scan_id = Some(scan_id);
                        self.is_scanning = false;
                        self.scan_progress_pct = 100;
                        self.screen = Screen::Results;
                        self.selected_finding_idx = 0;
                    }
                    ScanEvent::ScanFailed(err) => {
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
}
