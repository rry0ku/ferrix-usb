use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::Low => write!(f, "LOW"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::High => write!(f, "HIGH"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MediaPath(pub Vec<u8>);

impl MediaPath {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn escaped(&self) -> String {
        escape_media_path(&self.0)
    }
}

impl From<Vec<u8>> for MediaPath {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for MediaPath {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<&str> for MediaPath {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<String> for MediaPath {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl fmt::Display for MediaPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.escaped())
    }
}

impl Serialize for MediaPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.escaped())
    }
}

impl<'de> Deserialize<'de> for MediaPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(MediaPath::from(s))
    }
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{FEFF}'
    )
}

fn escape_media_path(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        match std::str::from_utf8(&bytes[idx..]) {
            Ok(valid_str) => {
                for ch in valid_str.chars() {
                    escape_char(ch, &mut out);
                }
                break;
            }
            Err(err) => {
                let valid_len = err.valid_up_to();
                if valid_len > 0 {
                    if let Ok(valid_str) = std::str::from_utf8(&bytes[idx..idx + valid_len]) {
                        for ch in valid_str.chars() {
                            escape_char(ch, &mut out);
                        }
                    }
                    idx += valid_len;
                }
                if let Some(err_len) = err.error_len() {
                    for &b in &bytes[idx..idx + err_len] {
                        out.push_str(&format!("\\x{b:02x}"));
                    }
                    idx += err_len;
                } else {
                    for &b in &bytes[idx..] {
                        out.push_str(&format!("\\x{b:02x}"));
                    }
                    break;
                }
            }
        }
    }
    out
}

fn escape_char(ch: char, out: &mut String) {
    if ch.is_control() {
        if (ch as u32) <= 0x7f {
            out.push_str(&format!("\\x{:02x}", ch as u8));
        } else {
            out.push_str(&format!("\\u{{{:04x}}}", ch as u32));
        }
    } else if is_bidi_control(ch) {
        out.push_str(&format!("\\u{{{:04x}}}", ch as u32));
    } else {
        out.push(ch);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    Device,
    Partition(u32),
    Path(MediaPath),
    ByteOffset(u64),
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::Device => write!(f, "device"),
            Location::Partition(part) => write!(f, "partition {part}"),
            Location::Path(path) => write!(f, "{path}"),
            Location::ByteOffset(offset) => write!(f, "offset 0x{offset:x}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub stage: String,
    pub location: Location,
    pub reason: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Quarantine,
    Fail,
}

impl Verdict {
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Pass => 0,
            Verdict::Quarantine => 10,
            Verdict::Fail => 20,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Pass => write!(f, "PASS"),
            Verdict::Quarantine => write!(f, "QUARANTINE"),
            Verdict::Fail => write!(f, "FAIL"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Ok,
    Error(String),
    Skipped,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageResult {
    pub stage_id: String,
    pub status: StageStatus,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum StageError {
    #[error("I/O error during stage execution: {0}")]
    Io(String),

    #[error("Parser error: {0}")]
    Parse(String),

    #[error("Stage timed out")]
    Timeout,

    #[error("Internal stage failure: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanEvent {
    Progress {
        stage_id: String,
        current: u64,
        total: Option<u64>,
        message: Option<String>,
    },
    Finding(Finding),
}

#[derive(Debug, Clone)]
pub struct EventSink {
    sender: Option<Sender<ScanEvent>>,
}

impl EventSink {
    pub fn new(sender: Sender<ScanEvent>) -> Self {
        Self {
            sender: Some(sender),
        }
    }

    pub fn noop() -> Self {
        Self { sender: None }
    }

    pub fn emit(&self, event: ScanEvent) {
        if let Some(ref s) = self.sender {
            let _ = s.send(event);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub target_path: PathBuf,
    pub snapshot_path: Option<PathBuf>,
    pub read_only: bool,
    pub event_sink: EventSink,
}

impl ScanContext {
    pub fn new(target_path: PathBuf) -> Self {
        Self {
            target_path,
            snapshot_path: None,
            read_only: true,
            event_sink: EventSink::noop(),
        }
    }

    pub fn with_event_sink(mut self, event_sink: EventSink) -> Self {
        self.event_sink = event_sink;
        self
    }
}

pub trait Stage: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, StageError>;
}

pub fn resolve_verdict(
    required_stages: &[&str],
    completed_stages: &[StageResult],
    findings: &[Finding],
) -> Verdict {
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return Verdict::Fail;
    }

    for required in required_stages {
        match completed_stages.iter().find(|s| s.stage_id == *required) {
            Some(res) => {
                if res.status != StageStatus::Ok {
                    return Verdict::Quarantine;
                }
            }
            None => {
                return Verdict::Quarantine;
            }
        }
    }

    for stage in completed_stages {
        if stage.status != StageStatus::Ok {
            return Verdict::Quarantine;
        }
    }

    if findings.iter().any(|f| f.severity == Severity::High) {
        return Verdict::Quarantine;
    }

    Verdict::Pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    fn make_finding(id: &str, severity: Severity) -> Finding {
        Finding {
            id: id.to_string(),
            severity,
            confidence: Confidence::High,
            stage: "test_stage".to_string(),
            location: Location::Device,
            reason: "test finding".to_string(),
            evidence: "evidence details".to_string(),
        }
    }

    fn make_stage_result(id: &str, status: StageStatus) -> StageResult {
        StageResult {
            stage_id: id.to_string(),
            status,
            findings: Vec::new(),
        }
    }

    #[test]
    fn test_all_stages_ok_no_findings_passes() {
        let required = ["snapshot", "partition", "filesystem", "file_layer"];
        let completed = vec![
            make_stage_result("snapshot", StageStatus::Ok),
            make_stage_result("partition", StageStatus::Ok),
            make_stage_result("filesystem", StageStatus::Ok),
            make_stage_result("file_layer", StageStatus::Ok),
        ];
        let findings = vec![];

        assert_eq!(
            resolve_verdict(&required, &completed, &findings),
            Verdict::Pass
        );
    }

    #[test]
    fn test_info_low_medium_findings_passes() {
        let required = ["snapshot", "partition"];
        let completed = vec![
            make_stage_result("snapshot", StageStatus::Ok),
            make_stage_result("partition", StageStatus::Ok),
        ];
        let findings = vec![
            make_finding("FX-PART-001", Severity::Info),
            make_finding("FX-PART-002", Severity::Low),
            make_finding("FX-PART-003", Severity::Medium),
        ];

        assert_eq!(
            resolve_verdict(&required, &completed, &findings),
            Verdict::Pass
        );
    }

    #[test]
    fn test_high_finding_quarantines() {
        let required = ["snapshot"];
        let completed = vec![make_stage_result("snapshot", StageStatus::Ok)];
        let findings = vec![make_finding("FX-PART-004", Severity::High)];

        assert_eq!(
            resolve_verdict(&required, &completed, &findings),
            Verdict::Quarantine
        );
    }

    #[test]
    fn test_critical_finding_fails() {
        let required = ["snapshot"];
        let completed = vec![make_stage_result("snapshot", StageStatus::Ok)];
        let findings = vec![make_finding("FX-DEV-001", Severity::Critical)];

        assert_eq!(
            resolve_verdict(&required, &completed, &findings),
            Verdict::Fail
        );
    }

    #[test]
    fn test_critical_overrides_high_and_stage_error() {
        let required = ["snapshot"];
        let completed = vec![make_stage_result(
            "snapshot",
            StageStatus::Error("read error".to_string()),
        )];
        let findings = vec![
            make_finding("FX-DEV-001", Severity::Critical),
            make_finding("FX-PART-002", Severity::High),
        ];

        assert_eq!(
            resolve_verdict(&required, &completed, &findings),
            Verdict::Fail
        );
    }

    #[test]
    fn test_stage_error_on_required_stage_never_passes() {
        let required = ["snapshot", "partition"];
        let completed = vec![
            make_stage_result("snapshot", StageStatus::Ok),
            make_stage_result(
                "partition",
                StageStatus::Error("corrupted table".to_string()),
            ),
        ];
        let findings = vec![];

        let verdict = resolve_verdict(&required, &completed, &findings);
        assert_ne!(verdict, Verdict::Pass);
        assert_eq!(verdict, Verdict::Quarantine);
    }

    #[test]
    fn test_stage_error_on_optional_stage_never_passes() {
        let required = ["snapshot"];
        let completed = vec![
            make_stage_result("snapshot", StageStatus::Ok),
            make_stage_result("extra", StageStatus::Error("crash".to_string())),
        ];
        let findings = vec![];

        let verdict = resolve_verdict(&required, &completed, &findings);
        assert_ne!(verdict, Verdict::Pass);
        assert_eq!(verdict, Verdict::Quarantine);
    }

    #[test]
    fn test_skipped_required_stage_never_passes() {
        let required = ["snapshot", "partition"];
        let completed = vec![
            make_stage_result("snapshot", StageStatus::Ok),
            make_stage_result("partition", StageStatus::Skipped),
        ];
        let findings = vec![];

        let verdict = resolve_verdict(&required, &completed, &findings);
        assert_ne!(verdict, Verdict::Pass);
        assert_eq!(verdict, Verdict::Quarantine);
    }

    #[test]
    fn test_timed_out_stage_never_passes() {
        let required = ["snapshot"];
        let completed = vec![make_stage_result("snapshot", StageStatus::TimedOut)];
        let findings = vec![];

        let verdict = resolve_verdict(&required, &completed, &findings);
        assert_ne!(verdict, Verdict::Pass);
        assert_eq!(verdict, Verdict::Quarantine);
    }

    #[test]
    fn test_missing_required_stage_never_passes() {
        let required = ["snapshot", "partition"];
        let completed = vec![make_stage_result("snapshot", StageStatus::Ok)];
        let findings = vec![];

        let verdict = resolve_verdict(&required, &completed, &findings);
        assert_ne!(verdict, Verdict::Pass);
        assert_eq!(verdict, Verdict::Quarantine);
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(Verdict::Pass.exit_code(), 0);
        assert_eq!(Verdict::Quarantine.exit_code(), 10);
        assert_eq!(Verdict::Fail.exit_code(), 20);
    }

    #[test]
    fn test_media_path_normal() {
        let p = MediaPath::from("photos/vacation.jpg");
        assert_eq!(p.escaped(), "photos/vacation.jpg");
        assert_eq!(p.to_string(), "photos/vacation.jpg");
    }

    #[test]
    fn test_media_path_terminal_escape() {
        let raw = b"\x1b[31;1mexploit.sh\x1b[0m";
        let p = MediaPath::from(&raw[..]);
        assert_eq!(p.escaped(), "\\x1b[31;1mexploit.sh\\x1b[0m");
        assert!(!p.escaped().contains('\x1b'));
    }

    #[test]
    fn test_media_path_bidi_override() {
        let hostile = "document\u{202E}fdp.exe";
        let p = MediaPath::from(hostile);
        assert_eq!(p.escaped(), "document\\u{202e}fdp.exe");
        assert!(!p.escaped().contains('\u{202E}'));
    }

    #[test]
    fn test_media_path_control_characters() {
        let raw = b"test\x00file\x07\r\n.txt";
        let p = MediaPath::from(&raw[..]);
        assert_eq!(p.escaped(), "test\\x00file\\x07\\x0d\\x0a.txt");
    }

    #[test]
    fn test_media_path_non_utf8() {
        let raw = b"invalid_\x80\xfe\xff_name.dat";
        let p = MediaPath::from(&raw[..]);
        assert_eq!(p.escaped(), "invalid_\\x80\\xfe\\xff_name.dat");
    }

    #[test]
    fn test_media_path_legitimate_unicode() {
        let path = "दस्तावेज़/中文/ملف.pdf";
        let p = MediaPath::from(path);
        assert_eq!(p.escaped(), "दस्तावेज़/中文/ملف.pdf");
    }

    #[test]
    fn test_media_path_serde_json() {
        let raw = "evil\x1b[32m\u{202E}name.txt".as_bytes();
        let finding = Finding {
            id: "FX-FILE-001".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_layer".to_string(),
            location: Location::Path(MediaPath::from(raw)),
            reason: "hostile filename".to_string(),
            evidence: "escape sequences".to_string(),
        };

        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("evil\\\\x1b[32m\\\\u{202e}name.txt"));
        assert!(!json.contains('\x1b'));
        assert!(!json.contains('\u{202E}'));

        let deserialized: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, finding.id);
        assert_eq!(deserialized.severity, finding.severity);
        assert_eq!(
            deserialized.location.to_string(),
            finding.location.to_string()
        );
    }

    #[test]
    fn test_event_sink() {
        let (tx, rx) = channel();
        let sink = EventSink::new(tx);
        let ctx = ScanContext::new(PathBuf::from("/dev/sdb")).with_event_sink(sink);

        ctx.event_sink.emit(ScanEvent::Progress {
            stage_id: "partition".to_string(),
            current: 1,
            total: Some(2),
            message: Some("scanning".to_string()),
        });

        let event = rx.recv().unwrap();
        match event {
            ScanEvent::Progress {
                stage_id,
                current,
                total,
                message,
            } => {
                assert_eq!(stage_id, "partition");
                assert_eq!(current, 1);
                assert_eq!(total, Some(2));
                assert_eq!(message, Some("scanning".to_string()));
            }
            _ => panic!("unexpected event"),
        }

        let noop_ctx = ScanContext::new(PathBuf::from("/dev/sdb"));
        noop_ctx.event_sink.emit(ScanEvent::Progress {
            stage_id: "none".to_string(),
            current: 0,
            total: None,
            message: None,
        });
    }
}
