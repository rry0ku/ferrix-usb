use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ferrix_usb::core::{Confidence, Finding, Location, Severity};
use ferrix_usb::tui::{
    handle_key_event, sanitize_single_line, sanitize_terminal_string, App, ScanMode, Screen,
};
use std::fs;

#[test]
fn test_terminal_string_sanitization_ansi_and_control() {
    let raw = "\x1b[31;1mRedAlert\x1b[0m\x07\x00NullBell";
    let sanitized = sanitize_terminal_string(raw);
    assert_eq!(sanitized, "RedAlert\\x07\\x00NullBell");
    assert!(!sanitized.contains('\x1b'));
}

#[test]
fn test_terminal_string_sanitization_bidi_overrides() {
    let raw = "photo\u{202E}fdp.exe";
    let sanitized = sanitize_terminal_string(raw);
    assert_eq!(sanitized, "photo[RLO]fdp.exe");

    let raw_isolate = "test\u{2066}rtl\u{2069}end";
    let sanitized_isolate = sanitize_terminal_string(raw_isolate);
    assert_eq!(sanitized_isolate, "test[LRI]rtl[PDI]end");
}

#[test]
fn test_sanitize_single_line() {
    let raw = "line1\nline2\tline3";
    let sanitized = sanitize_single_line(raw);
    assert_eq!(sanitized, "line1 line2    line3");
}

#[test]
fn test_app_state_navigation() {
    let mut app = App::default();
    assert_eq!(app.screen, Screen::DeviceSelect);

    let key_m = KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE);
    handle_key_event(&mut app, key_m);
    assert!(app.is_entering_manual_device);

    for c in "/dev/sdb".chars() {
        let key_char = KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
        handle_key_event(&mut app, key_char);
    }
    assert_eq!(app.manual_device_input, "/dev/sdb");

    let key_enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
    handle_key_event(&mut app, key_enter);
    assert_eq!(app.screen, Screen::ModeSelect);

    let key_2 = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
    handle_key_event(&mut app, key_2);
    assert_eq!(app.mode, ScanMode::Egress);

    let key_1 = KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE);
    handle_key_event(&mut app, key_1);
    assert_eq!(app.mode, ScanMode::Ingress);
}

#[test]
fn test_app_filtered_findings_and_info_toggle() {
    let mut app = App {
        all_findings: vec![
            Finding {
                id: "FX-INFO-001".to_string(),
                severity: Severity::Info,
                confidence: Confidence::Low,
                stage: "test".to_string(),
                location: Location::Device,
                reason: "info finding".to_string(),
                evidence: "evidence".to_string(),
            },
            Finding {
                id: "FX-HIGH-001".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "test".to_string(),
                location: Location::Device,
                reason: "high finding".to_string(),
                evidence: "evidence".to_string(),
            },
        ],
        ..Default::default()
    };

    assert_eq!(app.filtered_findings().len(), 1);
    assert_eq!(app.filtered_findings()[0].id, "FX-HIGH-001");

    let key_i = KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE);
    app.screen = Screen::Results;
    handle_key_event(&mut app, key_i);

    assert!(app.show_info_findings);
    assert_eq!(app.filtered_findings().len(), 2);
}

#[test]
fn test_app_triage_suppression_flow() {
    let mut app = App {
        screen: Screen::Results,
        all_findings: vec![Finding {
            id: "FX-FILE-003".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            stage: "file_scan".to_string(),
            location: Location::Device,
            reason: "hidden executable".to_string(),
            evidence: "dotfile with ELF".to_string(),
        }],
        ..Default::default()
    };

    let key_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
    handle_key_event(&mut app, key_t);
    assert_eq!(app.screen, Screen::Triage);

    app.triage_reason_input = "authorized diagnostic utility".to_string();
    app.triage_author_input = "sec-officer".to_string();

    let res = app.apply_triage_suppression();
    assert!(res.is_ok());

    let _ = fs::remove_file("suppressions.json");
}

#[test]
fn test_terminal_string_sanitization_osc_and_dcs() {
    let osc52 = "\x1b]52;c;evil_clipboard_payload\x07CleanText";
    let sanitized = sanitize_terminal_string(osc52);
    assert_eq!(sanitized, "CleanText");

    let osc_title = "\x1b]0;EvilTitle\x1b\\NormalText";
    let sanitized_title = sanitize_terminal_string(osc_title);
    assert_eq!(sanitized_title, "NormalText");

    let dcs = "\x1bPEvilDcs\x1b\\AfterDcs";
    let sanitized_dcs = sanitize_terminal_string(dcs);
    assert_eq!(sanitized_dcs, "AfterDcs");
}
