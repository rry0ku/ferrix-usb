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

#[test]
fn test_app_eta_calculation_and_smoothing() {
    use ferrix_usb::tui::app::ScanEvent;
    use std::sync::mpsc::channel;

    let mut app = App::default();
    let (tx, rx) = channel();
    app.rx_event = Some(rx);

    tx.send(ScanEvent::StageStarted {
        name: "Acquiring Snapshot".to_string(),
        index: 1,
        total: 4,
    })
    .unwrap();
    app.poll_scan_events();
    assert!(app.stage_start_time.is_some());

    app.last_progress_time =
        Some(std::time::Instant::now() - std::time::Duration::from_millis(600));
    tx.send(ScanEvent::Progress {
        stage_id: "snapshot".to_string(),
        current: 10 * 1024 * 1024,
        total: Some(100 * 1024 * 1024),
        message: None,
    })
    .unwrap();
    app.poll_scan_events();

    assert!(app.transfer_speed_bps > 0.0);
    assert!(app.estimated_eta_seconds.is_some());

    tx.send(ScanEvent::StageStarted {
        name: "Partition inspection".to_string(),
        index: 2,
        total: 4,
    })
    .unwrap();
    app.poll_scan_events();

    assert_eq!(app.transfer_speed_bps, 0.0);
    assert_eq!(app.estimated_eta_seconds, None);

    tx.send(ScanEvent::Progress {
        stage_id: "partition".to_string(),
        current: 2,
        total: Some(2),
        message: None,
    })
    .unwrap();
    app.poll_scan_events();

    assert_eq!(app.estimated_eta_seconds, Some(0));
}

#[test]
fn test_browse_contents_current_dir_entries_and_sorting() {
    use ferrix_usb::core::MediaPath;
    use ferrix_usb::fs::DiscoveredFile;

    let mut app = App {
        browse_files: vec![
            DiscoveredFile {
                path: MediaPath::from("file_root.txt".as_bytes()),
                size: 1024,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(512),
            },
            DiscoveredFile {
                path: MediaPath::from("photos".as_bytes()),
                size: 0,
                is_dir: true,
                attributes: 0x10,
                partition_index: 1,
                data_offset: None,
            },
            DiscoveredFile {
                path: MediaPath::from("photos/beach.jpg".as_bytes()),
                size: 2048,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(1024),
            },
            DiscoveredFile {
                path: MediaPath::from("photos/trips/japan.png".as_bytes()),
                size: 4096,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(2048),
            },
            DiscoveredFile {
                path: MediaPath::from("docs/report.pdf".as_bytes()),
                size: 8192,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(4096),
            },
        ],
        ..Default::default()
    };

    let root_entries = app.current_dir_entries();
    assert_eq!(root_entries.len(), 3);
    assert_eq!(root_entries[0].name, "docs");
    assert!(root_entries[0].is_dir);
    assert_eq!(root_entries[1].name, "photos");
    assert!(root_entries[1].is_dir);
    assert_eq!(root_entries[2].name, "file_root.txt");
    assert!(!root_entries[2].is_dir);

    app.browse_current_dir = "photos".to_string();
    let photo_entries = app.current_dir_entries();
    assert_eq!(photo_entries.len(), 3);
    assert_eq!(photo_entries[0].name, "..");
    assert!(photo_entries[0].is_dir);
    assert_eq!(photo_entries[0].full_path, "");
    assert_eq!(photo_entries[1].name, "trips");
    assert!(photo_entries[1].is_dir);
    assert_eq!(photo_entries[2].name, "beach.jpg");
    assert!(!photo_entries[2].is_dir);

    app.browse_current_dir = "photos/trips".to_string();
    let trip_entries = app.current_dir_entries();
    assert_eq!(trip_entries.len(), 2);
    assert_eq!(trip_entries[0].name, "..");
    assert_eq!(trip_entries[0].full_path, "photos");
    assert_eq!(trip_entries[1].name, "japan.png");
    assert!(!trip_entries[1].is_dir);
}

#[test]
fn test_browse_contents_key_navigation() {
    use ferrix_usb::core::MediaPath;
    use ferrix_usb::fs::DiscoveredFile;

    let mut app = App {
        screen: Screen::BrowseContents,
        browse_files: vec![
            DiscoveredFile {
                path: MediaPath::from("folder1/file.txt".as_bytes()),
                size: 100,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: None,
            },
            DiscoveredFile {
                path: MediaPath::from("file_root.txt".as_bytes()),
                size: 200,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: None,
            },
        ],
        ..Default::default()
    };

    assert_eq!(app.browse_selected_idx, 0);
    let key_enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
    handle_key_event(&mut app, key_enter);
    assert_eq!(app.browse_current_dir, "folder1");
    assert_eq!(app.browse_selected_idx, 0);

    let key_down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    handle_key_event(&mut app, key_down);
    assert_eq!(app.browse_selected_idx, 1);

    handle_key_event(&mut app, key_enter);
    assert!(app.status_message.is_some());
    assert!(app
        .status_message
        .as_ref()
        .unwrap()
        .contains("File preview disabled for security"));

    let key_backspace = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);
    handle_key_event(&mut app, key_backspace);
    assert_eq!(app.browse_current_dir, "");

    let key_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE);
    handle_key_event(&mut app, key_s);
    assert_eq!(app.screen, Screen::ModeSelect);

    let key_esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
    handle_key_event(&mut app, key_esc);
    assert_eq!(app.screen, Screen::DeviceSelect);
}
