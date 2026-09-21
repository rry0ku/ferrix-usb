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
                ..Default::default()
            },
            DiscoveredFile {
                path: MediaPath::from("photos".as_bytes()),
                size: 0,
                is_dir: true,
                attributes: 0x10,
                partition_index: 1,
                data_offset: None,
                ..Default::default()
            },
            DiscoveredFile {
                path: MediaPath::from("photos/beach.jpg".as_bytes()),
                size: 2048,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(1024),
                ..Default::default()
            },
            DiscoveredFile {
                path: MediaPath::from("photos/trips/japan.png".as_bytes()),
                size: 4096,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(2048),
                ..Default::default()
            },
            DiscoveredFile {
                path: MediaPath::from("docs/report.pdf".as_bytes()),
                size: 8192,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(4096),
                ..Default::default()
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
                ..Default::default()
            },
            DiscoveredFile {
                path: MediaPath::from("file_root.txt".as_bytes()),
                size: 200,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: None,
                ..Default::default()
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

#[test]
fn test_status_message_auto_expiration() {
    let mut app = App::default();
    assert!(app.status_message.is_none());

    app.set_status("Temporary notification");
    assert_eq!(
        app.status_message.as_deref(),
        Some("Temporary notification")
    );
    assert!(app.status_message_time.is_some());

    app.poll_scan_events();
    assert_eq!(
        app.status_message.as_deref(),
        Some("Temporary notification")
    );

    app.status_message_time = Some(std::time::Instant::now() - std::time::Duration::from_secs(6));
    app.poll_scan_events();
    assert!(app.status_message.is_none());
    assert!(app.status_message_time.is_none());
}

#[test]
fn test_browse_contents_l_and_right_keys() {
    use ferrix_usb::core::MediaPath;
    use ferrix_usb::fs::DiscoveredFile;

    let mut app = App {
        screen: Screen::BrowseContents,
        browse_files: vec![DiscoveredFile {
            path: MediaPath::from("subfolder/doc.txt".as_bytes()),
            size: 50,
            is_dir: false,
            attributes: 0x20,
            partition_index: 1,
            data_offset: None,
            ..Default::default()
        }],
        ..Default::default()
    };

    let key_l = KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE);
    handle_key_event(&mut app, key_l);
    assert_eq!(app.browse_current_dir, "subfolder");

    let key_h = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE);
    handle_key_event(&mut app, key_h);
    assert_eq!(app.browse_current_dir, "");

    let key_right = KeyEvent::new(KeyCode::Right, KeyModifiers::NONE);
    handle_key_event(&mut app, key_right);
    assert_eq!(app.browse_current_dir, "subfolder");

    let key_left = KeyEvent::new(KeyCode::Left, KeyModifiers::NONE);
    handle_key_event(&mut app, key_left);
    assert_eq!(app.browse_current_dir, "");
}

#[test]
fn test_dos_and_exfat_timestamp_formatting() {
    use ferrix_usb::fs::exfat::format_exfat_datetime;
    use ferrix_usb::fs::fat::{format_dos_date, format_dos_datetime};

    let dos_date = (44 << 9) | (5 << 5) | 12;
    let dos_time = (14 << 11) | (30 << 5) | (20 / 2);
    let dt = format_dos_datetime(dos_date, dos_time);
    assert_eq!(dt, Some("2024-05-12 14:30:20".to_string()));

    let d = format_dos_date(dos_date);
    assert_eq!(d, Some("2024-05-12".to_string()));

    assert_eq!(format_dos_datetime(0, 0), None);
    assert_eq!(format_dos_date(0), None);

    let exfat_dt_no_tz = format_exfat_datetime(dos_date, dos_time, 0);
    assert_eq!(exfat_dt_no_tz, Some("2024-05-12 14:30:20".to_string()));

    let exfat_dt_with_tz = format_exfat_datetime(dos_date, dos_time, 0x80 | 22);
    assert_eq!(
        exfat_dt_with_tz,
        Some("2024-05-12 14:30:20 UTC+05:30".to_string())
    );
}

#[test]
fn test_browse_contents_metadata_and_scrolling() {
    use ferrix_usb::core::MediaPath;
    use ferrix_usb::fs::DiscoveredFile;

    let mut app = App {
        screen: Screen::BrowseContents,
        browse_files: vec![
            DiscoveredFile {
                path: MediaPath::from("doc.txt".as_bytes()),
                size: 94,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(0x2029D0000),
                created: Some("2024-05-12 14:30:00".to_string()),
                modified: Some("2024-05-12 15:45:00".to_string()),
                accessed: Some("2024-05-13".to_string()),
                starting_cluster: Some(16862),
                cluster_size: Some(4096),
                fs_type: Some("FAT32".to_string()),
                detected_type: Some("Plain Text".to_string()),
            },
            DiscoveredFile {
                path: MediaPath::from("doc2.txt".as_bytes()),
                size: 128,
                is_dir: false,
                attributes: 0x20,
                partition_index: 1,
                data_offset: Some(0x2029D1000),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let entries = app.current_dir_entries();
    assert_eq!(entries.len(), 2);
    let e = &entries[0];
    assert_eq!(e.created.as_deref(), Some("2024-05-12 14:30:00"));
    assert_eq!(e.modified.as_deref(), Some("2024-05-12 15:45:00"));
    assert_eq!(e.accessed.as_deref(), Some("2024-05-13"));
    assert_eq!(e.starting_cluster, Some(16862));
    assert_eq!(e.cluster_size, Some(4096));
    assert_eq!(e.fs_type.as_deref(), Some("FAT32"));
    assert_eq!(e.detected_type.as_deref(), Some("Plain Text"));

    assert_eq!(app.browse_detail_scroll, 0);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE),
    );
    assert_eq!(app.browse_detail_scroll, 1);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE),
    );
    assert_eq!(app.browse_detail_scroll, 2);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE),
    );
    assert_eq!(app.browse_detail_scroll, 1);
    handle_key_event(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.browse_detail_scroll, 0);
}

#[test]
fn test_browse_reentry_caching_and_escape_cancellation() {
    use ferrix_usb::core::MediaPath;
    use ferrix_usb::fs::DiscoveredFile;
    use ferrix_usb::tui::DeviceEntry;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    let mut app = App {
        devices: vec![DeviceEntry {
            path: PathBuf::from("/dev/sdb"),
            name: "sdb".to_string(),
            size_bytes: 1024 * 1024,
            vendor: "Vendor".to_string(),
            model: "Model".to_string(),
            serial: "12345".to_string(),
            is_removable: true,
            is_system_drive: false,
            mount_points: Vec::new(),
            sector_size: 512,
        }],
        selected_device_idx: 0,
        browse_target_path: PathBuf::from("/dev/sdb"),
        browse_target_name: "sdb".to_string(),
        browse_files: vec![DiscoveredFile {
            path: MediaPath::from("existing.txt".as_bytes()),
            size: 100,
            is_dir: false,
            attributes: 0x20,
            partition_index: 1,
            data_offset: None,
            ..Default::default()
        }],
        browse_loading: false,
        screen: Screen::DeviceSelect,
        ..Default::default()
    };

    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE),
    );
    assert_eq!(app.screen, Screen::BrowseContents);
    assert!(!app.browse_loading);
    assert_eq!(app.browse_files.len(), 1);
    assert!(app.rx_browse.is_none());

    handle_key_event(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.screen, Screen::DeviceSelect);
    assert!(app.browse_cancel.load(Ordering::SeqCst));
    assert!(!app.browse_loading);
    assert!(app.rx_browse.is_none());

    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE),
    );
    assert_eq!(app.screen, Screen::BrowseContents);
    assert!(!app.browse_loading);
    assert_eq!(app.browse_files.len(), 1);
}
