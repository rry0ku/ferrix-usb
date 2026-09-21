use crate::core::{Severity, Verdict};
use crate::tui::app::{App, ScanMode, Screen};
use crate::tui::sanitize::sanitize_single_line;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use ratatui::Frame;

pub fn draw_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.area());

    draw_header(f, chunks[0]);

    match app.screen {
        Screen::DeviceSelect => draw_device_select(f, chunks[1], app),
        Screen::ModeSelect => draw_mode_select(f, chunks[1], app),
        Screen::BrowseContents => draw_browse_contents(f, chunks[1], app),
        Screen::Scanning => draw_scanning(f, chunks[1], app),
        Screen::Results => draw_results(f, chunks[1], app),
        Screen::Report => draw_report(f, chunks[1], app),
        Screen::Triage => {
            draw_results(f, chunks[1], app);
            draw_triage_modal(f, app);
        }
    }

    draw_footer(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "ferrix-usb ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "•  Offline Removable Media Security Station",
            Style::default().fg(Color::White),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Left);

    f.render_widget(header, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let hints = match app.screen {
        Screen::DeviceSelect => {
            if app.is_entering_manual_device {
                "[Enter] Confirm Path  [Esc] Cancel  [q] Quit"
            } else {
                "[Enter] Select  [v] Browse Files  [m] Manual Path  [u] Unmount Drive  [r] Refresh  [q] Quit"
            }
        }
        Screen::ModeSelect => "[1] Ingress  [2] Egress  [v] Browse Files  [Enter] Start Scan  [Esc] Back  [q] Quit",
        Screen::BrowseContents => {
            "[↑/↓/j/k] Navigate  [Enter/l] Open Dir  [Backspace/h] Up  [J/K] Scroll Details  [s] Start Scan  [Esc] Back  [q] Quit"
        }
        Screen::Scanning => "Scanning in progress... Please wait. [q] Cancel",
        Screen::Results => {
            "[↑/↓/j/k] Navigate  [i] Toggle Info  [t] Triage False Positive  [p] Export Report  [Esc] Device Select  [q] Quit"
        }
        Screen::Report => "[j] Export JSON  [h] Export HTML  [Esc] Back to Results  [q] Quit",
        Screen::Triage => "[Tab] Switch Field  [Enter] Confirm Suppression  [Esc] Cancel",
    };

    let footer = if let Some(ref msg) = app.status_message {
        let msg_lower = msg.to_lowercase();
        let (prefix, prefix_color) = if msg_lower.contains("error") || msg_lower.contains("failed")
        {
            ("Error: ", Color::LightRed)
        } else if msg_lower.contains("success")
            || msg_lower.contains("unmounted")
            || msg_lower.contains("released")
        {
            ("Success: ", Color::LightGreen)
        } else {
            ("Notice: ", Color::LightYellow)
        };

        Paragraph::new(Line::from(vec![
            Span::styled(
                prefix,
                Style::default()
                    .fg(prefix_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                msg,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  •  {hints}"),
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .block(Block::default().borders(Borders::ALL))
    } else {
        Paragraph::new(Line::from(vec![
            Span::styled(
                "Keys: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(hints, Style::default().fg(Color::White)),
        ]))
        .block(Block::default().borders(Borders::ALL))
    };

    f.render_widget(footer, area);
}

fn draw_device_select(f: &mut Frame, area: Rect, app: &mut App) {
    if app.is_entering_manual_device {
        let block = Block::default()
            .title(" Enter Path to Block Device or Disk Image ")
            .borders(Borders::ALL);
        let text = vec![
            Line::from(
                "Type the path to the target raw block device (e.g. /dev/sdb) or disk image:",
            ),
            Line::from(""),
            Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    &app.manual_device_input,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("█", Style::default().fg(Color::Yellow)),
            ]),
        ];
        let p = Paragraph::new(text).block(block);
        f.render_widget(p, area);
        return;
    }

    let items: Vec<ListItem> = if app.devices.is_empty() {
        vec![
            ListItem::new(Line::from("")),
            ListItem::new(Line::from(vec![Span::styled(
                "  No removable storage devices detected.",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )])),
            ListItem::new(Line::from("")),
            ListItem::new(Line::from(vec![Span::styled(
                "  • Insert a USB drive or SD card to begin inspection.",
                Style::default().fg(Color::DarkGray),
            )])),
            ListItem::new(Line::from(vec![
                Span::styled("  • Press ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "[m]",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " to enter a block device or disk image path manually (e.g. /dev/sdb).",
                    Style::default().fg(Color::DarkGray),
                ),
            ])),
            ListItem::new(Line::from(vec![
                Span::styled("  • Press ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "[r]",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " to refresh device detection.",
                    Style::default().fg(Color::DarkGray),
                ),
            ])),
        ]
    } else {
        app.devices
            .iter()
            .enumerate()
            .map(|(idx, dev)| {
                let is_selected = idx == app.selected_device_idx;
                let marker = if is_selected { "▶ " } else { "  " };

                let size_mb = dev.size_bytes / (1024 * 1024);
                let size_str = if size_mb > 1024 {
                    format!("{:.1} GB", size_mb as f64 / 1024.0)
                } else {
                    format!("{size_mb} MB")
                };

                let mount_tag = if dev.is_system_drive {
                    " [HOST OS DRIVE - PROTECTED]".to_string()
                } else if dev.size_bytes == 0 && !dev.path.starts_with("/sys/bus/usb/devices/") {
                    " [NO MEDIA / EMPTY]".to_string()
                } else if !dev.mount_points.is_empty() {
                    format!(" [MOUNTED at {} - UNSAFE]", dev.mount_points.join(", "))
                } else {
                    " [Unmounted]".to_string()
                };

                let vendor_model = match (dev.vendor.trim(), dev.model.trim()) {
                    ("", "") => "Removable Storage Device".to_string(),
                    (v, "") => v.to_string(),
                    ("", m) => m.to_string(),
                    (v, m) => format!("{v} {m}"),
                };

                let text = format!(
                    "{marker}{} ({}) - {} [serial: {}]{}",
                    dev.name,
                    size_str,
                    vendor_model,
                    if dev.serial.is_empty() {
                        "none"
                    } else {
                        &dev.serial
                    },
                    mount_tag
                );

                let style = if is_selected {
                    if dev.is_system_drive {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else if !dev.mount_points.is_empty() {
                        Style::default()
                            .fg(Color::LightRed)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    }
                } else if dev.is_system_drive {
                    Style::default().fg(Color::DarkGray)
                } else if !dev.mount_points.is_empty() {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::White)
                };

                ListItem::new(text).style(style)
            })
            .collect()
    };

    let title = format!(" Detected Storage Media & Images ({}) ", app.devices.len());
    let list = List::new(items).block(Block::default().title(title).borders(Borders::ALL));

    if app.devices.is_empty() {
        app.device_list_state.select(None);
    } else {
        let sel = app.selected_device_idx.min(app.devices.len() - 1);
        app.device_list_state.select(Some(sel));
    }
    f.render_stateful_widget(list, area, &mut app.device_list_state);

    if !app.devices.is_empty() {
        let mut scrollbar_state = ScrollbarState::new(app.devices.len().saturating_sub(1))
            .position(app.selected_device_idx);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"));
        f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }
}

fn draw_mode_select(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);

    let dev_name = app
        .selected_device()
        .map(|d| d.path.display().to_string())
        .unwrap_or_else(|| app.manual_device_input.clone());

    let ingress_style = if app.mode == ScanMode::Ingress {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let egress_style = if app.mode == ScanMode::Egress {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mode_text = vec![
        Line::from(vec![
            Span::styled("Target Media: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                dev_name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                if app.mode == ScanMode::Ingress {
                    "[*] 1. Ingress Mode "
                } else {
                    "[ ] 1. Ingress Mode "
                },
                ingress_style,
            ),
            Span::raw("- Vet incoming media before crossing security boundary into secure network"),
        ]),
        Line::from(vec![
            Span::styled(
                if app.mode == ScanMode::Egress {
                    "[*] 2. Egress Mode  "
                } else {
                    "[ ] 2. Egress Mode  "
                },
                egress_style,
            ),
            Span::raw(
                "- Check media for leftover remnants, verify wipe patterns, and detect metadata",
            ),
        ]),
    ];

    let p_mode = Paragraph::new(mode_text).block(
        Block::default()
            .title(" Step 2: Select Inspection Mode ")
            .borders(Borders::ALL),
    );
    f.render_widget(p_mode, chunks[0]);

    let policy_text = vec![
        Line::from(vec![
            Span::styled("Active Policy: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                &app.policy.name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(format!(
            "Allowed Filesystems: {:?}",
            app.policy.allowed_filesystems
        )),
        Line::from(format!("Max Partitions: {}", app.policy.max_partitions)),
        Line::from(format!(
            "Allowed File Types: {:?}",
            app.policy.allowed_types
        )),
        Line::from(format!("Max File Size: {} MB", app.policy.max_file_size_mb)),
        Line::from(""),
        Line::from(Span::styled(
            "Press [Enter] to start scan.",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    let p_policy = Paragraph::new(policy_text).block(
        Block::default()
            .title(" Active Security Policy ")
            .borders(Borders::ALL),
    );
    f.render_widget(p_policy, chunks[1]);
}

fn draw_scanning(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(8)])
        .split(area);

    let eta_str = if let Some(eta_secs) = app.estimated_eta_seconds {
        if eta_secs >= 3600 {
            format!(
                " • ETA: {:02}:{:02}:{:02}",
                eta_secs / 3600,
                (eta_secs % 3600) / 60,
                eta_secs % 60
            )
        } else {
            format!(" • ETA: {:02}:{:02}", eta_secs / 60, eta_secs % 60)
        }
    } else {
        String::new()
    };

    let speed_str = if app.transfer_speed_bps > 1024.0 {
        let mbps = app.transfer_speed_bps / (1024.0 * 1024.0);
        format!(" • {:.1} MB/s", mbps)
    } else {
        String::new()
    };

    let max_label_len = chunks[0].width.saturating_sub(10) as usize;
    let stage_name = if app.current_stage_name.len() > max_label_len && max_label_len > 12 {
        format!("{}...", &app.current_stage_name[..max_label_len - 3])
    } else {
        app.current_stage_name.clone()
    };

    let gauge_label = format!(
        "{}%{eta_str}{speed_str} - {stage_name}",
        app.scan_progress_pct
    );

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" Scan Progress ")
                .borders(Borders::ALL),
        )
        .gauge_style(
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .percent(app.scan_progress_pct)
        .label(gauge_label);

    f.render_widget(gauge, chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    let stages = match app.mode {
        ScanMode::Ingress => {
            if app.total_stages == 6 {
                vec![
                    (1, "Device Snapshot & Hash"),
                    (2, "USB Descriptors & BadUSB"),
                    (3, "Partition Table & Layout"),
                    (4, "Filesystem Structure"),
                    (5, "File Content & Evasion"),
                    (6, "Policy Rule Compliance"),
                ]
            } else {
                vec![
                    (1, "USB Descriptors & BadUSB"),
                    (2, "Partition Table & Layout"),
                    (3, "Filesystem Structure"),
                    (4, "File Content & Evasion"),
                    (5, "Policy Rule Compliance"),
                ]
            }
        }
        ScanMode::Egress => {
            if app.total_stages == 2 {
                vec![
                    (1, "Device Snapshot & Hash"),
                    (2, "Remnants, Wipe & Metadata"),
                ]
            } else {
                vec![(1, "Remnants, Wipe & Metadata")]
            }
        }
    };

    let mut stage_lines = Vec::new();
    stage_lines.push(Line::from(Span::styled(
        "Inspection Pipeline Stages:",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    stage_lines.push(Line::from(""));

    for (idx, name) in &stages {
        let is_completed = app.completed_stages.len() >= *idx;
        let is_running = !is_completed && app.current_stage_index == *idx;

        let (icon, style) = if is_completed {
            (
                "[✓]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
        } else if is_running {
            (
                "[▶]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            ("[ ]", Style::default().fg(Color::DarkGray))
        };

        stage_lines.push(Line::from(vec![
            Span::styled(format!(" {icon} {idx}. "), style),
            Span::styled(
                *name,
                if is_running {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else if is_completed {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ]));
    }

    stage_lines.push(Line::from(""));
    let findings_count = app.all_findings.len();
    stage_lines.push(Line::from(vec![
        Span::styled("Findings Discovered: ", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("{findings_count}"),
            if findings_count > 0 {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            },
        ),
    ]));

    let p_stages = Paragraph::new(stage_lines).block(
        Block::default()
            .title(" Pipeline Status ")
            .borders(Borders::ALL),
    );
    f.render_widget(p_stages, body_chunks[0]);

    let log_height = body_chunks[1].height.saturating_sub(2) as usize;
    let start_idx = app.scan_activity_log.len().saturating_sub(log_height);
    let log_slice = &app.scan_activity_log[start_idx..];

    let log_lines: Vec<Line> = log_slice
        .iter()
        .map(|msg| {
            if msg.contains("[!]") || msg.contains("Finding") {
                Line::from(Span::styled(msg, Style::default().fg(Color::Yellow)))
            } else if msg.contains("[Stage Completed]") || msg.contains("complete") {
                Line::from(Span::styled(msg, Style::default().fg(Color::Green)))
            } else if msg.contains("[Stage") {
                Line::from(Span::styled(
                    msg,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(Span::styled(msg, Style::default().fg(Color::Gray)))
            }
        })
        .collect();

    let p_log = Paragraph::new(log_lines).block(
        Block::default()
            .title(" Live Activity Log ")
            .borders(Borders::ALL),
    );
    f.render_widget(p_log, body_chunks[1]);
}

fn draw_results(f: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    if let Some(ref err) = app.scan_error {
        let banner = Paragraph::new(Line::from(vec![
            Span::styled(
                "STATUS: ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "ERROR - SCAN FAILED / DEVICE INACCESSIBLE",
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center);

        f.render_widget(banner, chunks[0]);

        let err_lines = vec![
            Line::from(Span::styled(
                "Device Access / Acquisition Failure",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Details: ", Style::default().fg(Color::Cyan)),
                Span::styled(err, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Common Causes & Troubleshooting:",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from("• No media: Multi-slot card readers require a card (SD/CF/microSD) to be physically inserted."),
            Line::from("• Privileges: Raw block devices require root access. Re-run with 'sudo ferrix'."),
            Line::from("• Disconnected: Device was unplugged or reset by the kernel during initialization."),
            Line::from(""),
            Line::from(Span::styled(
                "Press [Esc] to return to device selection.",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
        ];

        let p_err = Paragraph::new(err_lines)
            .block(
                Block::default()
                    .title(" Scan Failure Details ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(p_err, chunks[1]);
        return;
    }

    let verdict = app.verdict.unwrap_or(Verdict::Quarantine);
    let (v_text, v_color) = match verdict {
        Verdict::Pass => ("PASS - MEDIA APPROVED FOR SECURE USE", Color::Green),
        Verdict::Quarantine => ("QUARANTINE - MEDIA REQUIRES SECURITY REVIEW", Color::Yellow),
        Verdict::Fail => ("FAIL - MEDIA REJECTED / HOSTILE DETECTED", Color::Red),
    };

    let banner = Paragraph::new(Line::from(vec![
        Span::styled(
            "VERDICT: ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            v_text,
            Style::default().fg(v_color).add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Center);

    f.render_widget(banner, chunks[0]);

    let sub_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let findings: Vec<_> = app.filtered_findings().into_iter().cloned().collect();
    let items: Vec<ListItem> = findings
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            let is_selected = idx == app.selected_finding_idx;
            let marker = if is_selected { "▶ " } else { "  " };

            let (sev_str, sev_color) = match f.severity {
                Severity::Critical => ("CRIT", Color::Red),
                Severity::High => ("HIGH", Color::LightRed),
                Severity::Medium => ("MED ", Color::Yellow),
                Severity::Low => ("LOW ", Color::Blue),
                Severity::Info => ("INFO", Color::Cyan),
            };

            let line = format!(
                "{marker}[{sev_str}] {} - {}",
                f.id,
                sanitize_single_line(&f.reason)
            );
            let style = if is_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(sev_color)
            };

            ListItem::new(line).style(style)
        })
        .collect();

    let count_label = if app.show_info_findings {
        format!("All Findings ({})", findings.len())
    } else {
        format!("Actionable Findings ({}) [Info hidden]", findings.len())
    };

    let list = List::new(items).block(Block::default().title(count_label).borders(Borders::ALL));
    if findings.is_empty() {
        app.findings_list_state.select(None);
    } else {
        let sel = app.selected_finding_idx.min(findings.len() - 1);
        app.findings_list_state.select(Some(sel));
    }
    f.render_stateful_widget(list, sub_chunks[0], &mut app.findings_list_state);

    if !findings.is_empty() {
        let mut scrollbar_state = ScrollbarState::new(findings.len().saturating_sub(1))
            .position(app.selected_finding_idx);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"));
        f.render_stateful_widget(scrollbar, sub_chunks[0], &mut scrollbar_state);
    }

    let mut detail_text = if let Some(f) = findings.get(app.selected_finding_idx) {
        vec![
            Line::from(vec![
                Span::styled("Finding ID: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    &f.id,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Severity: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{:?}", f.severity),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("Confidence: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{:?}", f.confidence),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Location: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    sanitize_single_line(&f.location.to_string()),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled("Reason:", Style::default().fg(Color::Cyan))),
            Line::from(sanitize_single_line(&f.reason)),
            Line::from(""),
            Line::from(Span::styled("Evidence:", Style::default().fg(Color::Cyan))),
            Line::from(sanitize_single_line(&f.evidence)),
        ]
    } else {
        vec![Line::from("No finding selected.")]
    };

    if app.verdict == Some(Verdict::Pass) {
        detail_text.push(Line::from(""));
        detail_text.push(Line::from(vec![
            Span::styled(
                "[r] ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Release verified files from snapshot to staging folder"),
        ]));
    }

    let detail = Paragraph::new(detail_text)
        .block(
            Block::default()
                .title(" Finding Detail ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(detail, sub_chunks[1]);
}

fn draw_report(f: &mut Frame, area: Rect, app: &App) {
    let scan_id = app.scan_id.as_deref().unwrap_or("scan-manual");
    let export_msg = app
        .report_export_path
        .as_ref()
        .map(|p| format!("Report successfully exported to: {p}"))
        .unwrap_or_else(|| "Press [j] to export JSON, [h] to export HTML".to_string());

    let text = vec![
        Line::from(vec![
            Span::styled("Scan ID: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                scan_id,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Verdict: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{:?}", app.verdict.unwrap_or(Verdict::Quarantine)),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total Findings: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{}", app.all_findings.len()),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "[j] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Export JSON Report"),
        ]),
        Line::from(vec![
            Span::styled(
                "[h] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Export HTML Report (Standalone offline viewer)"),
        ]),
        Line::from(""),
        Line::from(Span::styled(export_msg, Style::default().fg(Color::Green))),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .title(" Report Export & Manifest ")
            .borders(Borders::ALL),
    );
    f.render_widget(p, area);
}

fn draw_triage_modal(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 40, f.area());
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(2),
        ])
        .split(area);

    let block = Block::default()
        .title(" Triage: Propose Scoped Suppression ")
        .borders(Borders::ALL);
    f.render_widget(block, area);

    let findings = app.filtered_findings();
    let finding_id = findings
        .get(app.selected_finding_idx)
        .map(|f| f.id.as_str())
        .unwrap_or("N/A");

    let p_info = Paragraph::new(format!(
        "Suppressing Finding: {finding_id} (Expires in 90 days)"
    ))
    .style(Style::default().fg(Color::Yellow));
    f.render_widget(p_info, chunks[0]);

    let author_cursor = if app.triage_focus_field == 0 {
        "█"
    } else {
        ""
    };
    let author_style = if app.triage_focus_field == 0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let p_author = Paragraph::new(format!(
        "Author: {}{author_cursor}",
        app.triage_author_input
    ))
    .style(author_style)
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(p_author, chunks[1]);

    let reason_cursor = if app.triage_focus_field == 1 {
        "█"
    } else {
        ""
    };
    let reason_style = if app.triage_focus_field == 1 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let p_reason = Paragraph::new(format!(
        "Reason: {}{reason_cursor}",
        app.triage_reason_input
    ))
    .style(reason_style)
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(p_reason, chunks[2]);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_attributes(attr: u8) -> String {
    let mut flags = Vec::new();
    if attr & 0x01 != 0 {
        flags.push("Read-Only");
    }
    if attr & 0x02 != 0 {
        flags.push("Hidden");
    }
    if attr & 0x04 != 0 {
        flags.push("System");
    }
    if attr & 0x10 != 0 {
        flags.push("Directory");
    }
    if attr & 0x20 != 0 {
        flags.push("Archive");
    }
    if flags.is_empty() {
        "Normal".to_string()
    } else {
        flags.join(", ")
    }
}

fn draw_browse_contents(f: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    if app.browse_loading {
        let block = Block::default()
            .title(format!(" 📁 Inspecting Drive: {} ", app.browse_target_name))
            .borders(Borders::ALL);
        let text = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "Parsing filesystem structures in sandboxed environment...",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Target Media: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    app.browse_target_path.display().to_string(),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(""),
            Line::from("Media is being inspected offline and read-only without kernel mounting."),
        ];
        let p = Paragraph::new(text).block(block);
        f.render_widget(p, area);
        return;
    }

    if let Some(ref err) = app.browse_error {
        let block = Block::default()
            .title(format!(" 📁 Drive Contents: {} ", app.browse_target_name))
            .borders(Borders::ALL);
        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Inspection Error: ",
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                ),
                Span::styled(err, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from("Could not read filesystem structures. The device may be unpartitioned, encrypted, or using an unsupported filesystem format."),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Press [s] to proceed with security scan anyway, or [Esc] to return to device selection.",
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ];
        let p = Paragraph::new(text).block(block);
        f.render_widget(p, area);
        return;
    }

    let entries = app.current_dir_entries();

    let path_display = if app.browse_current_dir.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", app.browse_current_dir)
    };

    let title = format!(
        " 📁 {} [{}] ({} items) ",
        app.browse_target_name,
        path_display,
        entries.len()
    );

    let items: Vec<ListItem> = if entries.is_empty() {
        vec![
            ListItem::new(Line::from("")),
            ListItem::new(Line::from(vec![Span::styled(
                "  (Empty directory / no files found)",
                Style::default().fg(Color::DarkGray),
            )])),
        ]
    } else {
        entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                let is_selected = idx == app.browse_selected_idx;
                let marker = if is_selected { "▶ " } else { "  " };

                let (icon, name_styled, size_str, style) = if entry.name == ".." {
                    (
                        "📁 ",
                        Span::styled(".. (Parent Directory)", Style::default().fg(Color::Yellow)),
                        String::new(),
                        if is_selected {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Yellow)
                        },
                    )
                } else if entry.is_dir {
                    (
                        "📁 ",
                        Span::styled(
                            format!("{}/", entry.name),
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        "[DIR]".to_string(),
                        if is_selected {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Yellow)
                        },
                    )
                } else {
                    (
                        "   ",
                        Span::styled(&entry.name, Style::default().fg(Color::White)),
                        format_size(entry.size),
                        if is_selected {
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::White)
                        },
                    )
                };

                let line = Line::from(vec![
                    Span::raw(marker),
                    Span::raw(icon),
                    name_styled,
                    Span::styled(
                        if size_str.is_empty() {
                            String::new()
                        } else {
                            format!("  ({})", size_str)
                        },
                        Style::default().fg(Color::DarkGray),
                    ),
                ]);

                ListItem::new(line).style(style)
            })
            .collect()
    };

    let list_block = Block::default().title(title).borders(Borders::ALL);
    let list = List::new(items).block(list_block);

    if entries.is_empty() {
        app.browse_list_state.select(None);
    } else {
        let sel = app.browse_selected_idx.min(entries.len() - 1);
        app.browse_list_state.select(Some(sel));
    }
    f.render_stateful_widget(list, chunks[0], &mut app.browse_list_state);

    if !entries.is_empty() {
        let mut scrollbar_state =
            ScrollbarState::new(entries.len().saturating_sub(1)).position(app.browse_selected_idx);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"));
        f.render_stateful_widget(scrollbar, chunks[0], &mut scrollbar_state);
    }

    let details_block = Block::default()
        .title(" Metadata Inspection (Sandboxed) ")
        .borders(Borders::ALL);

    if let Some(entry) = entries.get(app.browse_selected_idx) {
        let ext = if entry.is_dir {
            "Directory".to_string()
        } else {
            std::path::Path::new(&entry.name)
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_else(|| "none".to_string())
        };

        let offset_str = match entry.data_offset {
            Some(off) => format!("0x{:08X} (sector {})", off, off / 512),
            None => "N/A".to_string(),
        };

        let fs_str = match entry.fs_type {
            Some(ref fs) => format!("{fs} (Partition #{})", entry.partition_index),
            None => format!("Partition #{}", entry.partition_index),
        };

        let cluster_str = match entry.starting_cluster {
            Some(cl) => format!("#{cl} (0x{cl:08X})"),
            None => "N/A".to_string(),
        };

        let (allocated_str, slack_str) = if !entry.is_dir {
            if let Some(cs) = entry.cluster_size {
                if cs > 0 {
                    let clusters = if entry.size == 0 {
                        0
                    } else {
                        (entry.size.saturating_add(cs as u64 - 1)) / cs as u64
                    };
                    let allocated = clusters.saturating_mul(cs as u64);
                    let slack = allocated.saturating_sub(entry.size);
                    (
                        format!(
                            "{} bytes ({} cluster{})",
                            allocated,
                            clusters,
                            if clusters == 1 { "" } else { "s" }
                        ),
                        format!("{} bytes (unallocated in cluster)", slack),
                    )
                } else {
                    ("N/A".to_string(), "N/A".to_string())
                }
            } else {
                ("N/A".to_string(), "N/A".to_string())
            }
        } else {
            ("N/A (Directory)".to_string(), "N/A (Directory)".to_string())
        };

        let detected_type_str = entry.detected_type.as_deref().unwrap_or(if entry.is_dir {
            "Directory"
        } else {
            "Unknown"
        });

        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    "Name: ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    &entry.name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Path: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("/{}", entry.full_path),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Type: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    if entry.is_dir {
                        "Directory"
                    } else {
                        "Regular File"
                    },
                    Style::default().fg(if entry.is_dir {
                        Color::Yellow
                    } else {
                        Color::Green
                    }),
                ),
            ]),
            Line::from(vec![
                Span::styled("Filesystem: ", Style::default().fg(Color::Cyan)),
                Span::styled(fs_str, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Extension: ", Style::default().fg(Color::Cyan)),
                Span::styled(ext.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Content Type: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    detected_type_str,
                    Style::default().fg(if detected_type_str.contains("Executable") {
                        Color::LightRed
                    } else {
                        Color::White
                    }),
                ),
            ]),
        ];

        let ext_lower = ext.to_lowercase();
        if !entry.is_dir
            && detected_type_str.contains("Executable")
            && ext_lower != ".exe"
            && ext_lower != ".bin"
        {
            lines.push(Line::from(vec![
                Span::styled(
                    "Risk Warning: ",
                    Style::default()
                        .fg(Color::LightRed)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Executable file disguised with non-executable extension!",
                    Style::default().fg(Color::LightRed),
                ),
            ]));
        }

        lines.extend(vec![
            Line::from(vec![
                Span::styled("File Size: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{} bytes ({})", entry.size, format_size(entry.size)),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Allocated Size: ", Style::default().fg(Color::Cyan)),
                Span::styled(allocated_str, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Slack Space: ", Style::default().fg(Color::Cyan)),
                Span::styled(slack_str, Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("Starting Cluster: ", Style::default().fg(Color::Cyan)),
                Span::styled(cluster_str, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Data Offset: ", Style::default().fg(Color::Cyan)),
                Span::styled(offset_str, Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("Attributes: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!(
                        "{} (0x{:02X})",
                        format_attributes(entry.attributes),
                        entry.attributes
                    ),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Created (Birth): ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    entry.created.as_deref().unwrap_or("Not recorded"),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Modified (Write): ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    entry.modified.as_deref().unwrap_or("Not recorded"),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Accessed: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    entry.accessed.as_deref().unwrap_or("Not recorded"),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "────────────────────────────────────────",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(vec![
                Span::styled(
                    "Security Sandbox Active",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(
                "Direct file opening, rendering, and execution are strictly disabled to protect the host station from malicious payloads and hostile file parsers.",
            ),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "[s]",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " to proceed with full multi-stage security vetting.",
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
        ]);

        let p_details = Paragraph::new(lines)
            .block(details_block)
            .scroll((app.browse_detail_scroll, 0))
            .wrap(Wrap { trim: true });
        f.render_widget(p_details, chunks[1]);
    } else {
        let p_empty = Paragraph::new("Select an item to inspect metadata.")
            .block(details_block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p_empty, chunks[1]);
    }
}
