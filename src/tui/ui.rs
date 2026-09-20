use crate::core::{Severity, Verdict};
use crate::tui::app::{App, ScanMode, Screen};
use crate::tui::sanitize::sanitize_single_line;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap};
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
                "[Enter] Select Device  [m] Manual Path  [u] Unmount Drive  [r] Refresh  [q] Quit"
            }
        }
        Screen::ModeSelect => "[1] Ingress  [2] Egress  [Enter] Start Scan  [Esc] Back  [q] Quit",
        Screen::Scanning => "Scanning in progress... Please wait. [q] Cancel",
        Screen::Results => {
            "[↑/↓/j/k] Navigate  [i] Toggle Info  [t] Triage False Positive  [p] Export Report  [Esc] Device Select  [q] Quit"
        }
        Screen::Report => "[j] Export JSON  [h] Export HTML  [Esc] Back to Results  [q] Quit",
        Screen::Triage => "[Tab] Switch Field  [Enter] Confirm Suppression  [Esc] Cancel",
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            "Keys: ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(hints, Style::default().fg(Color::White)),
    ]))
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

fn draw_device_select(f: &mut Frame, area: Rect, app: &App) {
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
            ]),
        ];
        let p = Paragraph::new(text).block(block);
        f.render_widget(p, area);
        return;
    }

    let items: Vec<ListItem> = app
        .devices
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
            } else if !dev.mount_points.is_empty() {
                format!(" [MOUNTED at {} - UNSAFE]", dev.mount_points.join(", "))
            } else {
                " [Unmounted]".to_string()
            };

            let text = format!(
                "{marker}{} ({}) - {} {} [serial: {}]{}",
                dev.name,
                size_str,
                dev.vendor,
                dev.model,
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
        .collect();

    let title = format!(" Detected Storage Media & Images ({}) ", app.devices.len());
    let list = List::new(items).block(Block::default().title(title).borders(Borders::ALL));

    f.render_widget(list, area);
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

    let max_label_len = chunks[0].width.saturating_sub(10) as usize;
    let stage_name = if app.current_stage_name.len() > max_label_len && max_label_len > 12 {
        format!("{}...", &app.current_stage_name[..max_label_len - 3])
    } else {
        app.current_stage_name.clone()
    };

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
        .label(format!("{}% - {}", app.scan_progress_pct, stage_name));

    f.render_widget(gauge, chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    let stages = match app.mode {
        ScanMode::Ingress => vec![
            (1, "USB Descriptors & BadUSB"),
            (2, "Partition Table & Layout"),
            (3, "Filesystem Structure"),
            (4, "File Content & Evasion"),
            (5, "Policy Rule Compliance"),
        ],
        ScanMode::Egress => vec![(1, "Remnants, Wipe & Metadata")],
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

fn draw_results(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

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

    let findings = app.filtered_findings();
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
                Severity::Info => ("INFO", Color::DarkGray),
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
    f.render_widget(list, sub_chunks[0]);

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

    let author_style = if app.triage_focus_field == 0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let p_author = Paragraph::new(format!("Author: {}", app.triage_author_input))
        .style(author_style)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(p_author, chunks[1]);

    let reason_style = if app.triage_focus_field == 1 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let p_reason = Paragraph::new(format!("Reason: {}", app.triage_reason_input))
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
