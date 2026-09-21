use crate::tui::app::{App, ScanMode, Screen};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::atomic::Ordering;

pub fn handle_key_event(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    match app.screen {
        Screen::DeviceSelect => {
            if app.is_entering_manual_device {
                match key.code {
                    KeyCode::Enter => {
                        if !app.manual_device_input.trim().is_empty() {
                            app.is_entering_manual_device = false;
                            app.screen = Screen::ModeSelect;
                        }
                    }
                    KeyCode::Esc => {
                        app.is_entering_manual_device = false;
                    }
                    KeyCode::Backspace => {
                        app.manual_device_input.pop();
                    }
                    KeyCode::Char(c) => {
                        app.manual_device_input.push(c);
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => app.should_quit = true,
                    KeyCode::Char('m') => {
                        app.is_entering_manual_device = true;
                        app.manual_device_input.clear();
                    }
                    KeyCode::Char('r') => {
                        app.refresh_devices();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.selected_device_idx > 0 {
                            app.selected_device_idx -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !app.devices.is_empty()
                            && app.selected_device_idx < app.devices.len() - 1
                        {
                            app.selected_device_idx += 1;
                        }
                    }
                    KeyCode::PageUp => {
                        app.selected_device_idx = app.selected_device_idx.saturating_sub(5);
                    }
                    KeyCode::PageDown => {
                        if !app.devices.is_empty() {
                            app.selected_device_idx =
                                (app.selected_device_idx + 5).min(app.devices.len() - 1);
                        }
                    }
                    KeyCode::Home => {
                        app.selected_device_idx = 0;
                    }
                    KeyCode::End => {
                        if !app.devices.is_empty() {
                            app.selected_device_idx = app.devices.len() - 1;
                        }
                    }
                    KeyCode::Char('u') => {
                        if let Some(dev) = app.selected_device() {
                            if dev.is_system_drive {
                                app.set_status("Cannot unmount: host system drive is protected.");
                            } else {
                                let path = dev.path.clone();
                                match crate::device::auth::unmount_device_partitions(&path) {
                                    Ok(unmounted) => {
                                        if unmounted.is_empty() {
                                            app.set_status("Device is not mounted.");
                                        } else {
                                            app.set_status(format!(
                                                "Successfully unmounted: {}",
                                                unmounted.join(", ")
                                            ));
                                            app.refresh_devices();
                                        }
                                    }
                                    Err(e) => {
                                        app.set_status(format!("Failed to unmount device: {e}"));
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Char('v') | KeyCode::Char('b') => {
                        app.open_drive_browser();
                    }
                    KeyCode::Enter if !app.devices.is_empty() => {
                        if let Some(dev) = app.selected_device() {
                            if dev.size_bytes == 0 && !dev.path.starts_with("/sys/bus/usb/devices/")
                            {
                                app.set_status(format!(
                                    "Cannot scan '{}': No media inserted (0 bytes). Insert media or select another device.",
                                    dev.name
                                ));
                                return;
                            }
                        }
                        app.screen = Screen::ModeSelect;
                    }
                    _ => {}
                }
            }
        }
        Screen::ModeSelect => match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc => app.screen = Screen::DeviceSelect,
            KeyCode::Char('v') | KeyCode::Char('b') => app.open_drive_browser(),
            KeyCode::Char('1') => app.mode = ScanMode::Ingress,
            KeyCode::Char('2') => app.mode = ScanMode::Egress,
            KeyCode::Enter => app.start_scan(),
            _ => {}
        },
        Screen::BrowseContents => match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc => {
                app.browse_cancel.store(true, Ordering::SeqCst);
                app.browse_loading = false;
                app.rx_browse = None;
                app.screen = Screen::DeviceSelect;
            }
            KeyCode::Char('s') => {
                app.screen = Screen::ModeSelect;
            }
            KeyCode::Char('r') => {
                app.browse_files.clear();
                app.open_drive_browser();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if app.browse_selected_idx > 0 {
                    app.browse_selected_idx -= 1;
                    app.browse_detail_scroll = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let total = app.current_dir_entries().len();
                if total > 0 && app.browse_selected_idx < total - 1 {
                    app.browse_selected_idx += 1;
                    app.browse_detail_scroll = 0;
                }
            }
            KeyCode::PageUp => {
                app.browse_selected_idx = app.browse_selected_idx.saturating_sub(10);
                app.browse_detail_scroll = 0;
            }
            KeyCode::PageDown => {
                let total = app.current_dir_entries().len();
                if total > 0 {
                    app.browse_selected_idx = (app.browse_selected_idx + 10).min(total - 1);
                    app.browse_detail_scroll = 0;
                }
            }
            KeyCode::Home => {
                app.browse_selected_idx = 0;
                app.browse_detail_scroll = 0;
            }
            KeyCode::End => {
                let total = app.current_dir_entries().len();
                if total > 0 {
                    app.browse_selected_idx = total - 1;
                    app.browse_detail_scroll = 0;
                }
            }
            KeyCode::Char('J') | KeyCode::Char(']') => {
                app.browse_detail_scroll = app.browse_detail_scroll.saturating_add(1);
            }
            KeyCode::Char('K') | KeyCode::Char('[') => {
                app.browse_detail_scroll = app.browse_detail_scroll.saturating_sub(1);
            }
            KeyCode::Backspace | KeyCode::Char('h') | KeyCode::Left => {
                if !app.browse_current_dir.is_empty() {
                    let parent = match app.browse_current_dir.rfind('/') {
                        Some(idx) => app.browse_current_dir[..idx].to_string(),
                        None => String::new(),
                    };
                    app.browse_current_dir = parent;
                    app.browse_selected_idx = 0;
                    app.browse_detail_scroll = 0;
                }
            }
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                let entries = app.current_dir_entries();
                if let Some(entry) = entries.get(app.browse_selected_idx) {
                    if entry.is_dir {
                        app.browse_current_dir = entry.full_path.clone();
                        app.browse_selected_idx = 0;
                        app.browse_detail_scroll = 0;
                    } else {
                        app.set_status(
                            "File preview disabled for security. Metadata inspection only.",
                        );
                    }
                }
            }
            _ => {}
        },
        Screen::Scanning => {
            if let KeyCode::Char('q') = key.code {
                app.is_scanning = false;
                app.screen = Screen::DeviceSelect;
            }
        }
        Screen::Results => match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc => app.screen = Screen::DeviceSelect,
            KeyCode::Char('i') => {
                app.show_info_findings = !app.show_info_findings;
                let max = app.filtered_findings().len();
                if max == 0 {
                    app.selected_finding_idx = 0;
                } else if app.selected_finding_idx >= max {
                    app.selected_finding_idx = max - 1;
                }
            }
            KeyCode::Char('p') => app.screen = Screen::Report,
            KeyCode::Char('r') => {
                if app.verdict == Some(crate::core::Verdict::Pass) {
                    let _ = app.release_verified_files();
                }
            }
            KeyCode::Char('t') => {
                if !app.filtered_findings().is_empty() {
                    app.screen = Screen::Triage;
                    app.triage_reason_input.clear();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if app.selected_finding_idx > 0 {
                    app.selected_finding_idx -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = app.filtered_findings().len();
                if max > 0 && app.selected_finding_idx < max - 1 {
                    app.selected_finding_idx += 1;
                }
            }
            KeyCode::PageUp => {
                app.selected_finding_idx = app.selected_finding_idx.saturating_sub(10);
            }
            KeyCode::PageDown => {
                let max = app.filtered_findings().len();
                if max > 0 {
                    app.selected_finding_idx = (app.selected_finding_idx + 10).min(max - 1);
                }
            }
            KeyCode::Home => {
                app.selected_finding_idx = 0;
            }
            KeyCode::End => {
                let max = app.filtered_findings().len();
                if max > 0 {
                    app.selected_finding_idx = max - 1;
                }
            }
            _ => {}
        },
        Screen::Report => match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc => app.screen = Screen::Results,
            KeyCode::Char('j') => {
                let _ = app.export_report(false);
            }
            KeyCode::Char('h') => {
                let _ = app.export_report(true);
            }
            _ => {}
        },
        Screen::Triage => match key.code {
            KeyCode::Esc => app.screen = Screen::Results,
            KeyCode::Tab => {
                app.triage_focus_field = (app.triage_focus_field + 1) % 2;
            }
            KeyCode::Backspace => {
                if app.triage_focus_field == 0 {
                    app.triage_author_input.pop();
                } else {
                    app.triage_reason_input.pop();
                }
            }
            KeyCode::Char(c) => {
                if app.triage_focus_field == 0 {
                    app.triage_author_input.push(c);
                } else {
                    app.triage_reason_input.push(c);
                }
            }
            KeyCode::Enter if app.apply_triage_suppression().is_ok() => {
                app.screen = Screen::Results;
            }
            _ => {}
        },
    }
}
