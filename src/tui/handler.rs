use crate::tui::app::{App, ScanMode, Screen};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

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
                    KeyCode::Char('r') => app.refresh_devices(),
                    KeyCode::Char('m') => {
                        app.is_entering_manual_device = true;
                        app.manual_device_input.clear();
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
                    KeyCode::Char('u') => {
                        if let Some(dev) = app.selected_device() {
                            if dev.is_system_drive {
                                app.status_message = Some(
                                    "Cannot unmount: host system drive is protected.".to_string(),
                                );
                            } else {
                                let path = dev.path.clone();
                                match crate::device::auth::unmount_device_partitions(&path) {
                                    Ok(unmounted) => {
                                        if unmounted.is_empty() {
                                            app.status_message =
                                                Some("Device is not mounted.".to_string());
                                        } else {
                                            app.status_message = Some(format!(
                                                "Successfully unmounted: {}",
                                                unmounted.join(", ")
                                            ));
                                            app.refresh_devices();
                                        }
                                    }
                                    Err(e) => {
                                        app.status_message =
                                            Some(format!("Failed to unmount device: {e}"));
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Enter if !app.devices.is_empty() => {
                        app.screen = Screen::ModeSelect;
                    }
                    _ => {}
                }
            }
        }
        Screen::ModeSelect => match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc => app.screen = Screen::DeviceSelect,
            KeyCode::Char('1') => app.mode = ScanMode::Ingress,
            KeyCode::Char('2') => app.mode = ScanMode::Egress,
            KeyCode::Enter => app.start_scan(),
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
            KeyCode::Char('i') => app.show_info_findings = !app.show_info_findings,
            KeyCode::Char('p') => app.screen = Screen::Report,
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
