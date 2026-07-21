use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, Panel};
use crate::data::run_matrix::{Os, ParityState, Role};
use crate::data::vm_prober::{LabReadinessState, VmStatus};

fn evidence_for_vm(app: &App, vm: &VmStatus) -> (&'static str, Color) {
    let Some(os) = Os::from_label(&vm.platform) else {
        return ("—", Color::DarkGray);
    };
    let role_label = app.actual_role_for_vm(&vm.alias);
    let Some(role) = Role::from_label(&role_label) else {
        return ("—", Color::DarkGray);
    };
    let state = app
        .parity_matrix
        .get(&(role, os))
        .copied()
        .unwrap_or(ParityState::Unproven);
    match state {
        ParityState::Proven => ("PROVEN", Color::Green),
        ParityState::Failed => ("FAILED", Color::Red),
        ParityState::Flaky => ("FLAKY", Color::Yellow),
        ParityState::Unproven => ("UNPROVEN", Color::Gray),
        ParityState::NotInSchema => ("N/A", Color::Magenta),
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let count = app.vm_statuses.len();
    let focused = app.focused_panel == Panel::VmStatus;
    let role_hint = if app.roles_locked_by_active_lab() {
        "roles locked to active lab"
    } else {
        "←→ plan next-run role"
    };
    let unregistered = app
        .vm_statuses
        .iter()
        .filter(|vm| !vm.inventory_registered)
        .count();
    let inventory_note = if unregistered > 0 {
        format!("  *{unregistered} host-only")
    } else {
        String::new()
    };
    let online = app.vm_statuses.iter().filter(|vm| vm.ssh_ok).count();
    let ready = app
        .vm_statuses
        .iter()
        .filter(|vm| vm.lab_readiness.state == LabReadinessState::Ready)
        .count();
    let current = app
        .vm_statuses
        .iter()
        .filter(|vm| app.run_use_for_vm(&vm.alias) == "CURRENT")
        .count();
    let title = format!(
        "VM STATUS [1] {count} total · {online} online · {ready} ready · {current} current{inventory_note}  ↑↓ select  {role_hint}"
    );

    let border_fg = if focused { Color::Yellow } else { Color::Cyan };
    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(border_fg)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_fg));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.vm_statuses.is_empty() {
        f.render_widget(
            Paragraph::new("Probing...").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    // Only render as many VM lines as fit below the header.
    let max_lines = (inner.height as usize).saturating_sub(1);
    let visible: Vec<Line> = app
        .vm_statuses
        .iter()
        .enumerate()
        .take(max_lines)
        .map(|(idx, vm)| {
            let selected = focused && idx == app.selected_vm;
            let (power, power_color) = match vm.power_state.as_str() {
                "started" => ("ON", Color::Green),
                "stopped" => ("OFF", Color::DarkGray),
                "missing" => ("MISSING", Color::Red),
                _ => ("UNKNOWN", Color::Yellow),
            };
            let (online, online_color) = if vm.ssh_ok {
                ("YES", Color::Green)
            } else {
                ("NO", Color::Red)
            };
            let (readiness, readiness_color) = match vm.lab_readiness.state {
                LabReadinessState::Checking => ("CHECKING", Color::Yellow),
                LabReadinessState::Ready => ("READY", Color::Green),
                LabReadinessState::Blocked => ("BLOCKED", Color::Red),
                LabReadinessState::Unknown => ("UNKNOWN", Color::DarkGray),
            };

            let alias_style = if vm.ssh_ok {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let alias_style = if selected {
                // The selection background is DarkGray. An OFFLINE VM's alias fg
                // is ALSO DarkGray, so a selected offline row would render its
                // name DarkGray-on-DarkGray -- invisible. Since the cursor
                // defaults to row 0 (frequently a stopped host-only VM), the
                // selected VM's name routinely vanished. Lift the offline fg to
                // Gray (still dimmer than an online White row, but readable on
                // the highlight) so a selected row's name is never fg == bg.
                let fg = if vm.ssh_ok { Color::White } else { Color::Gray };
                Style::default()
                    .fg(fg)
                    .add_modifier(Modifier::BOLD)
                    .bg(Color::DarkGray)
            } else {
                alias_style
            };

            let marker = if selected { "▸" } else { " " };
            let role = app.actual_role_for_vm(&vm.alias);
            let run_use = app.run_use_for_vm(&vm.alias);
            let run_color = match run_use {
                "CURRENT" => Color::Green,
                "PREVIOUS" => Color::Blue,
                _ => Color::DarkGray,
            };
            let (evidence, evidence_color) = evidence_for_vm(app, vm);
            let alias = if vm.inventory_registered {
                vm.alias.clone()
            } else {
                format!("*{}", vm.alias)
            };

            Line::from(vec![
                Span::raw(format!("{marker} ")),
                Span::styled(format!("{alias:<22}"), alias_style),
                Span::styled(
                    format!("{:<10}", vm.platform),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(format!("{power:<10}"), Style::default().fg(power_color)),
                Span::styled(format!("{online:<12}"), Style::default().fg(online_color)),
                Span::styled(
                    format!("{readiness:<13}"),
                    Style::default().fg(readiness_color),
                ),
                Span::styled(format!("{run_use:<11}"), Style::default().fg(run_color)),
                Span::styled(format!("{role:<14}"), Style::default().fg(Color::Yellow)),
                Span::styled(format!("{:<17}", vm.ip), Style::default().fg(Color::Gray)),
                Span::styled(evidence, Style::default().fg(evidence_color)),
            ])
        })
        .collect();

    // Show overflow count if some VMs hidden
    let extra = app.vm_statuses.len().saturating_sub(max_lines);
    let mut lines = vec![Line::from(vec![
        Span::styled("  ", Style::default().fg(Color::Blue)),
        Span::styled(format!("{:<22}", "VM"), Style::default().fg(Color::Blue)),
        Span::styled(format!("{:<10}", "OS"), Style::default().fg(Color::Blue)),
        Span::styled(format!("{:<10}", "POWER"), Style::default().fg(Color::Blue)),
        Span::styled(
            format!("{:<12}", "ONLINE/SSH"),
            Style::default().fg(Color::Blue),
        ),
        Span::styled(
            format!("{:<13}", "LAB READY"),
            Style::default().fg(Color::Blue),
        ),
        Span::styled(
            format!("{:<11}", "RUN USE"),
            Style::default().fg(Color::Blue),
        ),
        Span::styled(format!("{:<14}", "ROLE"), Style::default().fg(Color::Blue)),
        Span::styled(format!("{:<17}", "IP"), Style::default().fg(Color::Blue)),
        Span::styled("EVIDENCE", Style::default().fg(Color::Blue)),
    ])];
    lines.extend(visible);
    if extra > 0 {
        lines.push(Line::from(Span::styled(
            format!("  … and {extra} more"),
            Style::default().fg(Color::DarkGray),
        )));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::vm_prober::{LabReadiness, LabReadinessState, VmStatus};
    use ratatui::{Terminal, backend::TestBackend};
    use std::path::PathBuf;

    /// Renders the panel with a real TestBackend and finds the x-column
    /// where each needle first appears on the given row.
    fn col_of(buf: &ratatui::buffer::Buffer, y: u16, needle: &str) -> Option<u16> {
        for x in 0..buf.area.width {
            let mut tail = String::new();
            for sx in x..buf.area.width {
                tail.push_str(buf[(sx, y)].symbol());
                if tail.len() >= needle.len() {
                    break;
                }
            }
            if tail.starts_with(needle) {
                return Some(x);
            }
        }
        None
    }

    #[test]
    fn header_labels_line_up_with_the_data_columns_below() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.vm_statuses = vec![VmStatus {
            alias: "debian-headless-1".into(),
            ip: "192.168.0.200".into(),
            platform: "linux".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: ready(),
        }];

        let backend = TestBackend::new(150, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, f.area(), &app)).unwrap();
        let buf = terminal.backend().buffer().clone();

        let header_row = 1;
        let data_row = 2;
        assert_eq!(
            col_of(&buf, header_row, "VM"),
            col_of(&buf, data_row, "debian-headless-1"),
            "VM header must start at same column as alias"
        );
        assert_eq!(
            col_of(&buf, header_row, "OS"),
            col_of(&buf, data_row, "linux"),
            "OS header must start at the same column as the platform value"
        );
        assert_eq!(
            col_of(&buf, header_row, "POWER"),
            col_of(&buf, data_row, "ON"),
            "POWER header must align"
        );
        assert_eq!(
            col_of(&buf, header_row, "ONLINE/SSH"),
            col_of(&buf, data_row, "YES"),
            "ONLINE header must align"
        );
        assert_eq!(
            col_of(&buf, header_row, "LAB READY"),
            col_of(&buf, data_row, "READY"),
            "LAB READY header must align"
        );
        assert_eq!(
            col_of(&buf, header_row, "IP"),
            col_of(&buf, data_row, "192.168.0.200"),
            "IP header must align"
        );
    }

    fn ready() -> LabReadiness {
        LabReadiness {
            state: LabReadinessState::Ready,
            detail: "all checks passed".to_owned(),
        }
    }

    fn windows_vm() -> VmStatus {
        VmStatus {
            alias: "windows-utm-1".into(),
            ip: "192.168.0.210".into(),
            platform: "windows".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: ready(),
        }
    }

    fn linux_vm() -> VmStatus {
        VmStatus {
            // Deliberately NOT "debian-headless-1"/"-2"/"-3" -- those match
            // MonitorConfig::default()'s exit_vm/client_vm/entry_vm, which
            // would accidentally give this fixture a real role in any test
            // that doesn't otherwise configure roles.
            alias: "debian-headless-9".into(),
            ip: "192.168.0.209".into(),
            platform: "linux".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: ready(),
        }
    }

    #[test]
    fn evidence_word_reflects_actual_run_role_and_parity_state() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.latest_run_roles
            .insert("windows-utm-1".to_owned(), "exit".to_owned());
        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Proven);

        assert_eq!(
            evidence_for_vm(&app, &windows_vm()),
            ("PROVEN", Color::Green)
        );

        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Failed);
        assert_eq!(evidence_for_vm(&app, &windows_vm()), ("FAILED", Color::Red));

        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Flaky);
        assert_eq!(
            evidence_for_vm(&app, &windows_vm()),
            ("FLAKY", Color::Yellow)
        );
    }

    #[test]
    fn evidence_is_blank_when_vm_was_not_used_in_a_run() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        assert_eq!(evidence_for_vm(&app, &linux_vm()), ("—", Color::DarkGray));
    }

    #[test]
    fn render_shows_named_evidence_column_and_only_actual_run_roles() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Proven);
        app.latest_run_roles
            .insert("windows-utm-1".to_owned(), "exit".to_owned());
        app.vm_statuses = vec![windows_vm(), linux_vm()];

        let backend = TestBackend::new(150, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, f.area(), &app)).unwrap();
        let buf = terminal.backend().buffer().clone();

        let header_row = 1;
        let windows_row = 2;
        let linux_row = 3;
        assert_eq!(
            col_of(&buf, header_row, "EVIDENCE"),
            col_of(&buf, windows_row, "PROVEN"),
            "named evidence header must align"
        );
        assert!(
            col_of(&buf, linux_row, "PROVEN").is_none(),
            "unused VM must have no evidence claim"
        );
        assert_eq!(app.actual_role_for_vm("debian-headless-9"), "—");
        assert_eq!(app.run_use_for_vm("windows-utm-1"), "PREVIOUS");
    }

    #[test]
    fn a_selected_offline_vm_alias_is_not_rendered_invisibly() {
        // Regression: a selected row uses bg=DarkGray; an OFFLINE VM's alias fg
        // was also DarkGray, so the selected offline row rendered its name
        // DarkGray-on-DarkGray (invisible). The cursor defaults to row 0 --
        // frequently a stopped host-only VM -- so the selected name vanished.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::VmStatus;
        app.selected_vm = 0;
        app.vm_statuses = vec![VmStatus {
            alias: "stopped-guest".into(),
            ip: "-".into(),
            platform: "unknown".into(),
            ssh_ok: false,
            power_state: "stopped".into(),
            inventory_registered: true,
            lab_readiness: LabReadiness {
                state: LabReadinessState::Unknown,
                detail: String::new(),
            },
        }];

        let backend = TestBackend::new(150, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, f.area(), &app)).unwrap();
        let buf = terminal.backend().buffer().clone();

        let data_row = 2;
        let x = col_of(&buf, data_row, "stopped-guest").expect("selected alias is rendered");
        assert_ne!(
            buf[(x, data_row)].fg,
            buf[(x, data_row)].bg,
            "a selected offline VM's alias must not render fg == bg (invisible)"
        );
        assert_ne!(
            buf[(x, data_row)].fg,
            Color::DarkGray,
            "selected offline alias fg must be lifted off the DarkGray selection bg"
        );
    }
}
