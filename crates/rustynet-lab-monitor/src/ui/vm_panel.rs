use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, Panel};
use crate::data::run_matrix::{Os, ParityState, Role};
use crate::data::vm_prober::VmStatus;

/// The active stage's name, IF it's inferable as touching this VM's
/// platform specifically -- e.g. "bootstrap_windows_host" for a windows VM,
/// "validate_macos_anchor_bundle_pull" for a macos VM. Stage names encode
/// their target OS by substring (`_{os}_`, a leading `{os}_`, or a trailing
/// `_{os}`; verified against the real per-stage log directory naming
/// convention -- there is no per-node log file, only per-stage ones, so
/// this substring match on the OS-scoped stage name is the closest
/// attribution available without parsing individual log bodies). Stages
/// with no OS keyword at all (PRE, and the 9 generic BOOTSTRAP stages) are
/// cross-platform and touch every node at once, so deliberately not
/// attributed to any single VM here -- showing the same generic stage name
/// against every row wouldn't differentiate anything. `None` whenever no
/// lab is genuinely running right now (see `App::lab_is_actively_running`).
fn live_activity_for_vm<'a>(app: &'a App, vm: &VmStatus) -> Option<&'a str> {
    if !app.lab_is_actively_running() {
        return None;
    }
    let stage = app.active_stage.as_deref()?;
    let platform = vm.platform.as_str();
    let touches_platform = stage == platform
        || stage.starts_with(&format!("{platform}_"))
        || stage.ends_with(&format!("_{platform}"))
        || stage.contains(&format!("_{platform}_"));
    touches_platform.then_some(stage)
}

/// A single-character colored dot reflecting this VM's CURRENT role's
/// Proven/Flaky/Failed/Unproven parity state for its platform, reusing
/// Parity Matrix's own color scheme (see parity_panel.rs's `progress_bar`):
/// Proven=Green, Failed=Red, Flaky=Yellow, Unproven=Gray. `None` when the VM
/// has no role assigned right now (role_for_vm returns "-") -- there's no
/// meaningful parity cell to reflect for "no role".
fn parity_glyph_for_vm(app: &App, vm: &VmStatus) -> Option<Span<'static>> {
    let os = Os::from_label(&vm.platform)?;
    let role_label = app.role_for_vm(&vm.alias);
    let role = Role::from_label(&role_label)?;
    let state = app
        .parity_matrix
        .get(&(role, os))
        .copied()
        .unwrap_or(ParityState::Unproven);
    let color = match state {
        ParityState::Proven => Color::Green,
        ParityState::Failed => Color::Red,
        ParityState::Flaky => Color::Yellow,
        ParityState::Unproven => Color::Gray,
    };
    Some(Span::styled("●", Style::default().fg(color)))
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let count = app.vm_statuses.len();
    let focused = app.focused_panel == Panel::VmStatus;
    let role_hint = if app.roles_locked_by_active_lab() {
        "roles locked to active lab"
    } else {
        "←→ role"
    };
    let title = format!("VM STATUS [1] ({count})  ↑↓ select  {role_hint}");

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
            let ssh_mark = if vm.ssh_ok {
                Span::styled("✓", Style::default().fg(Color::Green))
            } else {
                Span::styled("✗", Style::default().fg(Color::Red))
            };

            let alias_style = if vm.ssh_ok {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let alias_style = if selected {
                alias_style.add_modifier(Modifier::BOLD).bg(Color::DarkGray)
            } else {
                alias_style
            };

            let marker = if selected { "▸" } else { " " };
            let role = app.role_for_vm(&vm.alias);
            let glyph = parity_glyph_for_vm(app, vm).unwrap_or_else(|| Span::raw(" "));
            let activity = live_activity_for_vm(app, vm).unwrap_or("");

            Line::from(vec![
                Span::raw(marker),
                ssh_mark,
                Span::raw(" "),
                Span::styled(format!("{:<20}", vm.alias), alias_style),
                Span::styled(
                    format!("{:<9}", vm.platform),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(format!("{role:<16}"), Style::default().fg(Color::Yellow)),
                Span::styled(format!("{:<16}", vm.ip), Style::default().fg(Color::Gray)),
                glyph,
                Span::raw(" "),
                Span::styled(activity.to_owned(), Style::default().fg(Color::Cyan)),
            ])
        })
        .collect();

    // Show overflow count if some VMs hidden
    let extra = app.vm_statuses.len().saturating_sub(max_lines);
    // 3-char prefix ("   ") to match each data row's marker(1) + ssh
    // check(1) + space(1), so the header lines up with the values below
    // instead of sitting one column short.
    let mut lines = vec![Line::from(vec![
        Span::raw("   "),
        Span::styled(format!("{:<20}", "ALIAS"), Style::default().fg(Color::Blue)),
        Span::styled(format!("{:<9}", "OS"), Style::default().fg(Color::Blue)),
        Span::styled(format!("{:<16}", "ROLE"), Style::default().fg(Color::Blue)),
        Span::styled(format!("{:<16}", "IP"), Style::default().fg(Color::Blue)),
        Span::styled("P", Style::default().fg(Color::Blue)),
        Span::raw(" "),
        Span::styled("ACTIVITY", Style::default().fg(Color::Blue)),
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
    use crate::data::vm_prober::VmStatus;
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
        // Regression: the header row used a 2-char prefix ("  ") while
        // every data row's actual prefix is 3 chars (marker + ssh-check +
        // space), so "alias/os/role/ip" sat one column left of the values
        // they were meant to label.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.vm_statuses = vec![VmStatus {
            alias: "debian-headless-1".into(),
            ip: "192.168.0.200".into(),
            platform: "linux".into(),
            ssh_ok: true,
        }];

        let backend = TestBackend::new(70, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, f.area(), &app)).unwrap();
        let buf = terminal.backend().buffer().clone();

        let header_row = 1;
        let data_row = 2;
        assert_eq!(
            col_of(&buf, header_row, "ALIAS"),
            col_of(&buf, data_row, "debian-headless-1"),
            "ALIAS header must start at the same column as the alias value"
        );
        assert_eq!(
            col_of(&buf, header_row, "OS"),
            col_of(&buf, data_row, "linux"),
            "OS header must start at the same column as the platform value"
        );
        assert_eq!(
            col_of(&buf, header_row, "IP"),
            col_of(&buf, data_row, "192.168.0.200"),
            "IP header must start at the same column as the ip value"
        );
    }

    fn windows_vm() -> VmStatus {
        VmStatus {
            alias: "windows-utm-1".into(),
            ip: "192.168.0.210".into(),
            platform: "windows".into(),
            ssh_ok: true,
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
        }
    }

    fn running_job() -> crate::data::job_watcher::JobState {
        crate::data::job_watcher::JobState {
            job_id: "monitor-1".to_owned(),
            state: "running".to_owned(),
            pid: Some(1),
            started_unix: Some(1),
            area: "test".to_owned(),
            report_dir: "state/monitor-loop-monitor-1".to_owned(),
            request_args: None,
        }
    }

    #[test]
    fn live_activity_matches_an_os_specific_stage_to_that_platforms_vm_only() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.active_job = Some(running_job());
        app.active_stage = Some("bootstrap_windows_host".to_owned());

        assert_eq!(
            live_activity_for_vm(&app, &windows_vm()),
            Some("bootstrap_windows_host")
        );
        assert_eq!(
            live_activity_for_vm(&app, &linux_vm()),
            None,
            "a windows-specific stage must not show against a linux VM"
        );
    }

    #[test]
    fn live_activity_is_none_for_a_cross_platform_stage() {
        // PRE and the 9 generic BOOTSTRAP stages have no OS keyword at all
        // and touch every node at once -- attributing them to one VM would
        // misleadingly imply the others are idle.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.active_job = Some(running_job());
        app.active_stage = Some("bootstrap_hosts".to_owned());

        assert_eq!(live_activity_for_vm(&app, &windows_vm()), None);
        assert_eq!(live_activity_for_vm(&app, &linux_vm()), None);
    }

    #[test]
    fn live_activity_is_none_once_the_lab_is_idle() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.active_stage = Some("bootstrap_windows_host".to_owned());
        // No active_job set -- lab_is_actively_running() is false.

        assert_eq!(
            live_activity_for_vm(&app, &windows_vm()),
            None,
            "a stale active_stage must not render as live activity once idle"
        );
    }

    #[test]
    fn parity_glyph_reflects_the_vms_role_state_with_parity_matrix_colors() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.config.windows_vm = "windows-utm-1".to_owned();
        app.config.exit_platform = "windows".to_owned();
        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Proven);

        let glyph = parity_glyph_for_vm(&app, &windows_vm()).expect("exit role has a glyph");
        assert_eq!(glyph.content.as_ref(), "●");
        assert_eq!(glyph.style.fg, Some(Color::Green));

        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Failed);
        let glyph = parity_glyph_for_vm(&app, &windows_vm()).unwrap();
        assert_eq!(glyph.style.fg, Some(Color::Red));

        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Flaky);
        let glyph = parity_glyph_for_vm(&app, &windows_vm()).unwrap();
        assert_eq!(glyph.style.fg, Some(Color::Yellow));
    }

    #[test]
    fn parity_glyph_is_none_when_the_vm_has_no_role_assigned() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        // linux_vm's alias doesn't match any config role slot, so
        // role_for_vm falls back to a non-role placeholder label.
        assert!(parity_glyph_for_vm(&app, &linux_vm()).is_none());
    }

    #[test]
    fn render_shows_activity_and_glyph_columns_aligned_with_the_header() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.active_job = Some(running_job());
        app.active_stage = Some("bootstrap_windows_host".to_owned());
        app.parity_matrix
            .insert((Role::Exit, Os::Windows), ParityState::Proven);
        app.config.windows_vm = "windows-utm-1".to_owned();
        app.config.exit_platform = "windows".to_owned();
        app.vm_statuses = vec![windows_vm(), linux_vm()];

        let backend = TestBackend::new(110, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, f.area(), &app)).unwrap();
        let buf = terminal.backend().buffer().clone();

        let header_row = 1;
        let windows_row = 2;
        let linux_row = 3;
        // "P ACTIVITY", not bare "P" -- "IP"'s own trailing P would
        // otherwise be the first (wrong) match for a 1-char needle.
        let glyph_header_col = col_of(&buf, header_row, "P ACTIVITY");
        assert_eq!(
            glyph_header_col,
            col_of(&buf, windows_row, "●"),
            "the P header must line up with the parity glyph column"
        );
        assert_eq!(
            col_of(&buf, header_row, "ACTIVITY"),
            col_of(&buf, windows_row, "bootstrap_windows_host"),
            "the ACTIVITY header must line up with the activity column"
        );
        assert!(
            col_of(&buf, linux_row, "●").is_none(),
            "linux VM has no role assigned, so no parity glyph should render"
        );
        assert!(
            col_of(&buf, linux_row, "bootstrap_windows_host").is_none(),
            "a windows-specific stage must not render against the linux row"
        );
    }
}
