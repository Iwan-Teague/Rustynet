use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, Panel};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let count = app.vm_statuses.len();
    let focused = app.focused_panel == Panel::VmStatus;
    let role_hint = if app.roles_locked_by_active_lab() {
        "roles locked to active lab"
    } else {
        "←→ role"
    };
    let title = format!("VM STATUS [1/V] ({count})  ↑↓ select  {role_hint}");

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
                Span::styled(vm.ip.clone(), Style::default().fg(Color::Gray)),
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
        Span::styled("IP", Style::default().fg(Color::Blue)),
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
        terminal
            .draw(|f| render(f, f.area(), &app))
            .unwrap();
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
}
