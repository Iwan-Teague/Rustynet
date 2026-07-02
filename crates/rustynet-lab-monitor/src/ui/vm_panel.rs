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
    let title = format!(
        "VM STATUS [1/V] ({})  ↑↓ select  {role_hint}  c fetch commits",
        count
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
            let commit = vm.git_commit.as_deref().unwrap_or("—");

            Line::from(vec![
                Span::raw(marker),
                ssh_mark,
                Span::raw(" "),
                Span::styled(format!("{:<20}", vm.alias), alias_style),
                Span::styled(
                    format!("{:<9}", vm.platform),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(format!("{:<16}", role), Style::default().fg(Color::Yellow)),
                Span::styled(format!("{:<16}", vm.ip), Style::default().fg(Color::Gray)),
                Span::styled(commit.to_string(), Style::default().fg(Color::Cyan)),
            ])
        })
        .collect();

    // Show overflow count if some VMs hidden
    let extra = app.vm_statuses.len().saturating_sub(max_lines);
    let mut lines = vec![Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("{:<20}", "alias"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(format!("{:<9}", "os"), Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{:<16}", "role"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{:<16}", "ip"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("commit", Style::default().fg(Color::DarkGray)),
    ])];
    lines.extend(visible);
    if extra > 0 {
        lines.push(Line::from(Span::styled(
            format!("  … and {} more", extra),
            Style::default().fg(Color::DarkGray),
        )));
    }

    f.render_widget(Paragraph::new(lines), inner);
}
