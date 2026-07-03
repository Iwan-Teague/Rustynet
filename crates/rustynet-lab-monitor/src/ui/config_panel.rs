use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled("CONFIG", Style::default().fg(Color::Cyan)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let config = &app.config;
    let fields: Vec<(&str, &str)> = vec![
        ("Area", &config.area),
        ("exit_vm", &config.exit_vm),
        ("client_vm", &config.client_vm),
        ("entry_vm", &config.entry_vm),
        ("macos_vm", &config.macos_vm),
        ("windows_vm", &config.windows_vm),
        ("relay_platform", &config.relay_platform),
        ("anchor_platform", &config.anchor_platform),
        ("exit_platform", &config.exit_platform),
        ("admin_platform", &config.admin_platform),
        ("blind_exit_platform", &config.blind_exit_platform),
        (
            "macos_promote_exit",
            if config.macos_promote_exit {
                "YES"
            } else {
                "NO"
            },
        ),
        (
            "skip_linux_live_suite",
            if config.skip_linux_live_suite {
                "YES"
            } else {
                "NO"
            },
        ),
        ("rebuild_nodes", &config.rebuild_nodes),
        (
            "triage_on_failure",
            if config.triage_on_failure {
                "YES"
            } else {
                "NO"
            },
        ),
        ("dry_run", if config.dry_run { "YES" } else { "NO" }),
        (
            "disabled_stages",
            if config.disabled_stages.is_empty() {
                "0"
            } else {
                "set"
            },
        ),
    ];

    let mut lines: Vec<Line> = Vec::new();
    for (label, value) in fields.iter() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}: ", label.to_ascii_uppercase()),
                Style::default().fg(Color::Gray),
            ),
            Span::styled(*value, Style::default().fg(Color::White)),
        ]));
    }

    f.render_widget(Paragraph::new(lines), inner);
}
