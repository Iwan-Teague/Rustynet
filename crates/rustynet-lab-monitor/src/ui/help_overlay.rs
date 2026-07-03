use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};

pub fn render(f: &mut Frame, full_area: Rect) {
    // Center a 58x24 popup
    let popup_w = 58u16.min(full_area.width);
    let popup_h = 24u16.min(full_area.height);
    let x = (full_area.width.saturating_sub(popup_w)) / 2;
    let y = (full_area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect::new(full_area.x + x, full_area.y + y, popup_w, popup_h);

    f.render_widget(Clear, popup_area);
    let block = Block::default()
        .title("HELP (Esc to close)")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let bindings = vec![
        ("Tab", "Cycle overview/run/matrix pages"),
        ("1 / v", "Overview page VM status"),
        ("2 / p", "Overview page parity matrix"),
        ("3", "Run page stage grid"),
        ("4 / l", "Run page log panel"),
        ("5 / j", "Run page jobs panel"),
        ("6 / m", "Full stage matrix (every check x OS)"),
        ("Matrix ↑↓", "Scroll all 3 OS columns together"),
        ("s / ^S", "Start OpenCode live-lab loop if idle"),
        ("d", "Stop after current lab run completes"),
        ("x", "Stop active OpenCode live-lab loop"),
        ("r / ^R", "Force refresh (VM probe + state reload)"),
        ("y", "Copy current/failed stage logs to clipboard"),
        (
            "a",
            "Auto-fill config for next failed/unproven role x OS cell",
        ),
        ("Stage ↑↓", "Move selected stage; list follows selection"),
        ("Stage Space", "Toggle selected stage on/off"),
        (
            "Stage Enter",
            "Open stage detail overlay (summary + artifacts)",
        ),
        ("VM ↑↓", "Select VM row"),
        ("VM ←→", "Cycle selected VM role"),
        ("Log ↑↓", "Scroll log (pauses autoscroll)"),
        ("Log G/End", "Resume tail-follow (clear pin)"),
        ("?", "Toggle this help overlay"),
        ("q / ^Q", "Quit"),
    ];

    let lines: Vec<Line> = bindings
        .iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(format!("{key:16}"), Style::default().fg(Color::Yellow)),
                Span::styled(*desc, Style::default().fg(Color::White)),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(lines), inner);
}
