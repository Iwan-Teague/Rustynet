use anyhow::{Context, Result};
use crossterm::{
    cursor::{Hide, Show},
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Terminal size (cols, rows) before we enlarged it at startup.
static ORIGINAL_SIZE: OnceLock<(u16, u16)> = OnceLock::new();

/// Grow the terminal window by `extra_cols` × `extra_rows` using the xterm
/// resize escape (`\x1b[8;<rows>;<cols>t`).  Saves the original size so
/// `restore_terminal` can shrink it back.  Silently ignored by terminals that
/// don't support the sequence (tmux, VS Code integrated terminal, etc.).
fn resize_terminal_window(extra_cols: u16, extra_rows: u16) {
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        ORIGINAL_SIZE.set((cols, rows)).ok();
        let new_cols = cols.saturating_add(extra_cols);
        let new_rows = rows.saturating_add(extra_rows);
        print!("\x1b[8;{new_rows};{new_cols}t");
        let _ = io::stdout().flush();
        // Give the terminal emulator a moment to process the resize before
        // we query the new size for layout.
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
}

mod app;
mod config;
mod control;
mod data;
mod ui;

fn init_logging(repo_root: &std::path::Path) -> Result<()> {
    let log_dir = repo_root.join("state");
    std::fs::create_dir_all(&log_dir).ok();

    let log_path = log_dir.join("monitor.log");
    let _ = std::fs::File::create(&log_path);

    let make_writer = {
        let log_path = log_path.clone();
        move || -> Box<dyn std::io::Write> {
            match std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&log_path)
            {
                Ok(f) => Box::new(f),
                Err(_) => Box::new(io::stderr()),
            }
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(make_writer)
        .with_ansi(false)
        .init();

    Ok(())
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode().context("enabling raw terminal mode")?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        Hide,
        Clear(ClearType::All),
        Clear(ClearType::Purge)
    )
    .context("entering terminal UI mode")?;

    Terminal::new(CrosstermBackend::new(stdout)).context("creating terminal backend")
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        Show,
        DisableMouseCapture,
        LeaveAlternateScreen
    );
    // Restore window to its pre-launch size (no-op if we never resized).
    if let Some(&(cols, rows)) = ORIGINAL_SIZE.get() {
        print!("\x1b[8;{rows};{cols}t");
        let _ = io::stdout().flush();
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let repo_root = if let Some(idx) = args.iter().position(|a| a == "--repo-root") {
        PathBuf::from(&args[idx + 1])
    } else {
        std::env::current_dir().context("getting current directory")?
    };

    init_logging(&repo_root)?;

    // Headless snapshot mode: build the model, refresh once, print what the TUI
    // would render for the latest/active run, and exit — no terminal required
    // (Bucket 3, Full-Replacement DoD). Enables scripted / CI verification of
    // the monitor's data (works identically for a bash or a Rust --node run).
    if args.iter().any(|a| a == "--snapshot") {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("building tokio runtime")?;
        return rt.block_on(async {
            let mut app = app::App::new(repo_root.clone())?;
            app.refresh_state().await;
            print!("{}", app.snapshot_text());
            Ok(())
        });
    }

    // Set panic hook to restore terminal before printing panic
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        prev_hook(info);
    }));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    // Expand the terminal window before entering the TUI so the layout
    // has room for the prev-runs panel row at the bottom.
    resize_terminal_window(5, 5);

    let result = rt.block_on(async {
        let mut app = app::App::new(repo_root.clone())?;

        let mut terminal = init_terminal()?;

        let result = app.run_event_loop(&mut terminal).await;

        restore_terminal();
        result
    });

    restore_terminal();
    result?;
    Ok(())
}
