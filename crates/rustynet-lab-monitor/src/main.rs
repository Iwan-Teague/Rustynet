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
use std::io;
use std::path::PathBuf;

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
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let repo_root = if let Some(idx) = args.iter().position(|a| a == "--repo-root") {
        PathBuf::from(&args[idx + 1])
    } else {
        std::env::current_dir().context("getting current directory")?
    };

    init_logging(&repo_root)?;

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
