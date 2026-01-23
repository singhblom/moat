//! Moat CLI - Terminal UI for encrypted ATProto messaging

mod app;
mod keystore;
mod ui;

use app::App;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "moat", about = "Terminal UI for encrypted ATProto messaging")]
struct Args {
    /// Custom storage directory (default: ~/.moat)
    #[arg(short = 's', long = "storage-dir")]
    storage_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let result = run_app(&mut terminal, args.storage_dir).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = result {
        eprintln!("Error: {err:?}");
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    storage_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let mut app = App::new(storage_dir)?;

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        // Poll for events with timeout to allow async operations
        if event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                // Global quit
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(());
                }

                match app.handle_key(key).await {
                    Ok(should_quit) => {
                        if should_quit {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        app.set_error(format!("{e}"));
                    }
                }
            }
        }

        // Process any pending async operations
        app.tick().await?;
    }
}
