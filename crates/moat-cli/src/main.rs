//! Moat CLI - Terminal UI for encrypted ATProto messaging

mod app;
mod keystore;
mod ui;

use app::App;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let result = run_app(&mut terminal).await;

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

async fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> anyhow::Result<()> {
    let mut app = App::new()?;

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
