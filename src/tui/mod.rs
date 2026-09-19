pub mod app;
pub mod handler;
pub mod sanitize;
pub mod ui;

pub use app::*;
pub use handler::*;
pub use sanitize::*;
pub use ui::*;

use crossterm::event::{poll, read, Event};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::time::Duration;

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::default();

    while !app.should_quit {
        app.poll_scan_events();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if poll(Duration::from_millis(50))? {
            if let Event::Key(key) = read()? {
                handle_key_event(&mut app, key);
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
