//! Terminal UI rendering with Ratatui

use crate::app::{App, Focus, LoginField};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

/// Main draw function
pub fn draw(frame: &mut Frame, app: &App) {
    match app.focus {
        Focus::Login => draw_login(frame, app),
        _ => draw_main(frame, app),
    }

    // Draw error popup if present
    if let Some(ref error) = app.error_message {
        draw_error_popup(frame, error);
    }

    // Draw status if present
    if let Some(ref status) = app.status_message {
        draw_status(frame, status);
    }
}

fn draw_login(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Center the login form
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Length(10),
            Constraint::Percentage(30),
        ])
        .split(area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(50),
            Constraint::Percentage(25),
        ])
        .split(vertical[1]);

    let form_area = horizontal[1];

    let block = Block::default()
        .title(" Moat - Login ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(form_area);
    frame.render_widget(block, form_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(inner);

    // Handle label
    let handle_style = if app.login_form.field == LoginField::Handle {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let handle_label = Paragraph::new("Handle:").style(handle_style);
    frame.render_widget(handle_label, chunks[0]);

    // Handle input
    let handle_block = Block::default().borders(Borders::ALL).border_style(
        if app.login_form.field == LoginField::Handle {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        },
    );
    let handle_input = Paragraph::new(app.login_form.handle.as_str())
        .block(handle_block);
    frame.render_widget(handle_input, chunks[1]);

    // Password label
    let password_style = if app.login_form.field == LoginField::Password {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let password_label = Paragraph::new("App Password:").style(password_style);
    frame.render_widget(password_label, chunks[2]);

    // Password input (masked)
    let password_block = Block::default().borders(Borders::ALL).border_style(
        if app.login_form.field == LoginField::Password {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        },
    );
    let masked: String = "*".repeat(app.login_form.password.len());
    let password_input = Paragraph::new(masked).block(password_block);
    frame.render_widget(password_input, chunks[3]);

    // Show cursor in active field
    let cursor_pos = match app.login_form.field {
        LoginField::Handle => (
            chunks[1].x + 1 + app.login_form.handle.len() as u16,
            chunks[1].y + 1,
        ),
        LoginField::Password => (
            chunks[3].x + 1 + app.login_form.password.len() as u16,
            chunks[3].y + 1,
        ),
    };
    frame.set_cursor_position(cursor_pos);
}

fn draw_main(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Main layout: conversations | messages
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    // Conversations panel
    draw_conversations(frame, app, horizontal[0]);

    // Right panel: messages + input
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(horizontal[1]);

    draw_messages(frame, app, right[0]);
    draw_input(frame, app, right[1]);
}

fn draw_conversations(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Conversations;

    let block = Block::default()
        .title(" Conversations ")
        .borders(Borders::ALL)
        .border_style(if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });

    let items: Vec<ListItem> = app
        .conversations
        .iter()
        .enumerate()
        .map(|(i, conv)| {
            let style = if Some(i) == app.active_conversation {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let prefix = if Some(i) == app.active_conversation {
                "> "
            } else {
                "  "
            };

            let unread = if conv.unread > 0 {
                format!(" ({})", conv.unread)
            } else {
                String::new()
            };

            ListItem::new(format!("{}{}{}", prefix, conv.name, unread)).style(style)
        })
        .collect();

    // Help text at bottom if no conversations
    if app.conversations.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let help = Paragraph::new("Press 'n' to start\na new conversation")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(help, inner);
    } else {
        let list = List::new(items).block(block);
        frame.render_widget(list, area);
    }
}

fn draw_messages(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Messages;

    let block = Block::default()
        .title(" Messages ")
        .borders(Borders::ALL)
        .border_style(if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });

    let items: Vec<ListItem> = app
        .messages
        .iter()
        .map(|msg| {
            let style = if msg.is_own {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::White)
            };

            let time = msg.timestamp.format("%H:%M").to_string();
            let line = Line::from(vec![
                Span::styled(format!("[{}] ", time), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{}: ", msg.from), style.add_modifier(Modifier::BOLD)),
                Span::raw(&msg.content),
            ]);

            ListItem::new(line)
        })
        .collect();

    // Show help if no active conversation
    if app.active_conversation.is_none() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let help = Paragraph::new("Select a conversation\nor press 'n' to start one")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(help, inner);
    } else {
        let list = List::new(items).block(block);
        frame.render_widget(list, area);
    }
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Input;

    let block = Block::default()
        .title(" Message ")
        .borders(Borders::ALL)
        .border_style(if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });

    let input = Paragraph::new(app.input_buffer.as_str())
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(input, area);

    // Show cursor if focused
    if is_focused {
        frame.set_cursor_position((
            area.x + 1 + app.cursor_position as u16,
            area.y + 1,
        ));
    }
}

fn draw_error_popup(frame: &mut Frame, error: &str) {
    let area = frame.area();

    // Center popup
    let popup_width = (area.width as f32 * 0.6) as u16;
    let popup_height = 5;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" Error ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let text = Paragraph::new(error)
        .block(block)
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(Color::Red));

    frame.render_widget(text, popup_area);
}

fn draw_status(frame: &mut Frame, status: &str) {
    let area = frame.area();

    // Bottom status bar
    let status_area = Rect::new(0, area.height - 1, area.width, 1);

    let text = Paragraph::new(status)
        .style(Style::default().fg(Color::Yellow).bg(Color::DarkGray));

    frame.render_widget(text, status_area);
}
