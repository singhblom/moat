//! Terminal UI rendering with Ratatui

use crate::app::{App, DeviceAlert, Focus, LoginField, QUICK_EMOJIS};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::{sync::LazyLock, time::Instant};

static START_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);

fn color_pulse(
    start_r: f32,
    start_g: f32,
    start_b: f32,
    end_r: f32,
    end_g: f32,
    end_b: f32,
    period_ms: u32,
) -> Color {
    let elapsed = START_TIME.elapsed().as_millis() as f32;
    let t = ((elapsed / period_ms as f32) * std::f32::consts::TAU).sin();
    let t = (t + 1.0) / 2.0;
    let r = start_r * (1.0 - t) + t * end_r;
    let g = start_g * (1.0 - t) + t * end_g;
    let b = start_b * (1.0 - t) + t * end_b;
    Color::Rgb(r as u8, g as u8, b as u8)
}

/// Main draw function
pub fn draw(frame: &mut Frame, app: &App) {
    match app.focus {
        Focus::Login => draw_login(frame, app),
        _ => draw_main(frame, app),
    }

    // Draw input popups
    if app.focus == Focus::NewConversation {
        draw_handle_input_popup(
            frame,
            "New Conversation",
            "Enter handle:",
            &app.new_conv_handle,
        );
    } else if app.focus == Focus::WatchHandle {
        draw_handle_input_popup(
            frame,
            "Watch for Invites",
            "Enter handle to watch:",
            &app.watch_handle_input,
        );
    }

    // Draw message info popup if toggled
    if app.show_message_info {
        draw_message_info_popup(frame, app);
    }

    // Reaction picker is drawn inline in draw_messages

    // Draw device alerts if any
    if let Some(alert) = app.device_alerts.first() {
        draw_device_alert(frame, alert);
    }

    // Draw error popup if present
    if let Some(ref error) = app.error_message {
        draw_error_popup(frame, error);
    }

    // Draw bottom info bar: status message takes priority, otherwise show user info
    if let Some(ref status) = app.status_message {
        draw_status(frame, status);
    } else if let Some(ref handle) = app.logged_in_handle {
        let info = if let Some(ref url) = app.drawbridge_url {
            format!("{handle}  ::  {url}")
        } else {
            handle.clone()
        };
        draw_info_bar(frame, &info);
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
    let color = color_pulse(38.0, 227.0, 195.0, 38.0, 195.0, 227.0, 5000);
    let style = Style::default().fg(color);
    let block = Block::default()
        .title(" Moat - Login ")
        .borders(Borders::ALL)
        .style(style);

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
            Style::default().fg(Color::Gray)
        },
    );
    let handle_input = Paragraph::new(app.login_form.handle.as_str()).block(handle_block);
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
            Style::default().fg(Color::Gray)
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

    // Reserve a row at the bottom for the info bar when logged in
    let has_info_bar = app.logged_in_handle.is_some();
    let outer = if has_info_bar {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(1)])
            .split(area)
    } else {
        // No info bar — give all space to content
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(0)])
            .split(area)
    };

    let content_area = outer[0];

    // Main layout: conversations | messages
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(content_area);

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
    let color = if is_focused {
        color_pulse(38.0, 227.0, 195.0, 38.0, 195.0, 227.0, 5000)
    } else {
        Color::Gray
    };
    let style = Style::default().fg(color);

    let relay_count = app.drawbridge.active_connection_count();
    let title = if relay_count > 0 {
        format!(" Conversations  [relay:{}] ", relay_count)
    } else {
        " Conversations ".to_string()
    };

    let block = Block::default()
        .title(title)
        .title_style(style.add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .style(style);

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
        let help = Paragraph::new("'n' new conversation\n'w' watch for invites\n'q' to quit")
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(help, inner);
    } else {
        let list = List::new(items).block(block);
        frame.render_widget(list, area);
    }
}

fn draw_messages(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Messages;
    let color = if is_focused {
        color_pulse(38.0, 227.0, 195.0, 38.0, 195.0, 227.0, 5000)
    } else {
        Color::Gray
    };
    let style = Style::default().fg(color);

    let title = if is_focused && app.selected_message.is_some() {
        " Messages  [r]eact [i]nfo "
    } else {
        " Messages "
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .style(style);

    // Show help if no active conversation
    if app.active_conversation.is_none() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let help = Paragraph::new("Select a conversation\nor press 'n' to start one")
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(help, inner);
    } else {
        let inner_width = area.width.saturating_sub(2) as usize; // subtract borders
        let visible_height = area.height.saturating_sub(2) as usize;

        // Compute which message index is selected (selected_message is offset from bottom)
        let selected_msg_index = app
            .selected_message
            .map(|offset| app.messages.len().saturating_sub(1).saturating_sub(offset));

        // Build styled lines for each message
        let mut lines: Vec<Line> = Vec::new();
        for (msg_idx, msg) in app.messages.iter().enumerate() {
            let is_selected = selected_msg_index == Some(msg_idx) && is_focused;

            let msg_style = if msg.is_own {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::White)
            };

            // Selected message gets a background highlight
            let msg_style = if is_selected {
                msg_style.bg(Color::Rgb(40, 40, 60))
            } else {
                msg_style
            };

            let time = msg.timestamp.format("%H:%M").to_string();
            let prefix = format!("[{}] {}: ", time, msg.from);
            let content = &msg.content;

            // Selection indicator
            let indicator = if is_selected { "▎" } else { " " };
            let indicator_style = if is_selected {
                Style::default().fg(Color::Cyan).bg(Color::Rgb(40, 40, 60))
            } else {
                Style::default()
            };

            let time_style = if is_selected {
                Style::default().fg(Color::Gray).bg(Color::Rgb(40, 40, 60))
            } else {
                Style::default().fg(Color::Gray)
            };

            let name_style = if is_selected {
                msg_style.add_modifier(Modifier::BOLD)
            } else {
                msg_style.add_modifier(Modifier::BOLD)
            };

            // First visual line has the styled prefix
            if inner_width > 0 {
                let first_content_len = inner_width.saturating_sub(prefix.len() + 1); // +1 for indicator
                let first_chunk: String = content.chars().take(first_content_len).collect();
                lines.push(Line::from(vec![
                    Span::styled(indicator, indicator_style),
                    Span::styled(format!("[{}] ", time), time_style),
                    Span::styled(format!("{}: ", msg.from), name_style),
                    Span::styled(first_chunk, msg_style),
                ]));

                // Remaining content wraps onto continuation lines
                let remaining: String = content.chars().skip(first_content_len).collect();
                let wrap_width = inner_width.saturating_sub(1); // account for indicator column
                for chunk in remaining.chars().collect::<Vec<_>>().chunks(wrap_width) {
                    let s: String = chunk.iter().collect();
                    lines.push(Line::from(vec![
                        Span::styled(" ", indicator_style),
                        Span::styled(s, msg_style),
                    ]));
                }

                // Show aggregated reactions below the message
                if !msg.reactions.is_empty() {
                    // Aggregate: count each emoji
                    let mut counts: std::collections::BTreeMap<&str, usize> =
                        std::collections::BTreeMap::new();
                    for r in &msg.reactions {
                        *counts.entry(&r.emoji).or_insert(0) += 1;
                    }
                    let reaction_chips: Vec<String> = counts
                        .iter()
                        .map(|(emoji, count)| {
                            if *count > 1 {
                                format!("{} {}", emoji, count)
                            } else {
                                emoji.to_string()
                            }
                        })
                        .collect();
                    let reaction_line = format!(" {}", reaction_chips.join("  "));
                    let reaction_style = if is_selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .bg(Color::Rgb(40, 40, 60))
                    } else {
                        Style::default().fg(Color::Yellow)
                    };
                    lines.push(Line::from(vec![
                        Span::styled(" ", indicator_style),
                        Span::styled(reaction_line, reaction_style),
                    ]));
                }

                // Show inline emoji picker for selected message
                if is_selected {
                    if let Some(picker_idx) = app.reaction_picker {
                        let mut spans: Vec<Span> =
                            vec![Span::styled(" ", indicator_style), Span::raw(" ")];
                        for (i, emoji) in QUICK_EMOJIS.iter().enumerate() {
                            let style = if i == picker_idx {
                                Style::default().bg(Color::Yellow).fg(Color::Black)
                            } else {
                                Style::default().fg(Color::Gray)
                            };
                            spans.push(Span::styled(format!(" {} ", emoji), style));
                            if i + 1 < QUICK_EMOJIS.len() {
                                spans.push(Span::raw(" "));
                            }
                        }
                        lines.push(Line::from(spans));
                    }
                }
            }
        }

        let total_lines = lines.len();
        // message_scroll is offset from the bottom (0 = showing latest)
        let scroll_to_bottom = total_lines.saturating_sub(visible_height);
        let scroll_y = scroll_to_bottom.saturating_sub(app.message_scroll) as u16;

        let paragraph = Paragraph::new(lines).block(block).scroll((scroll_y, 0));
        frame.render_widget(paragraph, area);
    }
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Input;
    let color = if is_focused {
        color_pulse(38.0, 227.0, 195.0, 38.0, 195.0, 227.0, 5000)
    } else {
        Color::Gray
    };
    let style = Style::default().fg(color);

    let block = Block::default()
        .title(" Message ")
        .borders(Borders::ALL)
        .style(style);

    let input = Paragraph::new(app.input_buffer.as_str())
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(input, area);

    // Show cursor if focused
    if is_focused {
        frame.set_cursor_position((area.x + 1 + app.cursor_position as u16, area.y + 1));
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

    let text = Paragraph::new(status).style(Style::default().fg(Color::Yellow).bg(Color::Gray));

    frame.render_widget(text, status_area);
}

fn draw_info_bar(frame: &mut Frame, info: &str) {
    let area = frame.area();
    let bar_area = Rect::new(0, area.height - 1, area.width, 1);

    let text = Paragraph::new(info).style(Style::default().fg(Color::DarkGray));

    frame.render_widget(text, bar_area);
}

fn draw_handle_input_popup(frame: &mut Frame, title: &str, label: &str, input: &str) {
    let area = frame.area();

    // Center popup
    let popup_width = 50.min(area.width.saturating_sub(4));
    let popup_height = 6;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(format!(" {} ", title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(3)])
        .split(inner);

    // Label
    let label_widget = Paragraph::new(label).style(Style::default().fg(Color::Yellow));
    frame.render_widget(label_widget, chunks[0]);

    // Input field
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let input_widget = Paragraph::new(input).block(input_block);
    frame.render_widget(input_widget, chunks[1]);

    // Cursor
    frame.set_cursor_position((chunks[1].x + 1 + input.len() as u16, chunks[1].y + 1));
}

fn draw_message_info_popup(frame: &mut Frame, app: &App) {
    // Get the selected message (from bottom offset)
    let msg_index = if let Some(offset) = app.selected_message {
        app.messages.len().saturating_sub(1).saturating_sub(offset)
    } else {
        return;
    };

    let msg = match app.messages.get(msg_index) {
        Some(m) => m,
        None => return,
    };

    let area = frame.area();

    // Center popup
    let popup_width = 50.min(area.width.saturating_sub(4));
    let popup_height = 10;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" Message Info (press 'i' or Esc to close) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build info lines
    let mut lines = vec![
        Line::from(vec![
            Span::styled("From: ", Style::default().fg(Color::Yellow)),
            Span::raw(&msg.from),
        ]),
        Line::from(vec![
            Span::styled("Time: ", Style::default().fg(Color::Yellow)),
            Span::raw(msg.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        ]),
    ];

    if let Some(ref did) = msg.sender_did {
        lines.push(Line::from(vec![
            Span::styled("DID: ", Style::default().fg(Color::Yellow)),
            Span::raw(did),
        ]));
    }

    if let Some(ref device) = msg.sender_device {
        lines.push(Line::from(vec![
            Span::styled("Device: ", Style::default().fg(Color::Yellow)),
            Span::raw(device),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "Content: ",
        Style::default().fg(Color::Yellow),
    )]));

    // Truncate content if too long
    let max_content_len = (popup_width as usize).saturating_sub(4);
    let content_preview: String = msg.content.chars().take(max_content_len).collect();
    lines.push(Line::from(Span::raw(content_preview)));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

fn draw_device_alert(frame: &mut Frame, alert: &DeviceAlert) {
    let area = frame.area();

    // Top notification bar
    let alert_width = area.width.saturating_sub(4);
    let alert_height = 3;
    let alert_x = 2;
    let alert_y = 1;

    let alert_area = Rect::new(alert_x, alert_y, alert_width, alert_height);

    frame.render_widget(Clear, alert_area);

    let block = Block::default()
        .title(" New Device Alert ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let text = format!(
        "New device '{}:{}' joined conversation '{}' at {} (press any key to dismiss)",
        alert.user_name, alert.device_name, alert.conversation_name, alert.timestamp
    );

    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(Color::Magenta));

    frame.render_widget(paragraph, alert_area);
}
