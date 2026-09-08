//! Terminal UI rendering with Ratatui

use crate::app::{App, DeviceAlert, DisplayMessage, Focus, LoginField, QUICK_EMOJIS};
use moat_core::{PairingUiState, SyncFailure, SyncRequestUiState, SyncTally};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use ratatui_image::StatefulImage;
use std::{sync::LazyLock, time::Instant};

/// Number of terminal rows reserved for rendering an inline image.
const IMAGE_RENDER_ROWS: u16 = 16;

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
pub fn draw(frame: &mut Frame, app: &mut App) {
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
    } else if app.focus == Focus::PairEnterCode {
        draw_handle_input_popup(
            frame,
            "Link a Device",
            "Enter pairing code:",
            &app.pair_enter_code_input,
        );
    } else if app.focus == Focus::PairShowCode {
        draw_pair_show_code_popup(frame, app);
    } else if app.focus == Focus::PairApprove {
        draw_pair_approve_popup(frame, app);
    } else if app.focus == Focus::SyncApprove {
        draw_sync_approve_popup(frame, app);
    } else if app.focus == Focus::Devices {
        draw_devices_popup(frame, app);
    } else if app.focus == Focus::SyncOfferPrompt {
        draw_sync_offer_prompt(frame, app);
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

fn draw_main(frame: &mut Frame, app: &mut App) {
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
    // Key hints live in the title, matching the Messages pane, because the
    // help text below only renders while there are no conversations — so
    // every hint it carries vanishes the moment the user has one.
    let hints = if is_focused { "  [n]ew [d]evices" } else { "" };
    let title = if relay_count > 0 {
        format!(" Conversations{hints}  [relay:{relay_count}] ")
    } else {
        format!(" Conversations{hints} ")
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

            ListItem::new(format!("{}{}{}", prefix, conv.display_name(), unread)).style(style)
        })
        .collect();

    // Help text at bottom if no conversations
    if app.conversations.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let help = Paragraph::new(
            "'n' new conversation\n'w' watch for invites\n'd' linked devices\n\
             'p' show pairing code\n'P' enter pairing code\n'q' to quit",
        )
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(help, inner);
    } else {
        let list = List::new(items).block(block);
        frame.render_widget(list, area);
    }
}

fn draw_messages(frame: &mut Frame, app: &mut App, area: Rect) {
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

    if app.active_conversation.is_none() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let help = Paragraph::new("Select a conversation\nor press 'n' to start one")
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(help, inner);
        return;
    }

    let inner = block.inner(area);
    let inner_width = inner.width;
    let visible_height = inner.height;
    let w = inner_width as usize;

    // Extract immutable values before any mutable borrow of app.messages.
    let selected_msg_index = app
        .selected_message
        .map(|offset| app.messages.len().saturating_sub(1).saturating_sub(offset));
    let reaction_picker = app.reaction_picker;
    let message_scroll = app.message_scroll;

    // Pre-compute per-message heights (immutable pass).
    let heights: Vec<u16> = app
        .messages
        .iter()
        .enumerate()
        .map(|(i, msg)| {
            let is_sel_with_picker =
                selected_msg_index == Some(i) && reaction_picker.is_some();
            let text_rows = compute_msg_text_rows(msg, w, is_sel_with_picker);
            text_rows + if msg.image_proto.is_some() { IMAGE_RENDER_ROWS } else { 0 }
        })
        .collect();

    let total_rows: u16 = heights.iter().sum();
    let scroll_to_bottom = total_rows.saturating_sub(visible_height);
    let scroll_y = scroll_to_bottom.saturating_sub(message_scroll as u16);

    // Render block border first (consumes `block`).
    frame.render_widget(block, area);

    // Render each message in its own sub-Rect.
    let mut cumulative_y: u16 = 0;
    for (msg_idx, &h) in heights.iter().enumerate().take(app.messages.len()) {
        let msg_top = cumulative_y;
        cumulative_y += h;

        // Skip messages entirely above the viewport.
        if cumulative_y <= scroll_y {
            continue;
        }

        let vh = visible_height as i32;
        let view_top = msg_top as i32 - scroll_y as i32;

        // Stop once we're past the bottom of the viewport.
        if view_top >= vh {
            break;
        }

        let is_selected = selected_msg_index == Some(msg_idx) && is_focused;
        let is_sel_with_picker = is_selected && reaction_picker.is_some();
        let text_rows =
            compute_msg_text_rows(&app.messages[msg_idx], w, is_sel_with_picker) as i32;

        // ── Text portion ──────────────────────────────────────────────────────
        let text_view_bottom = view_top + text_rows;
        if text_view_bottom > 0 && view_top < vh {
            let render_y = view_top.max(0) as u16;
            let skip_rows = (-view_top).max(0) as u16;
            let visible_rows = (vh.min(text_view_bottom) - render_y as i32) as u16;
            if visible_rows > 0 {
                let text_rect =
                    Rect::new(inner.x, inner.y + render_y, inner_width, visible_rows);
                let lines = build_msg_lines(
                    &app.messages[msg_idx],
                    w,
                    is_selected,
                    reaction_picker,
                );
                let para = if skip_rows > 0 {
                    Paragraph::new(lines).scroll((skip_rows, 0))
                } else {
                    Paragraph::new(lines)
                };
                frame.render_widget(para, text_rect);
            }
        }

        // ── Image portion ─────────────────────────────────────────────────────
        let img_view_top = view_top + text_rows;
        let img_view_bottom = view_top + h as i32;
        if img_view_bottom > 0 && img_view_top < vh && app.messages[msg_idx].image_proto.is_some()
        {
            let render_y = img_view_top.max(0) as u16;
            let visible_rows = (vh.min(img_view_bottom) - render_y as i32) as u16;
            if visible_rows > 0 {
                let img_rect =
                    Rect::new(inner.x, inner.y + render_y, inner_width, visible_rows);
                let proto = app.messages[msg_idx].image_proto.as_mut().unwrap();
                frame.render_stateful_widget(StatefulImage::default(), img_rect, &mut proto.0);
            }
        }
    }
}

/// Count how many terminal rows the text portion of a message occupies.
fn compute_msg_text_rows(
    msg: &DisplayMessage,
    inner_width: usize,
    is_selected_with_picker: bool,
) -> u16 {
    if inner_width == 0 {
        return 1;
    }
    let time = msg.timestamp.format("%H:%M").to_string();
    let prefix = format!("[{}] {}: ", time, msg.from);
    // +1 for the indicator column
    let first_content_len = inner_width.saturating_sub(prefix.len() + 1);

    let content_chars = msg.content.chars().count();
    let mut rows: u16 = 1;

    if first_content_len > 0 && content_chars > first_content_len {
        let remaining = content_chars - first_content_len;
        let wrap_width = inner_width.saturating_sub(1); // indicator column
        if wrap_width > 0 {
            rows += remaining.div_ceil(wrap_width) as u16;
        }
    }

    if !msg.reactions.is_empty() {
        rows += 1;
    }
    if is_selected_with_picker {
        rows += 1;
    }
    rows
}

/// Build the styled `Line`s for the text portion of a single message.
fn build_msg_lines(
    msg: &DisplayMessage,
    inner_width: usize,
    is_selected: bool,
    reaction_picker: Option<usize>,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if inner_width == 0 {
        return lines;
    }

    let msg_style = if msg.is_own {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::White)
    };
    let msg_style = if is_selected {
        msg_style.bg(Color::Rgb(40, 40, 60))
    } else {
        msg_style
    };

    let time = msg.timestamp.format("%H:%M").to_string();
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
    let name_style = msg_style.add_modifier(Modifier::BOLD);

    let prefix = format!("[{}] {}: ", time, msg.from);
    let first_content_len = inner_width.saturating_sub(prefix.len() + 1);
    let content = &msg.content;
    let first_chunk: String = content.chars().take(first_content_len).collect();

    lines.push(Line::from(vec![
        Span::styled(indicator, indicator_style),
        Span::styled(format!("[{}] ", time), time_style),
        Span::styled(format!("{}: ", msg.from), name_style),
        Span::styled(first_chunk, msg_style),
    ]));

    // Continuation lines for wrapped content.
    let remaining: String = content.chars().skip(first_content_len).collect();
    let wrap_width = inner_width.saturating_sub(1);
    for chunk in remaining.chars().collect::<Vec<_>>().chunks(wrap_width) {
        let s: String = chunk.iter().collect();
        lines.push(Line::from(vec![
            Span::styled(" ", indicator_style),
            Span::styled(s, msg_style),
        ]));
    }

    // Aggregated reactions.
    if !msg.reactions.is_empty() {
        let mut counts: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for r in &msg.reactions {
            *counts.entry(r.emoji.as_str()).or_insert(0) += 1;
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
            Style::default().fg(Color::Yellow).bg(Color::Rgb(40, 40, 60))
        } else {
            Style::default().fg(Color::Yellow)
        };
        lines.push(Line::from(vec![
            Span::styled(" ", indicator_style),
            Span::styled(reaction_line, reaction_style),
        ]));
    }

    // Inline emoji picker.
    if is_selected {
        if let Some(picker_idx) = reaction_picker {
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

    lines
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    // A conversation whose history arrived by sync before the Add that
    // puts us in the group has nothing to send into: there is no local
    // MLS group to encrypt to. Say so where the composer would be, rather
    // than accepting keystrokes that cannot go anywhere.
    //
    // Deliberately not promising this resolves imminently. An Add comes
    // from a member, so if the device that served the history was the
    // only one and it goes offline, nothing adds us until it returns.
    let awaiting_membership = app
        .active_conversation
        .and_then(|i| app.conversations.get(i))
        .is_some_and(|c| !c.is_member);

    if awaiting_membership {
        let block = Block::default()
            .title(" Message ")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::DarkGray));
        let notice = Paragraph::new("Waiting to be connected to this conversation.")
            .block(block)
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true });
        frame.render_widget(notice, area);
        return;
    }

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

/// New device: display the pairing code and wait. Renders straight off
/// `App::pairing_ui_state()` — the code text, the waiting/paired/failed
/// status, and the border color are all derived from it, never cached
/// separately.
fn draw_pair_show_code_popup(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 8;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let (border_color, lines): (Color, Vec<Line>) = match app.pairing_ui_state() {
        PairingUiState::ShowingCode { code, .. } => (
            Color::Cyan,
            vec![
                Line::from(Span::styled(code, Style::default().fg(Color::Yellow))),
                Line::from(""),
                Line::from(
                    "On your other device: Settings -> Link a device, then enter this code.",
                ),
            ],
        ),
        PairingUiState::Done { .. } => (
            Color::Green,
            vec![Line::from("Paired! Press any key to continue.")],
        ),
        PairingUiState::Failed { reason } => (
            Color::Red,
            vec![
                Line::from(Span::styled("Pairing failed", Style::default().fg(Color::Red))),
                Line::from(""),
                Line::from(reason),
                Line::from(""),
                Line::from("Press any key to continue."),
            ],
        ),
        // Not reachable while this popup is showing (Focus::PairShowCode
        // only follows a successful `api_pair_new`), kept for exhaustiveness.
        PairingUiState::Idle | PairingUiState::AwaitingPeer | PairingUiState::AwaitingApproval { .. } => {
            (Color::Cyan, vec![Line::from("")])
        }
    };

    let block = Block::default()
        .title(" Link This Device ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

/// Existing device: confirmation screen naming the peer awaiting an
/// approval decision. Renders straight off `App::pairing_ui_state()`.
fn draw_pair_approve_popup(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 8;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" Link a Device? ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let lines: Vec<Line> = match app.pairing_ui_state() {
        PairingUiState::AwaitingApproval { device_name, did } => vec![
            Line::from(vec![
                Span::styled("Device: ", Style::default().fg(Color::Yellow)),
                Span::raw(device_name),
            ]),
            Line::from(vec![
                Span::styled("DID: ", Style::default().fg(Color::Yellow)),
                Span::raw(did),
            ]),
            Line::from(""),
            Line::from("Approve? (y/Enter to approve, n/Esc to reject)"),
        ],
        PairingUiState::Done { .. } => {
            vec![Line::from("Device added! Press any key to continue.")]
        }
        PairingUiState::Failed { reason } => vec![
            Line::from(Span::styled("Pairing failed", Style::default().fg(Color::Red))),
            Line::from(""),
            Line::from(reason),
            Line::from(""),
            Line::from("Press any key to continue."),
        ],
        // Not reachable while this popup is showing (`sync_pairing_focus`
        // only switches here on `AwaitingApproval`), kept for exhaustiveness.
        PairingUiState::Idle | PairingUiState::ShowingCode { .. } | PairingUiState::AwaitingPeer => {
            vec![Line::from("")]
        }
    };

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

/// The linked devices, and what any in-flight sync is doing.
///
/// This is the requester's surface: every other sync screen belongs to the
/// device being *asked*, so before this existed a device that requested
/// history showed nothing at all — not while waiting, not on success, and
/// not on failure.
fn draw_devices_popup(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let popup_width = 64.min(area.width.saturating_sub(4));
    let popup_height = 16.min(area.height.saturating_sub(4));
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .title(" Linked Devices ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let mut lines: Vec<Line> = Vec::new();

    let devices = app.api_ring_devices();
    if devices.is_empty() {
        lines.push(Line::from("No linked devices."));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Press p on the new device to show a pairing code.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for device in &devices {
            let name = device["device_name"].as_str().unwrap_or("Unnamed device");
            let is_self = device["is_self"].as_bool().unwrap_or(false);
            lines.push(Line::from(vec![
                Span::styled(
                    if is_self { "• " } else { "  " },
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(name.to_string()),
                Span::styled(
                    if is_self { "  (this device)" } else { "" },
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
            // What that device last said it holds. This is what turns
            // "ask a device and hope" into a choice the user can make:
            // approve on the one that actually has the history.
            if !is_self {
                lines.push(Line::from(Span::styled(
                    format!("    {}", advertisement_text(&device["advertised"])),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
    }

    lines.push(Line::from(""));
    // The sync line is the whole point of the screen: it is where a
    // request that nobody answered finally becomes visible.
    let (label, style) = match app.sync_request_ui_state() {
        SyncRequestUiState::Idle => (
            "No sync in progress.".to_string(),
            Style::default().fg(Color::DarkGray),
        ),
        SyncRequestUiState::AwaitingPeer => (
            "Waiting for another device to answer…".to_string(),
            Style::default().fg(Color::Yellow),
        ),
        SyncRequestUiState::AwaitingApproval { device_name } => (
            format!("{device_name} is asking you for history."),
            Style::default().fg(Color::Yellow),
        ),
        SyncRequestUiState::Active => (
            "Transferring history…".to_string(),
            Style::default().fg(Color::Green),
        ),
        SyncRequestUiState::Complete { tally, device_name } => (
            sync_complete_text(&tally, device_name.as_deref()),
            Style::default().fg(Color::Green),
        ),
        SyncRequestUiState::Failed { reason } => (
            requester_failure_text(&reason),
            Style::default().fg(Color::Red),
        ),
    };
    lines.push(Line::from(Span::styled(label, style)));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "s: ask for history   o: send history   Esc: close",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

/// What a sibling last advertised holding, for its line on the Devices
/// screen.
///
/// A hint, never a verdict: two devices can hold a hundred *different*
/// messages each and advertise the same count, so this narrows where to
/// ask rather than saying anyone is in sync. The wording states what was
/// said and when, and claims nothing further.
fn advertisement_text(advertised: &serde_json::Value) -> String {
    let Some(messages) = advertised["messages"].as_u64() else {
        return "hasn't said what it has yet".to_string();
    };
    if messages == 0 {
        return "says it has no history".to_string();
    }
    let convs = advertised["conversations"].as_u64().unwrap_or(0);
    format!(
        "says it has {} across {}",
        plural(messages, "message", "messages"),
        plural(convs, "conversation", "conversations"),
    )
}

/// How a finished sync reads, on either side of it.
///
/// An empty tally is not a lesser success, it is a different answer: with
/// one donor per gesture it is what tells the user to go and approve on a
/// *different* device. Naming that device is the other half — "no more
/// than you" is only actionable once you know which sibling said it.
///
/// Core carries the counts, not the words; this is the TUI's wording, and
/// `syncCompleteText` in moat-dart is the Flutter app's.
fn sync_complete_text(tally: &SyncTally, device_name: Option<&str>) -> String {
    let device = device_name.unwrap_or("that device");
    if tally.is_empty() {
        return format!("Nothing new — {device} didn't have more than you.");
    }
    let messages = plural(tally.messages, "message", "messages");
    let convs = plural(tally.conversations, "conversation", "conversations");
    format!("Received {messages} across {convs} from {device}.")
}

/// `"1 message"` / `"412 messages"`.
fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// How a [`SyncFailure`] reads on the device that was *asked* for history.
/// Its counterpart on the asking side is [`requester_failure_text`]; core
/// deliberately carries the fact rather than either wording.
fn responder_failure_text(reason: &SyncFailure) -> String {
    match reason {
        SyncFailure::RequestExpired => {
            "The request expired before you answered it.".to_string()
        }
        SyncFailure::Declined => "You declined this request.".to_string(),
        SyncFailure::ChannelClosed { detail } => {
            format!("The connection closed before the transfer finished ({detail}).")
        }
        // Neither can arise on this side; rendered rather than hidden so a
        // logic slip surfaces instead of showing a blank failure.
        SyncFailure::NoAnswer => "The other device stopped waiting.".to_string(),
        SyncFailure::PublishFailed { detail } => {
            format!("The request could not be sent ({detail}).")
        }
    }
}

/// How a [`SyncFailure`] reads on the device that *asked* for history.
fn requester_failure_text(reason: &SyncFailure) -> String {
    match reason {
        SyncFailure::NoAnswer => {
            "No device answered. Open Moat on the device that has your \
             history and try again."
                .to_string()
        }
        SyncFailure::ChannelClosed { detail } => {
            format!("The connection closed before the transfer finished ({detail}).")
        }
        SyncFailure::PublishFailed { detail } => {
            format!("The request could not be sent ({detail}).")
        }
        // Responder-side outcomes; see the note in `responder_failure_text`.
        SyncFailure::RequestExpired => "This request expired.".to_string(),
        SyncFailure::Declined => "Declined on this device.".to_string(),
    }
}

/// A sibling has said it holds no history, and this device does.
///
/// Raised on app open and the moment such an advertisement arrives,
/// because a newly added device with nothing on it is exactly when the
/// user cares — telling them a week later is worth much less.
///
/// Answering either way settles it: sending offers, declining sets the
/// dismissal flag so this same advertisement will not ask again. Only a
/// sibling that later says something *different* can prompt again.
fn draw_sync_offer_prompt(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 9;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .title(" New Device ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let name = app
        .pending_offer_device_name()
        .unwrap_or_else(|| "A new device".to_string());
    let lines = vec![
        Line::from(vec![
            Span::styled("Device: ", Style::default().fg(Color::Yellow)),
            Span::raw(name),
        ]),
        Line::from(""),
        Line::from("says it has none of your message history."),
        Line::from(""),
        Line::from("Send it your history? (y/Enter to send, n/Esc to dismiss)"),
    ];

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

/// A sibling asked for history. Names the requesting device from its MLS
/// leaf credential — the payload carries only a rendezvous token.
fn draw_sync_approve_popup(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 8;
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" Send History? ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let lines: Vec<Line> = match app.sync_request_ui_state() {
        SyncRequestUiState::AwaitingApproval { device_name } => vec![
            Line::from(vec![
                Span::styled("Device: ", Style::default().fg(Color::Yellow)),
                Span::raw(device_name),
            ]),
            Line::from(""),
            Line::from("is asking for message history."),
            Line::from(""),
            Line::from("Send it? (y/Enter to send, n/Esc to refuse)"),
        ],
        SyncRequestUiState::Failed { reason } => vec![
            Line::from(Span::styled("Sync failed", Style::default().fg(Color::Red))),
            Line::from(""),
            // Worded for *this* screen's role — the device that was asked.
            // `NoAnswer`'s requester-side wording ("no device answered")
            // would be nonsense here: this is the device with the history.
            Line::from(responder_failure_text(&reason)),
            Line::from(""),
            Line::from("Press any key to continue."),
        ],
        // The key handler dismisses this popup as soon as the state leaves
        // `AwaitingApproval`, so these are transitional at most.
        SyncRequestUiState::Idle
        | SyncRequestUiState::AwaitingPeer
        | SyncRequestUiState::Active
        | SyncRequestUiState::Complete { .. } => vec![Line::from("")],
    };

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(messages: u64, conversations: u64) -> SyncTally {
        SyncTally { messages, conversations }
    }

    /// The outcome that sends the user to a different device has to read
    /// differently from every other kind of "complete".
    #[test]
    fn an_empty_tally_says_the_device_had_nothing_new() {
        let text = sync_complete_text(&SyncTally::default(), Some("Pixel 8"));
        assert_eq!(text, "Nothing new — Pixel 8 didn't have more than you.");
    }

    #[test]
    fn a_transfer_reports_what_it_moved_and_where_from() {
        let text = sync_complete_text(&tally(412, 6), Some("Pixel 8"));
        assert_eq!(text, "Received 412 messages across 6 conversations from Pixel 8.");
    }

    #[test]
    fn singular_counts_read_as_singular() {
        let text = sync_complete_text(&tally(1, 1), Some("Laptop"));
        assert_eq!(text, "Received 1 message across 1 conversation from Laptop.");
    }

    /// Every completed transfer carries a credential, so this is the
    /// pairing-time caller rather than a peer that stayed anonymous.
    /// The Devices screen's per-sibling line. Deliberately factual: a
    /// count is a hint about where to ask, not a claim that anyone is in
    /// sync.
    #[test]
    fn an_advertisement_reads_as_what_the_device_said() {
        let advertised = serde_json::json!({ "messages": 412, "conversations": 6 });
        assert_eq!(
            advertisement_text(&advertised),
            "says it has 412 messages across 6 conversations"
        );
    }

    #[test]
    fn a_device_with_no_history_says_so_rather_than_showing_zero() {
        let advertised = serde_json::json!({ "messages": 0, "conversations": 0 });
        assert_eq!(advertisement_text(&advertised), "says it has no history");
    }

    /// A sibling that has not advertised yet is not the same as one that
    /// advertised nothing — the first is silence, the second an answer.
    #[test]
    fn a_silent_device_is_distinguished_from_an_empty_one() {
        assert_eq!(
            advertisement_text(&serde_json::Value::Null),
            "hasn't said what it has yet"
        );
    }

    #[test]
    fn an_unnamed_peer_still_reads_as_a_sentence() {
        let text = sync_complete_text(&SyncTally::default(), None);
        assert_eq!(text, "Nothing new — that device didn't have more than you.");
    }
}
