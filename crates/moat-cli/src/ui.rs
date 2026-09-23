//! Terminal UI rendering with Ratatui

use crate::app::{
    App, ChatMode, DeviceAlert, DisplayMessage, LoginField, Overlay, Screen, View, QUICK_EMOJIS,
};
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

/// One fullscreen surface, an optional modal over it, and a footer
/// carrying the keys for whatever has the keyboard.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);
    let (content, footer_area) = (outer[0], outer[1]);

    match app.view {
        View::Login => draw_login(frame, app, content),
        View::Session(Screen::Conversations) => draw_conversations_screen(frame, app, content),
        View::Session(Screen::Chat) => draw_chat_screen(frame, app, content),
        View::Session(Screen::Status) => draw_status_screen(frame, app, content),
    }

    match app.overlay {
        Overlay::None => {}
        Overlay::NewConversation => draw_handle_input_popup(
            frame,
            "New Conversation",
            "Enter handle:",
            &app.new_conv_handle,
        ),
        Overlay::WatchHandle => draw_handle_input_popup(
            frame,
            "Watch for Invites",
            "Enter handle to watch:",
            &app.watch_handle_input,
        ),
        Overlay::PairEnterCode => draw_handle_input_popup(
            frame,
            "Link a Device",
            "Enter pairing code:",
            &app.pair_enter_code_input,
        ),
        Overlay::PairShowCode => draw_pair_show_code_popup(frame, app),
        Overlay::PairApprove => draw_pair_approve_popup(frame, app),
        Overlay::SyncApprove => draw_sync_approve_popup(frame, app),
    }

    // Draw message info popup if toggled
    if app.show_message_info {
        draw_message_info_popup(frame, app);
    }

    // Draw device alerts if any
    if let Some(alert) = app.device_alerts.first() {
        draw_device_alert(frame, alert);
    }

    // Draw error popup if present
    if let Some(ref error) = app.error_message {
        draw_error_popup(frame, error);
    }

    draw_footer(frame, app, footer_area);
}

fn draw_login(frame: &mut Frame, app: &App, area: Rect) {
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

fn draw_conversations_screen(frame: &mut Frame, app: &App, area: Rect) {
    let style = Style::default().fg(color_pulse(38.0, 227.0, 195.0, 38.0, 195.0, 227.0, 5000));

    let relay_count = app.drawbridge.active_connection_count();
    let title = if relay_count > 0 {
        format!(" Conversations  [relay:{relay_count}] ")
    } else {
        " Conversations ".to_string()
    };

    let block = Block::default()
        .title(title)
        .title_style(style.add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .style(style);

    if app.conversations.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let help = Paragraph::new(
            "No conversations yet.\n\n\
             Press n to start one, or s for this account's other devices.",
        )
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true });
        frame.render_widget(help, inner);
        return;
    }

    let items: Vec<ListItem> = app
        .conversations
        .iter()
        .enumerate()
        .map(|(i, conv)| {
            let selected = Some(i) == app.active_conversation;
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if selected { "> " } else { "  " };
            let unread = if conv.unread > 0 {
                format!(" ({})", conv.unread)
            } else {
                String::new()
            };
            ListItem::new(format!("{}{}{}", prefix, conv.display_name(), unread)).style(style)
        })
        .collect();

    frame.render_widget(List::new(items).block(block), area);
}

/// Both halves are always drawn; `ChatMode` decides which is lit.
fn draw_chat_screen(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);
    draw_messages(frame, app, chunks[0]);
    draw_input(frame, app, chunks[1]);
}

fn draw_messages(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.chat_mode == ChatMode::Browse;
    let color = if is_focused {
        color_pulse(38.0, 227.0, 195.0, 38.0, 195.0, 227.0, 5000)
    } else {
        Color::Gray
    };
    let style = Style::default().fg(color);

    let title = match app.active_conversation.and_then(|i| app.conversations.get(i)) {
        Some(conv) => format!(" {} ", conv.display_name()),
        None => " Messages ".to_string(),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .style(style);

    if app.active_conversation.is_none() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let help = Paragraph::new("No conversation selected.\n\nTab to the conversation list and press Enter on one.")
            .style(Style::default().fg(Color::Gray))
            .wrap(Wrap { trim: true });
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
    if msg.send_failed.is_some() {
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

    if let Some(reason) = &msg.send_failed {
        let failed_style = if is_selected {
            Style::default().fg(Color::Red).bg(Color::Rgb(40, 40, 60))
        } else {
            Style::default().fg(Color::Red)
        };
        lines.push(Line::from(vec![
            Span::styled(" ", indicator_style),
            Span::styled(format!(" ! not sent: {reason}"), failed_style),
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

    let is_focused = app.chat_mode == ChatMode::Compose;
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

/// One hint: the key, and what it does.
///
/// A `mnemonic` hint carries its key inside the label — `quit` with the
/// `q` in key colour, which is `[q]uit` spelled with colour instead of
/// brackets. Two columns cheaper than naming the key separately, which is
/// what lets a screen's whole key set fit one row.
struct Hint {
    key: &'static str,
    label: &'static str,
    mnemonic: bool,
}

/// A hint whose key is spelled out beside its label: `tab screens`.
const fn hint(key: &'static str, label: &'static str) -> Hint {
    Hint { key, label, mnemonic: false }
}

/// A hint whose key is its label's first letter, highlighted in place.
const fn mnem(label: &'static str) -> Hint {
    Hint { key: "", label, mnemonic: true }
}

/// The keys that act on whatever currently has the keyboard.
///
/// Ordered by how likely a key is to be unknown *here*: screen-specific
/// first, then `tab` and `q`, which every screen hints. That order decides
/// which page a key lands on, and which is cut where nothing can page.
fn hints(app: &App) -> Vec<Hint> {
    match app.overlay {
        Overlay::NewConversation | Overlay::WatchHandle | Overlay::PairEnterCode => {
            vec![hint("⏎", "confirm"), hint("esc", "cancel")]
        }
        Overlay::PairShowCode => vec![hint("esc", "cancel pairing")],
        Overlay::PairApprove => vec![hint("y", "approve"), hint("n", "reject")],
        Overlay::SyncApprove => vec![hint("y", "send history"), hint("n", "refuse")],
        Overlay::None => match app.view {
            View::Login => vec![
                hint("tab", "next field"),
                hint("⏎", "sign in"),
                hint("esc", "quit"),
            ],
            View::Session(Screen::Conversations) => vec![
                hint("↑↓", "move"),
                hint("⏎", "open"),
                mnem("new"),
                mnem("watch"),
                mnem("status"),
                hint("tab", "screens"),
                mnem("quit"),
            ],
            View::Session(Screen::Chat) => chat_hints(app),
            View::Session(Screen::Status) => vec![
                mnem("view code"),
                mnem("enter code"),
                mnem("get history"),
                mnem("offer history"),
                hint("esc", "back"),
                hint("tab", "screens"),
                mnem("quit"),
            ],
        },
    }
}

fn chat_hints(app: &App) -> Vec<Hint> {
    // `m` is a letter here, so this set cannot page: it holds only what is
    // usable while typing. The rest is one Esc away in Browse.
    if app.chat_mode == ChatMode::Compose {
        return vec![
            hint("⏎", "send"),
            hint("/image", "<path>"),
            hint("esc", "browse"),
        ];
    }
    if app.reaction_picker.is_some() {
        return vec![hint("←→", "pick"), hint("⏎", "react"), hint("esc", "cancel")];
    }
    if app.show_message_info {
        return vec![hint("i", "close"), hint("esc", "close")];
    }
    let mut hints = vec![hint("↑↓", "scroll")];
    if app.selected_retryable().is_some() {
        hints.push(hint("s", "resend"));
    }
    hints.extend([
        mnem("react"),
        mnem("info"),
        hint("⏎", "compose"),
        hint("esc", "back"),
        hint("tab", "screens"),
        mnem("quit"),
    ]);
    hints
}

/// Columns a hint occupies, including the gap before it.
fn hint_cost(h: &Hint, first: bool) -> usize {
    let sep = if first { 1 } else { 2 };
    sep + h.label.chars().count()
        + if h.mnemonic { 0 } else { h.key.chars().count() + 1 }
}

/// Last on every page, so it sits in the same place each time.
const MORE: Hint = mnem("more");

/// Split the hints into pages that each fit `width`, leaving room for the
/// `more` hint. One page when they all fit, so `more` only appears when
/// something is behind it.
fn paginate(hints: &[Hint], width: u16) -> Vec<std::ops::Range<usize>> {
    let budget = width as usize;
    let total: usize = hints
        .iter()
        .enumerate()
        .map(|(i, h)| hint_cost(h, i == 0))
        .sum();
    if total <= budget {
        return vec![0..hints.len()];
    }

    let reserve = hint_cost(&MORE, false);
    let mut pages = Vec::new();
    let mut start = 0;
    while start < hints.len() {
        let mut used = 0;
        let mut end = start;
        while end < hints.len() {
            let cost = hint_cost(&hints[end], end == start);
            // Always take one, or a terminal narrower than a single hint
            // would page forever.
            if end > start && used + cost + reserve > budget {
                break;
            }
            used += cost;
            end += 1;
        }
        pages.push(start..end);
        start = end;
    }
    pages
}

/// Render one page of hints. Where `m` cannot be spared to page with,
/// the line is cut at a hint boundary and marked with `…` instead.
fn footer_spans(hints: &[Hint], width: u16, page: usize, pageable: bool) -> Vec<Span<'static>> {
    let key_style = Style::default().fg(Color::Yellow);
    let label_style = Style::default().fg(Color::DarkGray);

    let pages = if pageable {
        paginate(hints, width)
    } else {
        vec![0..hints.len()]
    };
    let paged = pages.len() > 1;
    let range = pages[page % pages.len()].clone();

    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    let mut push = |h: &Hint, first: bool| {
        spans.push(Span::raw(if first { " " } else { "  " }.to_string()));
        if h.mnemonic {
            let mut chars = h.label.chars();
            let key: String = chars.by_ref().take(1).collect();
            spans.push(Span::styled(key, key_style));
            spans.push(Span::styled(chars.collect::<String>(), label_style));
        } else {
            spans.push(Span::styled(h.key.to_string(), key_style));
            spans.push(Span::styled(format!(" {}", h.label), label_style));
        }
    };

    for (n, h) in hints[range].iter().enumerate() {
        let first = n == 0;
        let cost = hint_cost(h, first);
        // Stop at a boundary rather than letting the terminal cut a hint
        // in half, and say that we did.
        if !paged && !first && used + cost + 1 > width as usize {
            spans.push(Span::styled("…", label_style));
            return spans;
        }
        used += cost;
        push(h, first);
    }
    if paged {
        push(&MORE, false);
    }
    spans
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let line = match app.status_notice() {
        Some(notice) => Line::from(Span::styled(
            format!(" {notice}"),
            Style::default().fg(Color::Yellow),
        )),
        None => Line::from(footer_spans(
            &hints(app),
            area.width,
            app.hint_page,
            app.hints_are_pageable(),
        )),
    };
    frame.render_widget(Paragraph::new(line), area);
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
        // Not reachable while this popup is showing (Overlay::PairShowCode
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

/// Also the requester's sync surface: every other sync screen belongs to
/// the device being *asked*, so without this a device that requested
/// history showed nothing at all.
fn draw_status_screen(frame: &mut Frame, app: &App, area: Rect) {
    let style = Style::default().fg(color_pulse(38.0, 227.0, 195.0, 38.0, 195.0, 227.0, 5000));
    let block = Block::default()
        .title(" Status ")
        .title_style(style.add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .style(style);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    lines.push(section("Account"));
    lines.push(field(
        "handle",
        app.logged_in_handle.as_deref().unwrap_or("—").to_string(),
    ));
    lines.push(field("did", app.own_did().unwrap_or("—").to_string()));
    if let Some(pds) = app.pds_override() {
        lines.push(field("pds", pds.to_string()));
    }
    lines.push(field(
        "conversations",
        app.conversations.len().to_string(),
    ));

    lines.push(Line::from(""));
    lines.push(section("Relay"));
    lines.push(field(
        "url",
        app.drawbridge_url.clone().unwrap_or_else(|| "none".to_string()),
    ));
    lines.push(field(
        "connections",
        app.drawbridge.active_connection_count().to_string(),
    ));

    lines.push(Line::from(""));
    let devices = app.api_ring_devices();
    let (ring_id, _coord_groups, _members) = app.api_ring_status();
    lines.push(match ring_id {
        Some(id) => section(&format!("Devices ({} · ring {})", devices.len(), short_id(&id))),
        None => section("Devices"),
    });
    if devices.is_empty() {
        // No ring yet, so no leaf credential to read a name and id from.
        lines.push(device_line(
            &app.own_device_name(),
            &app.own_device_id(),
            true,
        ));
        lines.push(Line::from(Span::styled(
            "  No other devices linked. Press v here for a pairing code.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for device in &devices {
            let name = device["device_name"].as_str().unwrap_or("Unnamed device");
            let id = device["device_id"].as_str().unwrap_or("");
            let is_self = device["is_self"].as_bool().unwrap_or(false);
            lines.push(device_line(name, id, is_self));
        }
    }

    lines.push(Line::from(""));
    lines.push(section("History sync"));
    let (label, sync_style) = match app.sync_request_ui_state() {
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
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(label, sync_style),
    ]));

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))
}

fn field(label: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {label:<14}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(value),
    ])
}

fn device_line(name: &str, device_id: &str, is_self: bool) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            if is_self { "  • " } else { "    " },
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(format!("{name:<30}")),
        Span::styled(short_id(device_id), Style::default().fg(Color::Gray)),
        Span::styled(
            if is_self { "  this device" } else { "" },
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

/// Shortened the way git shortens a commit.
///
/// The device id has to be the discriminator: every device of one user
/// shares the DID, and the device name is kind + hostname, so two CLI
/// devices on one machine are identical without it.
fn short_id(hex_id: &str) -> String {
    const SHORT_LEN: usize = 8;
    if hex_id.is_empty() {
        return "?".to_string();
    }
    hex_id.chars().take(SHORT_LEN).collect()
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
    use ratatui::{backend::TestBackend, Terminal};

    fn tally(messages: u64, conversations: u64) -> SyncTally {
        SyncTally { messages, conversations }
    }

    fn test_app(dir: &std::path::Path) -> App {
        App::new(
            Some(dir.to_path_buf()),
            None,
            None,
            ratatui_image::picker::Picker::halfblocks(),
        )
        .expect("app in a temp dir")
    }

    fn render(app: &mut App, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        terminal.draw(|f| draw(f, app)).expect("draw");
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn footer_of(lines: &[String]) -> String {
        lines.last().cloned().unwrap_or_default()
    }

    /// The defect this footer replaces: hints that do not fit are hints
    /// the user never sees. At 80 columns no screen should need a page.
    #[test]
    fn every_screen_shows_all_its_hints_at_eighty_columns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());

        for (name, view, mode) in [
            ("login", View::Login, ChatMode::Compose),
            (
                "conversations",
                View::Session(Screen::Conversations),
                ChatMode::Compose,
            ),
            ("compose", View::Session(Screen::Chat), ChatMode::Compose),
            ("browse", View::Session(Screen::Chat), ChatMode::Browse),
            ("status", View::Session(Screen::Status), ChatMode::Compose),
        ] {
            app.view = view;
            app.chat_mode = mode;
            let footer = footer_of(&render(&mut app, 80, 24));

            assert!(!footer.contains('…'), "{name} footer is cut: {footer:?}");
            assert!(!footer.contains("more"), "{name} footer needs a page: {footer:?}");
        }
    }

    #[test]
    fn a_mnemonic_hint_colours_its_key_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.view = View::Session(Screen::Conversations);

        let mut terminal = Terminal::new(TestBackend::new(80, 6)).expect("test terminal");
        terminal.draw(|f| draw(f, &mut app)).expect("draw");
        let buffer = terminal.backend().buffer().clone();

        // Column, not byte offset — the row holds multi-byte glyphs (↑↓, ⏎).
        let footer_y = 5;
        let cells: Vec<String> = (0..80)
            .map(|x| buffer[(x, footer_y)].symbol().to_string())
            .collect();
        let quit_at = cells
            .windows(4)
            .position(|w| w.concat() == "quit")
            .expect("a quit hint") as u16;

        assert_eq!(buffer[(quit_at, footer_y)].fg, Color::Yellow, "the q");
        assert_eq!(buffer[(quit_at + 1, footer_y)].fg, Color::DarkGray, "the u");
    }

    /// Pairing had no hint anywhere at any width, which made it
    /// undiscoverable — the keys that start it are the ones that matter.
    #[test]
    fn the_status_screen_hints_the_keys_that_link_a_device() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.view = View::Session(Screen::Status);

        let footer = footer_of(&render(&mut app, 80, 24));

        assert!(footer.contains("view code"), "{footer:?}");
        assert!(footer.contains("enter code"), "{footer:?}");
    }

    fn footer_text(hints: &[Hint], width: u16, page: usize, pageable: bool) -> String {
        footer_spans(hints, width, page, pageable)
            .iter()
            .map(|s| s.content.as_ref())
            .collect()
    }

    #[test]
    fn hints_too_wide_for_the_row_page_instead_of_vanishing() {
        let hints = vec![
            hint("enter", "open"),
            mnem("new"),
            mnem("watch"),
            mnem("quit"),
        ];

        let first = footer_text(&hints, 24, 0, true);
        let second = footer_text(&hints, 24, 1, true);

        assert_eq!(first, " enter open  new  more");
        assert_eq!(second, " watch  quit  more");
        for page in [&first, &second] {
            assert!(page.chars().count() <= 24, "{page:?} overflows 24 columns");
            assert!(!page.contains('…'), "{page:?} dropped a hint instead of paging");
        }
    }

    #[test]
    fn paging_past_the_last_page_returns_to_the_first() {
        let hints = vec![
            hint("enter", "open"),
            mnem("new"),
            mnem("watch"),
            mnem("quit"),
        ];
        assert_eq!(
            footer_text(&hints, 24, 0, true),
            footer_text(&hints, 24, 2, true)
        );
    }

    #[test]
    fn unpageable_hints_are_cut_at_a_boundary_and_marked() {
        let hints = vec![
            hint("enter", "open"),
            mnem("new"),
            mnem("quit"),
        ];
        let text = footer_text(&hints, 14, 0, false);

        assert_eq!(text, " enter open…");
        assert!(text.chars().count() <= 14);
        assert!(!text.contains("ne"), "a hint was cut in half: {text:?}");
    }

    #[test]
    fn the_chat_footer_follows_the_mode_the_keyboard_is_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.view = View::Session(Screen::Chat);

        app.chat_mode = ChatMode::Compose;
        let composing = footer_of(&render(&mut app, 80, 24));
        app.chat_mode = ChatMode::Browse;
        let browsing = footer_of(&render(&mut app, 80, 24));

        assert!(composing.contains("send"), "composing: {composing:?}");
        assert!(browsing.contains("react"), "browsing: {browsing:?}");
    }

    #[test]
    fn an_overlay_replaces_the_screens_hints_with_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.view = View::Session(Screen::Conversations);
        app.overlay = Overlay::PairApprove;

        let footer = footer_of(&render(&mut app, 80, 24));
        assert!(footer.contains("approve"), "{footer:?}");
        assert!(footer.contains("reject"), "{footer:?}");
        assert!(!footer.contains("watch"), "{footer:?}");
    }

    #[test]
    fn the_status_screen_names_each_device_by_its_short_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.view = View::Session(Screen::Status);

        let rendered = render(&mut app, 80, 24).join("\n");
        let own_short: String = app.own_device_id().chars().take(8).collect();
        assert!(rendered.contains(&own_short), "{rendered}");
        // The full 32-hex id is noise next to a name.
        assert!(!rendered.contains(&app.own_device_id()), "{rendered}");
    }

    /// Not an assertion: prints each screen for a human to read.
    /// `cargo test print_screens -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_screens() {
        for (name, screen) in [
            ("conversations", Screen::Conversations),
            ("chat", Screen::Chat),
            ("status", Screen::Status),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut app = test_app(dir.path());
            app.view = View::Session(screen);
            println!("── {name} ──────────────────────────────────────────");
            for line in render(&mut app, 80, 20) {
                println!("|{line}");
            }
            for page in 0..3 {
                app.hint_page = page;
                let footer = render(&mut app, 40, 6).pop().unwrap_or_default();
                println!("[40 cols, page {page}]{footer}");
            }
        }
    }

    #[test]
    fn a_short_id_is_eight_hex_characters() {
        assert_eq!(short_id("8aaeb26be5e31013311aeb37646155e6"), "8aaeb26b");
        assert_eq!(short_id(""), "?");
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
    #[test]
    fn an_unnamed_peer_still_reads_as_a_sentence() {
        let text = sync_complete_text(&SyncTally::default(), None);
        assert_eq!(text, "Nothing new — that device didn't have more than you.");
    }
}
