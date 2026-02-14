//! Moat CLI - Terminal UI for encrypted ATProto messaging

mod app;
mod keystore;
mod message_helpers;
mod ui;

use app::App;
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use keystore::hex;
use message_helpers::{build_text_payload, render_message_preview};
use moat_core::EventKind;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "moat", about = "Terminal UI for encrypted ATProto messaging")]
struct Args {
    /// Custom storage directory (default: ~/.moat)
    #[arg(short = 's', long = "storage-dir", global = true)]
    storage_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch events from a repository (read-only, for testing)
    Fetch {
        /// ATProto handle or DID to fetch events from
        #[arg(long)]
        repository: String,
    },

    /// Print account and session information
    Status,

    /// Publish a test encrypted event to a conversation
    SendTest {
        /// Conversation tag (hex-encoded 16 bytes)
        #[arg(long)]
        tag: String,

        /// Message text to send
        #[arg(long)]
        message: String,
    },

    /// Export log or event data to files
    Export {
        /// Copy debug.log to this path
        #[arg(long)]
        log: Option<PathBuf>,

        /// Export fetched events as JSON to this path
        #[arg(long)]
        events: Option<PathBuf>,

        /// ATProto handle (required with --events)
        #[arg(long)]
        repository: Option<String>,
    },

    /// List devices in a conversation
    Devices {
        /// Conversation ID (hex-encoded group_id, or "list" to show all)
        #[arg(long)]
        conversation: String,
    },

    /// Remove a specific device from a conversation
    RemoveDevice {
        /// Conversation ID (hex-encoded group_id)
        #[arg(long)]
        conversation: String,

        /// Leaf index of the device to remove
        #[arg(long)]
        leaf_index: u32,
    },

    /// Kick a user (remove all their devices) from a conversation
    Kick {
        /// Conversation ID (hex-encoded group_id)
        #[arg(long)]
        conversation: String,

        /// DID of the user to kick
        #[arg(long)]
        did: String,
    },

    /// Leave a conversation (remove your own device)
    Leave {
        /// Conversation ID (hex-encoded group_id)
        #[arg(long)]
        conversation: String,
    },

    /// Delete all local data and PDS records for a fresh start
    DeleteAll {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        None => run_tui(args.storage_dir).await,
        Some(Command::Fetch { repository }) => cmd_fetch(args.storage_dir, &repository).await,
        Some(Command::Status) => cmd_status(args.storage_dir).await,
        Some(Command::SendTest { tag, message }) => {
            cmd_send_test(args.storage_dir, &tag, &message).await
        }
        Some(Command::Export {
            log,
            events,
            repository,
        }) => cmd_export(args.storage_dir, log, events, repository).await,
        Some(Command::Devices { conversation }) => {
            cmd_devices(args.storage_dir, &conversation).await
        }
        Some(Command::RemoveDevice {
            conversation,
            leaf_index,
        }) => cmd_remove_device(args.storage_dir, &conversation, leaf_index).await,
        Some(Command::Kick { conversation, did }) => {
            cmd_kick(args.storage_dir, &conversation, &did).await
        }
        Some(Command::Leave { conversation }) => cmd_leave(args.storage_dir, &conversation).await,
        Some(Command::DeleteAll { force }) => cmd_delete_all(args.storage_dir, force).await,
    }
}

// ── TUI (default) ──────────────────────────────────────────────────

async fn run_tui(storage_dir: Option<PathBuf>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, storage_dir).await;

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

        // Drain all pending background events (non-blocking)
        while let Ok(bg_event) = app.bg_rx.try_recv() {
            app.handle_bg_event(bg_event);
        }

        // Poll for terminal input (16ms = ~60fps)
        if event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
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

        // Spawn background tasks as needed (non-blocking)
        app.tick();

        // Device polling runs async but only every 30s (not latency-critical)
        if app.should_poll_devices() {
            app.do_device_poll().await;
        }
    }
}

// ── Helper: resolve storage dir ────────────────────────────────────

fn resolve_storage_dir(storage_dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match storage_dir {
        Some(dir) => Ok(dir),
        None => dirs::home_dir()
            .map(|h| h.join(".moat"))
            .ok_or_else(|| anyhow::anyhow!("home directory not found")),
    }
}

// ── Helper: login from stored credentials ──────────────────────────

async fn login_from_keystore(
    keys: &keystore::KeyStore,
) -> anyhow::Result<moat_atproto::MoatAtprotoClient> {
    let (handle, password) = keys
        .load_credentials()
        .map_err(|_| anyhow::anyhow!("No stored credentials. Run the TUI first to log in."))?;
    let client = moat_atproto::MoatAtprotoClient::login(&handle, &password).await?;
    Ok(client)
}

// ── fetch ──────────────────────────────────────────────────────────

async fn cmd_fetch(storage_dir: Option<PathBuf>, repository: &str) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;
    let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;
    let client = login_from_keystore(&keys).await?;

    // Load MLS session for decryption attempts
    let mls_path = base_dir.join("mls.bin");
    let mls = if mls_path.exists() {
        let bytes = std::fs::read(&mls_path)?;
        moat_core::MoatSession::from_state(&bytes)?
    } else {
        moat_core::MoatSession::new()
    };

    // Resolve handle to DID
    let did = client.resolve_did(repository).await?;
    eprintln!("Resolved {} -> {}", repository, did);

    // Read last rkey from local state (but do NOT update it)
    let last_rkey = keys.get_last_rkey(&did).ok().flatten();
    if let Some(ref rkey) = last_rkey {
        eprintln!("Fetching events after rkey: {}", rkey);
    } else {
        eprintln!("No last rkey stored, fetching all events");
    }

    let events = client
        .fetch_events_from_did(&did, last_rkey.as_deref())
        .await?;

    // Filter out already-seen rkey (rkey_start is inclusive)
    let events: Vec<_> = events
        .into_iter()
        .filter(|e| {
            if let Some(ref last) = last_rkey {
                e.rkey > *last
            } else {
                true
            }
        })
        .collect();

    eprintln!("Fetched {} new events", events.len());

    // Build tag -> group_id map for decryption using candidate tags
    let mut tag_map = std::collections::HashMap::new();
    let group_ids = keys.list_groups().unwrap_or_default();
    for gid in &group_ids {
        let group_id_bytes = hex::decode(gid).unwrap_or_default();
        if let Ok(tags) = mls.populate_candidate_tags(&group_id_bytes) {
            for tag in tags {
                tag_map.insert(tag, group_id_bytes.clone());
            }
        }
    }

    // Log to debug.log
    let log_path = base_dir.join("debug.log");
    let mut log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    for event in &events {
        let tag_hex = hex::encode(&event.tag);
        let mut line = format!(
            "rkey={} tag={} time={} size={}",
            event.rkey,
            tag_hex,
            event.created_at,
            event.ciphertext.len()
        );

        // Try to decrypt
        if let Some(group_id) = tag_map.get(&event.tag) {
            mls.mark_tag_seen(&event.tag);
            match mls.decrypt_event(group_id, &event.ciphertext) {
                Ok(outcome) => {
                    let decrypted = outcome.into_result();
                    let payload = if decrypted.event.kind == EventKind::Message {
                        decrypted
                            .event
                            .parse_message_payload()
                            .map(|parsed| render_message_preview(&parsed))
                            .unwrap_or_else(|| "(invalid message payload)".to_string())
                    } else {
                        String::from_utf8_lossy(&decrypted.event.payload).to_string()
                    };
                    line.push_str(&format!(
                        " kind={:?} payload={}",
                        decrypted.event.kind, payload
                    ));
                }
                Err(e) => {
                    line.push_str(&format!(" decrypt_error={}", e));
                }
            }
        } else {
            line.push_str(" (unknown tag)");
        }

        println!("{}", line);
        use std::io::Write;
        writeln!(log_file, "[fetch] {}", line)?;
    }

    if events.is_empty() {
        println!("No new events.");
    }

    Ok(())
}

// ── status ─────────────────────────────────────────────────────────

async fn cmd_status(storage_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;
    let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;

    // Account info
    if let Ok((handle, _)) = keys.load_credentials() {
        println!("Handle:          {}", handle);
    } else {
        println!("Handle:          (not logged in)");
    }

    // Try to get DID by logging in
    match login_from_keystore(&keys).await {
        Ok(client) => println!("DID:             {}", client.did()),
        Err(_) => println!("DID:             (login failed)"),
    }

    // Conversations
    let groups = keys.list_groups().unwrap_or_default();
    println!("Conversations:   {}", groups.len());

    // Last rkeys
    let pagination = keys.load_pagination_state().unwrap_or_default();
    if let Some((_did, rkey)) = pagination.last_rkeys.iter().next() {
        println!(
            "Last rkey:       {} (and {} more DIDs)",
            rkey,
            pagination.last_rkeys.len().saturating_sub(1)
        );
    } else {
        println!("Last rkey:       (none)");
    }

    // Storage size
    let size = dir_size(&base_dir).unwrap_or(0);
    println!("Storage:         {} ({} bytes)", human_size(size), size);
    println!("Storage path:    {}", base_dir.display());

    Ok(())
}

fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_file() {
                total += entry.metadata()?.len();
            } else if ft.is_dir() {
                total += dir_size(&entry.path())?;
            }
        }
    } else {
        total = std::fs::metadata(path)?.len();
    }
    Ok(total)
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ── send-test ──────────────────────────────────────────────────────

async fn cmd_send_test(
    storage_dir: Option<PathBuf>,
    tag_hex: &str,
    message: &str,
) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;
    let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;
    let client = login_from_keystore(&keys).await?;

    // Parse tag
    let tag_bytes = hex::decode(tag_hex).map_err(|e| anyhow::anyhow!("Invalid tag hex: {}", e))?;
    if tag_bytes.len() != 16 {
        anyhow::bail!(
            "Tag must be exactly 16 bytes (32 hex chars), got {}",
            tag_bytes.len()
        );
    }
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    // Load MLS state
    let mls_path = base_dir.join("mls.bin");
    let mls = if mls_path.exists() {
        let bytes = std::fs::read(&mls_path)?;
        moat_core::MoatSession::from_state(&bytes)?
    } else {
        anyhow::bail!("No MLS state found. Start a conversation in the TUI first.");
    };

    // Find group_id for this tag using candidate tag scanning
    let group_ids = keys.list_groups().unwrap_or_default();
    let mut found_group: Option<Vec<u8>> = None;

    for gid in &group_ids {
        let group_id_bytes = hex::decode(gid).unwrap_or_default();
        if let Ok(tags) = mls.populate_candidate_tags(&group_id_bytes) {
            if tags.contains(&tag) {
                found_group = Some(group_id_bytes);
                break;
            }
        }
    }

    let group_id = found_group
        .ok_or_else(|| anyhow::anyhow!("No conversation found matching tag {}", tag_hex))?;

    // Load key bundle
    let key_bundle = keys
        .load_identity_key()
        .map_err(|e| anyhow::anyhow!("Failed to load identity key: {}", e))?;

    // Get current epoch
    let epoch = mls.get_group_epoch(&group_id)?.unwrap_or(1);

    // Create and encrypt message
    let payload = build_text_payload(&message);
    let event = moat_core::Event::message_with_payload(group_id.clone(), epoch, &payload);
    let encrypted = mls.encrypt_event(&group_id, &key_bundle, &event)?;

    // Save MLS state (encryption advances epoch)
    let state = mls.export_state()?;
    let temp_path = mls_path.with_extension("tmp");
    std::fs::write(&temp_path, &state)?;
    std::fs::rename(&temp_path, &mls_path)?;

    // Update stored group state
    let conv_id = hex::encode(&group_id);
    keys.store_group_state(&conv_id, &encrypted.new_group_state)
        .map_err(|e| anyhow::anyhow!("Failed to store group state: {}", e))?;

    // Publish
    let uri = client
        .publish_event(&encrypted.tag, &encrypted.ciphertext)
        .await?;

    println!("Published: {}", uri);
    println!("New tag:   {}", hex::encode(&encrypted.tag));

    Ok(())
}

// ── export ─────────────────────────────────────────────────────────

async fn cmd_export(
    storage_dir: Option<PathBuf>,
    log_path: Option<PathBuf>,
    events_path: Option<PathBuf>,
    repository: Option<String>,
) -> anyhow::Result<()> {
    if log_path.is_none() && events_path.is_none() {
        anyhow::bail!("At least one of --log or --events must be provided");
    }

    let base_dir = resolve_storage_dir(storage_dir)?;

    // Export debug log
    if let Some(dest) = &log_path {
        let src = base_dir.join("debug.log");
        if src.exists() {
            std::fs::copy(&src, dest)?;
            println!("Exported debug log to {}", dest.display());
        } else {
            eprintln!("No debug.log found at {}", src.display());
        }
    }

    // Export events as JSON
    if let Some(dest) = &events_path {
        let repo = repository
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--repository is required when using --events"))?;

        let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;
        let client = login_from_keystore(&keys).await?;
        let did = client.resolve_did(repo).await?;
        let events = client.fetch_events_from_did(&did, None).await?;

        // Serialize events to JSON (only the serializable fields)
        let json_events: Vec<serde_json::Value> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "rkey": e.rkey,
                    "tag": hex::encode(&e.tag),
                    "ciphertext_len": e.ciphertext.len(),
                    "created_at": e.created_at.to_rfc3339(),
                    "author_did": e.author_did,
                })
            })
            .collect();

        let json = serde_json::to_string_pretty(&json_events)?;
        std::fs::write(dest, &json)?;
        println!(
            "Exported {} events to {}",
            json_events.len(),
            dest.display()
        );
    }

    Ok(())
}

// ── devices ─────────────────────────────────────────────────────────

async fn cmd_devices(storage_dir: Option<PathBuf>, conversation: &str) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;
    let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;

    // Load MLS state
    let mls_path = base_dir.join("mls.bin");
    let mls = if mls_path.exists() {
        let bytes = std::fs::read(&mls_path)?;
        moat_core::MoatSession::from_state(&bytes)?
    } else {
        anyhow::bail!("No MLS state found. Start a conversation in the TUI first.");
    };

    // List all conversations if requested
    if conversation == "list" {
        let groups = keys.list_groups().unwrap_or_default();
        println!("Conversations:");
        for gid in groups {
            let meta = keys.load_group_metadata(&gid).ok();
            let name = meta
                .map(|m| m.participant_handle)
                .unwrap_or_else(|| "(unknown)".to_string());
            println!("  {} - {}", &gid[..16], name);
        }
        return Ok(());
    }

    // Decode group_id
    let group_id =
        hex::decode(conversation).map_err(|e| anyhow::anyhow!("Invalid conversation ID: {}", e))?;

    // Get members
    let members = mls.get_group_members(&group_id)?;

    println!(
        "Devices in conversation {}:",
        &conversation[..16.min(conversation.len())]
    );
    println!();
    println!("{:<6} {:<20} {}", "Index", "Device Name", "DID");
    println!("{}", "-".repeat(70));

    for (leaf_index, credential) in members {
        let (did, device) = credential
            .map(|c| (c.did().to_string(), c.device_name().to_string()))
            .unwrap_or_else(|| ("(unknown)".to_string(), "(unknown)".to_string()));

        println!("{:<6} {:<20} {}", leaf_index, device, did);
    }

    Ok(())
}

// ── remove-device ───────────────────────────────────────────────────

async fn cmd_remove_device(
    storage_dir: Option<PathBuf>,
    conversation: &str,
    leaf_index: u32,
) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;
    let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;
    let client = login_from_keystore(&keys).await?;

    // Load MLS state
    let mls_path = base_dir.join("mls.bin");
    let mls = if mls_path.exists() {
        let bytes = std::fs::read(&mls_path)?;
        moat_core::MoatSession::from_state(&bytes)?
    } else {
        anyhow::bail!("No MLS state found.");
    };

    // Decode group_id
    let group_id =
        hex::decode(conversation).map_err(|e| anyhow::anyhow!("Invalid conversation ID: {}", e))?;

    // Load key bundle
    let key_bundle = keys
        .load_identity_key()
        .map_err(|e| anyhow::anyhow!("Failed to load identity key: {}", e))?;

    // Remove the member
    let result = mls.remove_member(&group_id, &key_bundle, leaf_index)?;

    // Save MLS state
    let state = mls.export_state()?;
    let temp_path = mls_path.with_extension("tmp");
    std::fs::write(&temp_path, &state)?;
    std::fs::rename(&temp_path, &mls_path)?;

    // Derive tag for the commit
    let tag = mls.derive_next_tag(&group_id, &key_bundle)?;

    // Publish the commit
    let uri = client.publish_event(&tag, &result.commit).await?;
    println!("Removed device at leaf index {}", leaf_index);
    println!("Published commit: {}", uri);

    Ok(())
}

// ── kick ────────────────────────────────────────────────────────────

async fn cmd_kick(
    storage_dir: Option<PathBuf>,
    conversation: &str,
    did_to_kick: &str,
) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;
    let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;
    let client = login_from_keystore(&keys).await?;

    // Load MLS state
    let mls_path = base_dir.join("mls.bin");
    let mls = if mls_path.exists() {
        let bytes = std::fs::read(&mls_path)?;
        moat_core::MoatSession::from_state(&bytes)?
    } else {
        anyhow::bail!("No MLS state found.");
    };

    // Decode group_id
    let group_id =
        hex::decode(conversation).map_err(|e| anyhow::anyhow!("Invalid conversation ID: {}", e))?;

    // Load key bundle
    let key_bundle = keys
        .load_identity_key()
        .map_err(|e| anyhow::anyhow!("Failed to load identity key: {}", e))?;

    // Kick the user (removes all their devices)
    let result = mls.kick_user(&group_id, &key_bundle, did_to_kick)?;

    // Save MLS state
    let state = mls.export_state()?;
    let temp_path = mls_path.with_extension("tmp");
    std::fs::write(&temp_path, &state)?;
    std::fs::rename(&temp_path, &mls_path)?;

    // Derive tag for the commit
    let tag = mls.derive_next_tag(&group_id, &key_bundle)?;

    // Publish the commit
    let uri = client.publish_event(&tag, &result.commit).await?;
    println!("Kicked user {}", did_to_kick);
    println!("Published commit: {}", uri);

    Ok(())
}

// ── leave ───────────────────────────────────────────────────────────

async fn cmd_leave(storage_dir: Option<PathBuf>, conversation: &str) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;
    let keys = keystore::KeyStore::with_path(base_dir.join("keys"))?;
    let client = login_from_keystore(&keys).await?;

    // Load MLS state
    let mls_path = base_dir.join("mls.bin");
    let mls = if mls_path.exists() {
        let bytes = std::fs::read(&mls_path)?;
        moat_core::MoatSession::from_state(&bytes)?
    } else {
        anyhow::bail!("No MLS state found.");
    };

    // Decode group_id
    let group_id =
        hex::decode(conversation).map_err(|e| anyhow::anyhow!("Invalid conversation ID: {}", e))?;

    // Load key bundle
    let key_bundle = keys
        .load_identity_key()
        .map_err(|e| anyhow::anyhow!("Failed to load identity key: {}", e))?;

    // Leave the group
    let result = mls.leave_group(&group_id, &key_bundle)?;

    // Save MLS state
    let state = mls.export_state()?;
    let temp_path = mls_path.with_extension("tmp");
    std::fs::write(&temp_path, &state)?;
    std::fs::rename(&temp_path, &mls_path)?;

    // Derive tag for the commit
    let tag = mls.derive_next_tag(&group_id, &key_bundle)?;

    // Publish the commit
    let uri = client.publish_event(&tag, &result.commit).await?;
    println!(
        "Left conversation {}",
        &conversation[..16.min(conversation.len())]
    );
    println!("Published commit: {}", uri);

    // Clean up local metadata
    let _ = keys.delete_group_metadata(conversation);

    Ok(())
}

// ── delete-all ──────────────────────────────────────────────────────

async fn cmd_delete_all(storage_dir: Option<PathBuf>, force: bool) -> anyhow::Result<()> {
    let base_dir = resolve_storage_dir(storage_dir)?;

    if !force {
        eprintln!("WARNING: This will delete:");
        eprintln!("  - All local conversations and messages");
        eprintln!("  - All MLS state (you will need to be re-invited to groups)");
        eprintln!("  - All key packages and stealth addresses from your PDS");
        eprintln!("  - All events you have published");
        eprintln!();
        eprintln!("Storage directory: {}", base_dir.display());
        eprintln!();
        eprint!("Type 'DELETE' to confirm: ");
        use std::io::Write;
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "DELETE" {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    // Try to delete PDS records if we can log in
    let keys_path = base_dir.join("keys");
    if keys_path.exists() {
        let keys = keystore::KeyStore::with_path(keys_path)?;
        match login_from_keystore(&keys).await {
            Ok(client) => {
                eprintln!("Deleting PDS records...");
                let deleted = client.delete_all_records().await?;
                eprintln!("Deleted {} records from PDS.", deleted);
            }
            Err(e) => {
                eprintln!("Could not log in to delete PDS records: {}", e);
                eprintln!("Continuing with local deletion only.");
            }
        }
    }

    // Delete local storage
    eprintln!("Deleting local storage: {}", base_dir.display());
    if base_dir.exists() {
        std::fs::remove_dir_all(&base_dir)?;
    }

    eprintln!("Done. All data deleted.");
    Ok(())
}
