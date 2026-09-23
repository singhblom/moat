//! Source of sends not yet published, kept so a failed send can be
//! retried — including after a restart.
//!
//! Storage location: `~/.moat/data/outbox/{hex(message_id)}.{image,text}`.

use std::path::PathBuf;

/// What the user sent, before any processing or encryption.
pub enum OutboxEntry {
    Image(Vec<u8>),
    Text(String),
}

pub struct Outbox {
    pub dir: PathBuf,
}

impl Outbox {
    /// Creates the directory (and all parents) if it does not already exist.
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, message_id: &[u8], ext: &str) -> PathBuf {
        self.dir.join(format!("{}.{ext}", hex::encode(message_id)))
    }

    /// Written via a temp file so a crash never leaves a truncated entry.
    pub fn put(&self, message_id: &[u8], entry: &OutboxEntry) -> std::io::Result<()> {
        let (target, bytes) = match entry {
            OutboxEntry::Image(b) => (self.path(message_id, "image"), b.as_slice()),
            OutboxEntry::Text(t) => (self.path(message_id, "text"), t.as_bytes()),
        };
        let tmp = target.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &target)
    }

    pub fn get(&self, message_id: &[u8]) -> Option<OutboxEntry> {
        if let Ok(b) = std::fs::read(self.path(message_id, "image")) {
            return Some(OutboxEntry::Image(b));
        }
        let t = std::fs::read_to_string(self.path(message_id, "text")).ok()?;
        Some(OutboxEntry::Text(t))
    }

    pub fn contains(&self, message_id: &[u8]) -> bool {
        self.path(message_id, "image").exists() || self.path(message_id, "text").exists()
    }

    pub fn remove(&self, message_id: &[u8]) {
        let _ = std::fs::remove_file(self.path(message_id, "image"));
        let _ = std::fs::remove_file(self.path(message_id, "text"));
    }
}
