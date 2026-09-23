//! Source bytes of image sends not yet published, kept so a failed send
//! can be retried — including after a restart.
//!
//! Storage location: `~/.moat/data/outbox/{hex(message_id)}`.

use std::path::PathBuf;

pub struct Outbox {
    pub dir: PathBuf,
}

impl Outbox {
    /// Creates the directory (and all parents) if it does not already exist.
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, message_id: &[u8]) -> PathBuf {
        self.dir.join(hex::encode(message_id))
    }

    /// Written via a temp file so a crash never leaves a truncated image.
    pub fn put(&self, message_id: &[u8], bytes: &[u8]) -> std::io::Result<()> {
        let target = self.path(message_id);
        let tmp = target.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &target)
    }

    pub fn get(&self, message_id: &[u8]) -> Option<Vec<u8>> {
        std::fs::read(self.path(message_id)).ok()
    }

    pub fn contains(&self, message_id: &[u8]) -> bool {
        self.path(message_id).exists()
    }

    /// Missing entries are not an error: most sends are text.
    pub fn remove(&self, message_id: &[u8]) {
        let _ = std::fs::remove_file(self.path(message_id));
    }
}

