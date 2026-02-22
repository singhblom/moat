//! Persistent disk cache for decrypted blob content.
//!
//! Blobs are keyed by their `content_hash` (SHA-256 of the plaintext), which
//! is stable across re-encryptions. This means the same text/image won't be
//! downloaded twice even if a sender re-encrypts and re-uploads it.
//!
//! Storage location: `~/.moat/data/blobs/{hex(content_hash)}`.

use std::path::PathBuf;

/// Disk cache for decrypted blob plaintext.
///
/// Thread-safe via the filesystem (reads/writes are atomic at the OS level for
/// single-file operations on most platforms). The cache grows indefinitely —
/// manual cleanup by the user is required if space becomes a concern.
pub struct BlobCache {
    pub dir: PathBuf,
}

impl BlobCache {
    /// Create a new `BlobCache` backed by `dir`.
    ///
    /// Creates the directory (and all parents) if it does not already exist.
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Look up a cached plaintext by its `content_hash`.
    ///
    /// Returns `Some(plaintext)` on a cache hit, `None` on a miss or I/O error.
    pub fn get(&self, content_hash: &[u8]) -> Option<Vec<u8>> {
        let path = self.dir.join(hex::encode(content_hash));
        std::fs::read(path).ok()
    }

    /// Store decrypted `plaintext` keyed by `content_hash`.
    ///
    /// Writes atomically via a temp file to avoid partial reads on concurrent
    /// access or power loss.
    pub fn put(&self, content_hash: &[u8], plaintext: &[u8]) -> std::io::Result<()> {
        let target = self.dir.join(hex::encode(content_hash));
        // Write to a temp path first, then rename.
        let tmp = target.with_extension("tmp");
        std::fs::write(&tmp, plaintext)?;
        std::fs::rename(&tmp, &target)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path().join("blobs")).unwrap();

        let hash = [0x42u8; 32];
        let plaintext = b"hello, cached world!";

        cache.put(&hash, plaintext).unwrap();
        let got = cache.get(&hash).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn miss_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path().join("blobs")).unwrap();

        let unknown_hash = [0xFFu8; 32];
        assert!(cache.get(&unknown_hash).is_none());
    }

    #[test]
    fn creates_directory_on_new() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("a").join("b").join("blobs");
        assert!(!blobs_dir.exists());

        BlobCache::new(blobs_dir.clone()).unwrap();
        assert!(blobs_dir.exists());
    }

    #[test]
    fn put_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path().join("blobs")).unwrap();

        let hash = [0x01u8; 32];
        cache.put(&hash, b"first write").unwrap();
        cache.put(&hash, b"second write").unwrap();

        // Last write wins.
        assert_eq!(cache.get(&hash).unwrap(), b"second write");
    }

    #[test]
    fn different_hashes_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path().join("blobs")).unwrap();

        let hash_a = [0xAAu8; 32];
        let hash_b = [0xBBu8; 32];

        cache.put(&hash_a, b"alpha").unwrap();
        cache.put(&hash_b, b"beta").unwrap();

        assert_eq!(cache.get(&hash_a).unwrap(), b"alpha");
        assert_eq!(cache.get(&hash_b).unwrap(), b"beta");
    }

    #[test]
    fn no_tmp_file_left_behind_after_put() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        let cache = BlobCache::new(blobs_dir.clone()).unwrap();

        let hash = [0x99u8; 32];
        cache.put(&hash, b"data").unwrap();

        // The .tmp file should not exist after a successful put.
        let tmp = blobs_dir
            .join(hex::encode(hash))
            .with_extension("tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path().join("blobs")).unwrap();

        let hash = [0x00u8; 32];
        cache.put(&hash, b"").unwrap();
        assert_eq!(cache.get(&hash).unwrap(), b"");
    }
}
