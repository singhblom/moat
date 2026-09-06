//! Phase A: Size bucketing to hide message length
//!
//! Messages are padded to fixed bucket sizes (512B, 1KB, 4KB control) to prevent
//! traffic analysis from inferring message content based on size.
//!
//! Bucketing rounds *up* to a fixed size, so there is no bucket for a
//! payload larger than the largest one — [`pad_to_bucket`] reports that
//! rather than producing a frame of some other size. Oversized content
//! belongs in an external blob with only the reference in the event, the
//! shape `message.long_text` and `message.image` already use.
//!
//! Not every frame needs a bucket. Padding hides a record's length from
//! whoever can see the PDS; a frame that never reaches the PDS — sync
//! traffic on the pair WebSocket, whose sizes the relay observes
//! regardless — has nothing to hide there, and pays a bucket's rounding
//! for it. [`frame_unpadded`] gives those the same length-prefix framing
//! without the bucket, so [`unpad`] reads both.

use rand::Rng;

use crate::{Error, Result};

/// Bucket sizes for message padding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    /// 512 bytes - for short messages and reactions
    Small = 512,
    /// 1024 bytes - standard envelope for most events
    Standard = 1024,
    /// 4096 bytes - control bucket for overflow commits/welcomes/checkpoints
    Control = 4096,
}

impl Bucket {
    /// Get the appropriate bucket for a given plaintext length
    pub fn for_size(len: usize) -> Self {
        // Reserve 4 bytes for length prefix
        let needed = len + 4;
        if needed <= Bucket::Small as usize {
            Bucket::Small
        } else if needed <= Bucket::Standard as usize {
            Bucket::Standard
        } else {
            Bucket::Control
        }
    }

    /// Get the byte size of this bucket
    pub fn size(self) -> usize {
        self as usize
    }
}

/// The largest plaintext that any bucket can hold, once the 4-byte length
/// prefix is accounted for.
pub const MAX_BUCKETED_PLAINTEXT: usize = Bucket::Control as usize - 4;

/// Pad plaintext to the nearest bucket size.
///
/// Format: [4-byte big-endian length][plaintext][random padding]
///
/// The total output will be exactly one of: 512, 1024, or 4096 bytes.
///
/// Fails above [`MAX_BUCKETED_PLAINTEXT`]: there is no bucket to round up
/// to, and every alternative is worse than saying so. Emitting an
/// unpadded frame would silently leak the exact length this function
/// exists to hide, and the arithmetic that used to run here underflowed
/// instead — a panic in debug builds and an unbounded allocation in
/// release ones.
pub fn pad_to_bucket(plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_BUCKETED_PLAINTEXT {
        return Err(Error::payload_too_large(
            plaintext.len(),
            MAX_BUCKETED_PLAINTEXT,
        ));
    }
    let bucket = Bucket::for_size(plaintext.len());
    let target_size = bucket.size();

    let mut result = Vec::with_capacity(target_size);

    // Write length prefix (4 bytes, big-endian)
    let len = plaintext.len() as u32;
    result.extend_from_slice(&len.to_be_bytes());

    // Write plaintext
    result.extend_from_slice(plaintext);

    // Fill remainder with random bytes
    let padding_len = target_size - result.len();
    if padding_len > 0 {
        let mut rng = rand::thread_rng();
        let padding: Vec<u8> = (0..padding_len).map(|_| rng.gen()).collect();
        result.extend_from_slice(&padding);
    }

    Ok(result)
}

/// Frame plaintext with the length prefix but no bucket padding.
///
/// For frames that never become PDS records — sync traffic on the pair
/// WebSocket. There is no record length for an observer to measure, so a
/// bucket buys nothing, and the rounding would cap the frame at 4 KiB on
/// a channel that carries 1 MiB. The output stays [`unpad`]-compatible,
/// so the receiving side needs no way to tell the two framings apart.
pub fn frame_unpadded(plaintext: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(4 + plaintext.len());
    result.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    result.extend_from_slice(plaintext);
    result
}

/// Remove padding and extract original plaintext.
///
/// Returns the original plaintext without the length prefix and padding.
pub fn unpad(padded: &[u8]) -> Vec<u8> {
    if padded.len() < 4 {
        return Vec::new();
    }

    // Read length prefix
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

    // Validate length
    if len > padded.len() - 4 {
        return Vec::new();
    }

    // Extract plaintext
    padded[4..4 + len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_selection() {
        // Small messages go to 512B bucket
        assert_eq!(Bucket::for_size(0), Bucket::Small);
        assert_eq!(Bucket::for_size(100), Bucket::Small);
        assert_eq!(Bucket::for_size(508), Bucket::Small); // 508 + 4 = 512

        // Standard messages go to 1KB bucket
        assert_eq!(Bucket::for_size(509), Bucket::Standard);
        assert_eq!(Bucket::for_size(800), Bucket::Standard);
        assert_eq!(Bucket::for_size(1020), Bucket::Standard); // 1020 + 4 = 1024

        // Control bucket for overflow
        assert_eq!(Bucket::for_size(1021), Bucket::Control);
        assert_eq!(Bucket::for_size(2000), Bucket::Control);
        assert_eq!(Bucket::for_size(4000), Bucket::Control);
    }

    #[test]
    fn test_pad_unpad_small() {
        let plaintext = b"Hello, world!";
        let padded = pad_to_bucket(plaintext).unwrap();

        assert_eq!(padded.len(), 512);
        assert_eq!(unpad(&padded), plaintext);
    }

    #[test]
    fn test_pad_unpad_medium() {
        let plaintext = vec![0x42; 600];
        let padded = pad_to_bucket(&plaintext).unwrap();

        assert_eq!(padded.len(), 1024);
        assert_eq!(unpad(&padded), plaintext);
    }

    #[test]
    fn test_pad_unpad_large() {
        let plaintext = vec![0x42; 2000];
        let padded = pad_to_bucket(&plaintext).unwrap();

        assert_eq!(padded.len(), 4096);
        assert_eq!(unpad(&padded), plaintext);
    }

    #[test]
    fn test_pad_unpad_empty() {
        let plaintext = b"";
        let padded = pad_to_bucket(plaintext).unwrap();

        assert_eq!(padded.len(), 512);
        assert_eq!(unpad(&padded), plaintext);
    }

    #[test]
    fn largest_bucketed_plaintext_still_pads() {
        let plaintext = vec![0x42; MAX_BUCKETED_PLAINTEXT];
        assert_eq!(pad_to_bucket(&plaintext).unwrap().len(), 4096);
    }

    /// One byte past the largest bucket. This used to underflow
    /// `target_size - result.len()` — a panic in debug builds, and in
    /// release ones a wrap to a near-`usize::MAX` allocation.
    #[test]
    fn one_byte_over_the_largest_bucket_is_an_error() {
        let plaintext = vec![0x42; MAX_BUCKETED_PLAINTEXT + 1];
        let err = pad_to_bucket(&plaintext).unwrap_err();
        assert!(
            matches!(err, crate::Error::PayloadTooLarge(_)),
            "expected PayloadTooLarge, got {err:?}"
        );
    }

    #[test]
    fn unpadded_framing_round_trips_and_keeps_its_size() {
        // Well past every bucket, which is the point: pair-WS frames are
        // not bounded by the bucket ladder.
        let plaintext = vec![0x42; 40_000];
        let framed = frame_unpadded(&plaintext);
        assert_eq!(framed.len(), plaintext.len() + 4);
        assert_eq!(unpad(&framed), plaintext);
    }

    /// `unpad` is the only reader for both framings, so it must not need
    /// to tell them apart.
    #[test]
    fn unpad_reads_both_framings() {
        let plaintext = b"same bytes, two framings";
        assert_eq!(unpad(&pad_to_bucket(plaintext).unwrap()), plaintext);
        assert_eq!(unpad(&frame_unpadded(plaintext)), plaintext);
    }

    #[test]
    fn test_unpad_invalid() {
        // Too short
        assert!(unpad(&[0, 0, 0]).is_empty());

        // Length exceeds data
        let bad = [0, 0, 0, 100, 1, 2, 3];
        assert!(unpad(&bad).is_empty());
    }

    #[test]
    fn test_padding_is_random() {
        let plaintext = b"test";
        let padded1 = pad_to_bucket(plaintext).unwrap();
        let padded2 = pad_to_bucket(plaintext).unwrap();

        // Plaintext portion should be identical
        assert_eq!(&padded1[..8], &padded2[..8]);

        // Padding portion should differ (with very high probability)
        assert_ne!(&padded1[8..], &padded2[8..]);
    }

    #[test]
    fn test_padded_sizes_at_boundaries() {
        // Max payload that fits in Small (508 + 4 = 512)
        assert_eq!(pad_to_bucket(&vec![0x42; 508]).unwrap().len(), 512);
        // One byte over spills to Standard
        assert_eq!(pad_to_bucket(&vec![0x42; 509]).unwrap().len(), 1024);
        // Max payload that fits in Standard (1020 + 4 = 1024)
        assert_eq!(pad_to_bucket(&vec![0x42; 1020]).unwrap().len(), 1024);
        // One byte over spills to Control
        assert_eq!(pad_to_bucket(&vec![0x42; 1021]).unwrap().len(), 4096);
    }
}
