use sha2::{Digest as _, Sha256};

pub const DIGEST_ANCHOR_STRIDE: u64 = 64;
pub const DIGEST_ANCHOR_CAP: usize = 256;

/// A checkpoint in the running conversation digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestAnchor {
    pub rkey: String,
    pub digest: [u8; 32],
}

/// Running digest state for one conversation.
#[derive(Debug, Clone, Default)]
pub struct DigestState {
    pub tip: [u8; 32],
    pub anchors: Vec<DigestAnchor>,
    pub append_count: u64,
    /// Set by `mark_epoch_boundary`; causes the next append to unconditionally anchor.
    pub epoch_boundary_pending: bool,
}

impl DigestState {
    /// Append a message to the digest chain.
    ///
    /// `digest_n = SHA256(digest_{n-1} || rkey || message_id)`
    ///
    /// Returns `true` if an anchor was saved for this append.
    pub fn append(&mut self, rkey: &str, message_id: &[u8; 16]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.tip);
        hasher.update(rkey.as_bytes());
        hasher.update(message_id);
        self.tip = hasher.finalize().into();
        self.append_count += 1;

        let force = self.epoch_boundary_pending;
        self.epoch_boundary_pending = false;

        let should_anchor = force || self.append_count % DIGEST_ANCHOR_STRIDE == 0;
        if should_anchor {
            self.anchors.push(DigestAnchor {
                rkey: rkey.to_string(),
                digest: self.tip,
            });
            if self.anchors.len() > DIGEST_ANCHOR_CAP {
                self.anchors.remove(0);
            }
        }
        should_anchor
    }
}

/// Result of comparing two anchor lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRange {
    /// `rkey` of the last anchor where both sides agreed (None = no common prefix).
    pub common_prefix_rkey: Option<String>,
    /// Anchors we have beyond the common prefix.
    pub our_tail: Vec<DigestAnchor>,
    /// Anchors they have beyond the common prefix.
    pub their_tail: Vec<DigestAnchor>,
}

/// Find the divergence point between two anchor lists.
///
/// Anchors are compared pairwise from the start; the first pair that differs
/// (or is absent on one side) marks the divergence.
pub fn diff_anchors(ours: &[DigestAnchor], theirs: &[DigestAnchor]) -> DiffRange {
    let common_len = ours
        .iter()
        .zip(theirs.iter())
        .take_while(|(o, t)| o.rkey == t.rkey && o.digest == t.digest)
        .count();

    DiffRange {
        common_prefix_rkey: if common_len > 0 {
            Some(ours[common_len - 1].rkey.clone())
        } else {
            None
        },
        our_tail: ours[common_len..].to_vec(),
        their_tail: theirs[common_len..].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(b: u8) -> [u8; 16] {
        [b; 16]
    }

    #[test]
    fn deterministic_digest() {
        let mut s1 = DigestState::default();
        let mut s2 = DigestState::default();
        for i in 0u8..10 {
            let rkey = format!("rkey{i:03}");
            s1.append(&rkey, &mid(i));
            s2.append(&rkey, &mid(i));
        }
        assert_eq!(s1.tip, s2.tip);
    }

    #[test]
    fn anchor_at_stride() {
        let mut s = DigestState::default();
        for i in 0u64..100 {
            let rkey = format!("r{i:04}");
            s.append(&rkey, &mid(i as u8));
        }
        // Anchors at 64 and 100 is not a stride boundary (100 % 64 = 36).
        assert_eq!(s.anchors.len(), 1);
        assert_eq!(s.anchors[0].rkey, "r0063");
    }

    #[test]
    fn anchors_capped_at_256() {
        let mut s = DigestState::default();
        for i in 0u64..(DIGEST_ANCHOR_STRIDE * 300) {
            let rkey = format!("r{i:06}");
            s.append(&rkey, &mid((i % 256) as u8));
        }
        assert!(s.anchors.len() <= DIGEST_ANCHOR_CAP);
    }

    #[test]
    fn epoch_boundary_forces_anchor() {
        let mut s = DigestState {
            epoch_boundary_pending: true,
            ..DigestState::default()
        };
        // First append (not a stride boundary) should still anchor.
        s.append("rkey001", &mid(1));
        assert_eq!(s.anchors.len(), 1);
        // Flag is cleared.
        assert!(!s.epoch_boundary_pending);
    }

    #[test]
    fn diff_anchors_identical() {
        let a = vec![
            DigestAnchor { rkey: "r001".into(), digest: [1u8; 32] },
            DigestAnchor { rkey: "r002".into(), digest: [2u8; 32] },
        ];
        let d = diff_anchors(&a, &a);
        assert_eq!(d.common_prefix_rkey, Some("r002".into()));
        assert!(d.our_tail.is_empty());
        assert!(d.their_tail.is_empty());
    }

    #[test]
    fn diff_anchors_disjoint() {
        let ours = vec![DigestAnchor { rkey: "r001".into(), digest: [1u8; 32] }];
        let theirs = vec![DigestAnchor { rkey: "r001".into(), digest: [2u8; 32] }];
        let d = diff_anchors(&ours, &theirs);
        assert_eq!(d.common_prefix_rkey, None);
        assert_eq!(d.our_tail, ours);
        assert_eq!(d.their_tail, theirs);
    }

    #[test]
    fn diff_anchors_partial_overlap() {
        let shared = DigestAnchor { rkey: "r001".into(), digest: [1u8; 32] };
        let ours = vec![
            shared.clone(),
            DigestAnchor { rkey: "r002".into(), digest: [10u8; 32] },
        ];
        let theirs = vec![
            shared.clone(),
            DigestAnchor { rkey: "r002".into(), digest: [20u8; 32] },
        ];
        let d = diff_anchors(&ours, &theirs);
        assert_eq!(d.common_prefix_rkey, Some("r001".into()));
        assert_eq!(d.our_tail.len(), 1);
        assert_eq!(d.their_tail.len(), 1);
    }
}
