//! In-process two/three-device pairing simulation: drives a live pairing
//! session (Enroll → Admit → Done) between real `MoatSession`s, plus a
//! three-device variant.

use moat_core::{
    decode_pairing_msg, derive_pairing_keys, generate_stealth_keypair, open_frame, MoatCredential,
    MoatSession, OfferedKp, PairingCommand, PairingMsg, PairingPayload, PairingSession,
    SiblingInfo,
};

/// A simulated device: its own `MoatSession`, credential, key bundle, and
/// stealth scan keypair (needed to populate `Admit.roster`).
struct SimDevice {
    mls: MoatSession,
    credential: MoatCredential,
    key_bundle: Vec<u8>,
    stealth_pub: [u8; 32],
}

impl SimDevice {
    fn new(did: &str, name: &str) -> Self {
        let mls = MoatSession::new();
        let credential = MoatCredential::new(did, name, *mls.device_id());
        let (_kp, key_bundle) = mls.generate_key_package(&credential).unwrap();
        let (_stealth_priv, stealth_pub) = generate_stealth_keypair();
        Self {
            mls,
            credential,
            key_bundle,
            stealth_pub,
        }
    }

    /// This device's own entry as it should appear in a roster it hands out
    /// (as the approver) or receives (as a joiner).
    fn sibling_info(&self) -> SiblingInfo {
        SiblingInfo {
            device_id: *self.mls.device_id(),
            device_name: self.credential.device_name().to_string(),
            stealth_pubkey: self.stealth_pub,
        }
    }
}

/// Drive one full Enroll → Admit → Done exchange between a new device and
/// an existing device (which may already hold a ring, for the "pair D3
/// after D2" variant). Asserts along the way that the approval prompt
/// fires, the pending Enroll is held, the ring gets persisted, the history
/// sync handoff is requested on both sides, and both sessions reach `Done`.
/// `known_siblings` is the approving device's host-cached roster of other
/// ring members (empty for a first pairing), threaded into `approve()`.
/// Returns the ring id both sessions converged on, plus the roster the
/// existing device actually sent in `Admit` (decoded straight off the wire,
/// the same way a real peer would).
fn run_pairing_session(
    new_device: &SimDevice,
    existing_device: &SimDevice,
    existing_ring_id: Option<&[u8]>,
    known_siblings: &[SiblingInfo],
) -> (Vec<u8>, Vec<SiblingInfo>) {
    // A fresh secret+token per pairing session, as if freshly scanned off a
    // regenerated QR code.
    let secret = [0x42u8; 32];
    let token = [0x24u8; 16];

    let mut new_session = PairingSession::new_device(&PairingPayload { secret, token });
    let mut existing_session = PairingSession::existing_device(&secret, &token);

    let conv_kps: Vec<OfferedKp> = Vec::new();

    let new_cmds = new_session
        .start_enroll(
            &new_device.mls,
            &new_device.credential,
            &new_device.key_bundle,
            new_device.stealth_pub,
            conv_kps,
        )
        .expect("start_enroll must succeed");

    let enroll_frame = new_cmds
        .iter()
        .find_map(|c| match c {
            PairingCommand::SendFrame { ciphertext } => Some(ciphertext.clone()),
            _ => None,
        })
        .expect("start_enroll must emit a SendFrame command carrying the Enroll frame");

    let existing_cmds = existing_session
        .on_frame_received(&existing_device.mls, &existing_device.credential, &enroll_frame)
        .expect("existing device must accept a well-formed Enroll frame");

    assert!(
        existing_cmds
            .iter()
            .any(|c| matches!(c, PairingCommand::SurfaceApprovalPrompt { .. })),
        "receiving Enroll must surface the approval prompt naming the new device"
    );
    assert!(
        existing_session.pending_enroll().is_some(),
        "the parsed Enroll must be held pending the user's approval decision"
    );

    // User taps Approve.
    let admit_cmds = existing_session
        .approve(
            &existing_device.mls,
            &existing_device.credential,
            &existing_device.key_bundle,
            existing_device.stealth_pub,
            known_siblings,
            existing_ring_id,
        )
        .expect("approve() must succeed for a well-formed pending Enroll");

    assert!(
        admit_cmds
            .iter()
            .any(|c| matches!(c, PairingCommand::SeedKpPool { .. })),
        "approve() must seed the newcomer's kp_pools entry from Enroll.conv_kps"
    );
    assert!(
        admit_cmds.iter().any(|c| matches!(c, PairingCommand::StartSync)),
        "approve() must hand the open channel to history sync via StartSync"
    );

    let admit_frame = admit_cmds
        .iter()
        .find_map(|c| match c {
            PairingCommand::SendFrame { ciphertext } => Some(ciphertext.clone()),
            _ => None,
        })
        .expect("approve() must emit a SendFrame command carrying the Admit frame");

    // Decode the roster straight off the wire (same keys/counter a real
    // peer would use to open the Admit frame) rather than reading it back
    // out of `existing_session`'s internals — this exercises the actual
    // contract the new device relies on.
    let keys = derive_pairing_keys(&secret, &token);
    let admit_plaintext =
        open_frame(&keys.k_old_to_new, 0, &admit_frame).expect("Admit frame must open");
    let roster = match decode_pairing_msg(&admit_plaintext).expect("Admit frame must decode") {
        PairingMsg::Admit(admit) => admit.roster,
        other => panic!("expected an Admit message, got {other:?}"),
    };

    let new_final_cmds = new_session
        .on_frame_received(&new_device.mls, &new_device.credential, &admit_frame)
        .expect("new device must accept a well-formed Admit frame");

    assert!(
        new_final_cmds
            .iter()
            .any(|c| matches!(c, PairingCommand::PersistRing { .. })),
        "receiving Admit must instruct the host to persist the joined ring"
    );
    assert!(
        new_final_cmds.iter().any(|c| matches!(c, PairingCommand::StartSync)),
        "receiving Admit must also hand the channel to history sync via StartSync"
    );
    assert_eq!(
        new_final_cmds.iter().find_map(|c| match c {
            PairingCommand::RosterReceived { roster } => Some(roster.clone()),
            _ => None,
        }),
        Some(roster.clone()),
        "receiving Admit must surface the roster to the host (RosterReceived), \
         matching what was actually sent on the wire — otherwise the new \
         device has no way to address SiblingMsg traffic to its new siblings"
    );

    assert!(new_session.is_done(), "new device session must reach Done");
    assert!(existing_session.is_done(), "existing device session must reach Done");

    let ring_id = existing_session
        .ring_id()
        .expect("approve() must record the ring id it created or joined")
        .to_vec();
    assert_eq!(
        new_session.ring_id(),
        Some(ring_id.as_slice()),
        "both sides of a pairing must agree on which ring they converged on"
    );
    (ring_id, roster)
}

#[test]
fn two_device_pairing_converges() {
    let new_device = SimDevice::new("did:plc:alice", "Alice's Phone");
    let existing_device = SimDevice::new("did:plc:alice", "Alice's Laptop");

    let (ring_id, _roster) = run_pairing_session(&new_device, &existing_device, None, &[]);

    let existing_members = existing_device
        .mls
        .get_group_members(&ring_id)
        .expect("existing device ring lookup");
    let new_members = new_device
        .mls
        .get_group_members(&ring_id)
        .expect("new device ring lookup");
    assert_eq!(existing_members.len(), 2, "existing device must see both ring members");
    assert_eq!(new_members.len(), 2, "new device must see both ring members");
}

#[test]
fn admit_roster_carries_the_approving_devices_own_stealth_key() {
    // Regression test for an API gap caught during review: `approve()`
    // originally had no way to supply the existing device's own stealth
    // key (or any already-known siblings'), so `Admit.roster` could never
    // carry real data — silently breaking the "newcomer can address
    // SiblingMsg traffic to every sibling from its first tick" guarantee
    // qr-pairing.md §3.3 documents, with no test to catch it.
    let new_device = SimDevice::new("did:plc:alice", "Alice's Phone");
    let existing_device = SimDevice::new("did:plc:alice", "Alice's Laptop");

    let (_ring_id, roster) = run_pairing_session(&new_device, &existing_device, None, &[]);

    assert_eq!(
        roster,
        vec![existing_device.sibling_info()],
        "a first pairing's roster must contain exactly the approving \
         device's own {{device_id, device_name, stealth_pubkey}} — the only \
         other sibling that exists at that point"
    );
}

#[test]
fn three_device_pairing_converges_and_third_device_gets_history() {
    // D1 pairs D2 first (no ring exists yet), then D1 pairs D3 into the
    // *same* ring — not a second one, which is why the ring id captured
    // from the D2 pairing is threaded into the D3 pairing below. There is
    // no staggered-online-order dimension to sweep here: the existing
    // device (D1) is by construction always the live, awake side that
    // approves each pairing.
    let d1 = SimDevice::new("did:plc:alice", "D1");
    let d2 = SimDevice::new("did:plc:alice", "D2");
    let d3 = SimDevice::new("did:plc:alice", "D3");

    let (ring_id_after_d2, roster_after_d2) = run_pairing_session(&d2, &d1, None, &[]);
    assert_eq!(
        roster_after_d2,
        vec![d1.sibling_info()],
        "d2's Admit must carry d1's own stealth key — no other sibling exists yet"
    );

    // By the time D1 pairs D3, it has learned D2's stealth address (in
    // reality via the PDS `stealthAddress` record fetch that feeds
    // `DeviceRingState::tick`'s `sibling_stealth` input — simulated here by
    // handing D1 the same `SiblingInfo` D2 exposed above).
    let known_siblings = vec![d2.sibling_info()];
    let (ring_id_after_d3, roster_after_d3) =
        run_pairing_session(&d3, &d1, Some(&ring_id_after_d2), &known_siblings);
    assert_eq!(
        ring_id_after_d3, ring_id_after_d2,
        "pairing D3 must add to D1's existing ring, not create a second one"
    );
    assert_eq!(
        roster_after_d3,
        vec![d1.sibling_info(), d2.sibling_info()],
        "d3's Admit must carry both existing siblings' stealth keys — d1's \
         own, plus d2's from d1's known-siblings cache"
    );
    let ring_id = ring_id_after_d2;

    let d1_members = d1.mls.get_group_members(&ring_id).expect("d1 ring lookup");
    let d3_members = d3.mls.get_group_members(&ring_id).expect("d3 ring lookup");
    assert_eq!(
        d1_members.len(),
        3,
        "d1 (who performed the add) must see all three ring members"
    );
    assert_eq!(
        d3_members.len(),
        3,
        "d3 must see all three ring members from d1's Welcome alone — mirrors \
         third_device_add_by_non_creator_member_succeeds_at_mls_layer in \
         device_ring.rs, except here D1 is both the ring creator and the adder"
    );

    // D2 is deliberately not asserted here. D1 adding D3 produces a commit
    // that only D1 (who made it, merged locally) and D3 (who joins via the
    // Welcome) see synchronously; delivering that commit to the *third*,
    // uninvolved sibling D2 is the ordinary async ring-commit distribution
    // path (qr-pairing.md §6, "Offline sibling catch-up" — a PDS fetch on
    // D2's next poll), which this two-session in-process driver has no PDS
    // to model. It's covered at the Beacon integration level instead.
    //
    // "Third device gets history": `run_pairing_session` already asserts
    // (for both the D2 and D3 pairings) that a `StartSync` handoff is
    // requested. The full byte-level guarantee — D3 actually receiving
    // D1/D2's prior conversation messages once `SyncSession` runs — is
    // proven end-to-end at the Beacon level, over real moat-cli HTTP
    // processes with an actual PDS
    // (`smoke_three_device_pairing_history_sync`), rather than re-driven
    // here: this simulation's job is `PairingSession`'s contract with its
    // host, not a second copy of `SyncSession`'s own delivery tests.
}
