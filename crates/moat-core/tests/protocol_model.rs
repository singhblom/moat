//! Protocol-level model of multi-device key-package consumption.
//!
//! This file is *not* an MLS or networking test. It is an abstract model of
//! the contract between three things:
//!
//! - The PDS, which stores `keyPackage` records and returns them on fetch.
//! - A device's local key store, which holds an init key for every KP it
//!   has published *until* a Welcome consumes that init key.
//! - The Welcomes that flow between devices.
//!
//! The model exists to answer one question: *given a sequence of high-level
//! protocol actions, does every Welcome that is ever created get successfully
//! received by its target?* If the answer is "no" for some interleaving, the
//! protocol design — not the implementation — is responsible.
//!
//! The bug that drove this file: with three Alice devices, the inviting
//! sibling can pick an already-consumed KP for a user-conversation `add_device`
//! and produce a Welcome the new device cannot decrypt. The hypothesis was
//! that simulating timing would help debug it. The reality is that the bug is
//! purely algebraic — a missing single-use invariant on key packages — and
//! catching it deterministically here is much faster than a subprocess
//! harness.
//!
//! The model treats every action as instantaneous and ordered; there is no
//! wall clock. Concurrency is modelled by interleaving actions in different
//! orders, not by parallelism.

use std::collections::{BTreeMap, BTreeSet};

// ── Identities and identifiers ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct DeviceId(u8);

/// PDS record key. Monotonically assigned per PDS write across all writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Rkey(u32);

/// Unique identifier for a Welcome instance. Multiple Welcomes may share an
/// `init_kp` — that is exactly the situation we are trying to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct WelcomeId(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Welcome {
    id: WelcomeId,
    sender: DeviceId,
    target: DeviceId,
    /// The rkey of the KP record whose init key this Welcome was built from.
    /// To process this Welcome the target must still hold that init key in
    /// its local key store.
    init_kp: Rkey,
}

// ── Protocol errors and trace events ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActionError {
    /// `pick`/`consume` asked for a KP not visible on the PDS for the target.
    KpNotOnPds {
        target: DeviceId,
        kp: Rkey,
    },
    /// `receive` tried to find a Welcome matching `(receiver, init_kp)` in
    /// flight. None matched.
    NoMatchingWelcomeInFlight {
        receiver: DeviceId,
        init_kp: Rkey,
    },
    /// `receive` found a Welcome but the target's keystore no longer holds
    /// the matching init key. THIS is the bug.
    InitKeyAlreadyConsumed {
        receiver: DeviceId,
        init_kp: Rkey,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceEvent {
    Published {
        owner: DeviceId,
        kp: Rkey,
    },
    Consumed {
        sender: DeviceId,
        target: DeviceId,
        kp: Rkey,
        welcome: WelcomeId,
    },
    Received {
        receiver: DeviceId,
        welcome: WelcomeId,
        init_kp: Rkey,
    },
    Deleted {
        owner: DeviceId,
        kp: Rkey,
    },
    Failed(ActionError),
}

// ── The model ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct ProtocolModel {
    next_rkey: u32,
    next_welcome_id: u32,
    /// KPs that are currently visible on the PDS, grouped by owner.
    pds: BTreeMap<DeviceId, BTreeSet<Rkey>>,
    /// Init keys currently in each device's local keystore. Adding a KP to
    /// the PDS adds its rkey here; receiving a Welcome that targets it
    /// removes the entry.
    keystore: BTreeMap<DeviceId, BTreeSet<Rkey>>,
    /// Welcomes that have been created but not yet processed.
    in_flight: Vec<Welcome>,
    /// Every state-changing action, in order. Useful for printing
    /// counter-examples.
    trace: Vec<TraceEvent>,
}

impl ProtocolModel {
    fn new() -> Self {
        Self {
            next_rkey: 1,
            next_welcome_id: 1,
            pds: BTreeMap::new(),
            keystore: BTreeMap::new(),
            in_flight: Vec::new(),
            trace: Vec::new(),
        }
    }

    /// `owner` publishes a fresh key package. The matching init key lands in
    /// `owner`'s keystore atomically.
    fn publish(&mut self, owner: DeviceId) -> Rkey {
        let kp = Rkey(self.next_rkey);
        self.next_rkey += 1;
        self.pds.entry(owner).or_default().insert(kp);
        self.keystore.entry(owner).or_default().insert(kp);
        self.trace.push(TraceEvent::Published { owner, kp });
        kp
    }

    /// `sender` picks the newest KP visible on the PDS for `target` (mirrors
    /// the production `key_packages.iter().rev().find(...)` rule). Returns
    /// `None` if no KP is on the PDS.
    fn pick_newest_kp(&self, target: DeviceId) -> Option<Rkey> {
        self.pds.get(&target)?.iter().next_back().copied()
    }

    /// `sender` builds a Welcome for `target` targeting the named KP. Once a
    /// consumer has fetched a KP's bytes, *it can build a Welcome from them*
    /// regardless of whether the record is still on the PDS — that's the
    /// crux of why "delete after use" is insufficient as a sole fix. We only
    /// require that the KP was published at some point (i.e. it has a known
    /// rkey on the model).
    fn consume(
        &mut self,
        sender: DeviceId,
        target: DeviceId,
        kp: Rkey,
    ) -> Result<WelcomeId, ActionError> {
        let ever_published = self
            .trace
            .iter()
            .any(|e| matches!(e, TraceEvent::Published { kp: k, .. } if *k == kp));
        if !ever_published {
            let e = ActionError::KpNotOnPds { target, kp };
            self.trace.push(TraceEvent::Failed(e.clone()));
            return Err(e);
        }
        let id = WelcomeId(self.next_welcome_id);
        self.next_welcome_id += 1;
        self.in_flight.push(Welcome {
            id,
            sender,
            target,
            init_kp: kp,
        });
        self.trace.push(TraceEvent::Consumed {
            sender,
            target,
            kp,
            welcome: id,
        });
        Ok(id)
    }

    /// `receiver` processes the next pending Welcome that targets its
    /// `init_kp`. Fails with `InitKeyAlreadyConsumed` if such a Welcome
    /// exists but the receiver's keystore no longer has the matching init
    /// key — that is the protocol violation we are watching for.
    fn receive(&mut self, receiver: DeviceId, init_kp: Rkey) -> Result<(), ActionError> {
        let idx = self
            .in_flight
            .iter()
            .position(|w| w.target == receiver && w.init_kp == init_kp);
        let Some(idx) = idx else {
            let e = ActionError::NoMatchingWelcomeInFlight { receiver, init_kp };
            self.trace.push(TraceEvent::Failed(e.clone()));
            return Err(e);
        };
        let w = self.in_flight.remove(idx);
        let has_key = self
            .keystore
            .get(&receiver)
            .is_some_and(|s| s.contains(&init_kp));
        if !has_key {
            let e = ActionError::InitKeyAlreadyConsumed { receiver, init_kp };
            self.trace.push(TraceEvent::Failed(e.clone()));
            return Err(e);
        }
        self.keystore.get_mut(&receiver).unwrap().remove(&init_kp);
        self.trace.push(TraceEvent::Received {
            receiver,
            welcome: w.id,
            init_kp,
        });
        Ok(())
    }

    /// Remove a KP record from `owner`'s PDS view. Does not touch the
    /// keystore — deletion from the PDS is a separate concept from
    /// consumption.
    fn delete_kp(&mut self, owner: DeviceId, kp: Rkey) {
        if let Some(set) = self.pds.get_mut(&owner) {
            set.remove(&kp);
        }
        self.trace.push(TraceEvent::Deleted { owner, kp });
    }

    /// True iff every Welcome ever created in this trace either was received
    /// successfully or is still in flight. False as soon as a single Welcome
    /// failed with `InitKeyAlreadyConsumed`.
    fn invariant_every_welcome_receivable(&self) -> bool {
        !self.trace.iter().any(|e| {
            matches!(
                e,
                TraceEvent::Failed(ActionError::InitKeyAlreadyConsumed { .. })
            )
        })
    }

    /// True iff every KP currently visible on the PDS still has its init key
    /// in the owner's keystore. A consumer that respects this invariant
    /// cannot pick an orphan.
    fn invariant_no_orphan_kp_on_pds(&self) -> bool {
        self.pds.iter().all(|(owner, kps)| {
            let ks = self.keystore.get(owner);
            kps.iter().all(|kp| ks.is_some_and(|s| s.contains(kp)))
        })
    }

    fn dump_trace(&self) -> String {
        let mut out = String::new();
        for ev in &self.trace {
            out.push_str(&format!("  {ev:?}\n"));
        }
        out
    }
}

// ── SlotModel: the per-consumer key-package slot scheme ──────────────────────
//
// The user's proposed protocol: instead of a shared "pool" of KPs that any
// consumer fetches from, the publisher writes one KP record per intended
// consumer. The lexicon would gain two fields, e.g.:
//
//   record social.moat.keyPackage {
//       v: u32,
//       ciphersuite: String,
//       key_package: Vec<u8>,
//       intended_for: DeviceId,      // ← NEW
//       expires_at: DateTime,
//       created_at: DateTime,
//   }
//
// …and a deterministic rkey per (owner, intended_for) pair so the slot is a
// single record that gets *overwritten* on replenish (no orphans). This
// model represents the slot as `Option<Rkey>`: `Some` = current fresh KP,
// `None` = the slot has been consumed and the owner has not yet replenished.
//
// The slot model is exercised in three flavours below:
// - `SlotModel::receive` clears the slot synchronously with consumption.
//   This is the *ideal* design and assumes the consumer's KP-fetch sees the
//   slot-empty signal in time.
// - `DelayedSlotModel` separates `process_welcome` (which only updates the
//   keystore) from `observe_consumption` (which clears the slot). Used to
//   probe whether a same-consumer re-fetch within the lag window can
//   resurrect the orphan-within-slot problem.

#[derive(Debug, Default)]
struct SlotModel {
    next_rkey: u32,
    next_welcome_id: u32,
    /// PDS: one fresh KP per (owner, intended_for) slot. `None` means the
    /// slot is empty and the consumer has to wait for the owner to
    /// replenish it.
    slots: BTreeMap<(DeviceId, DeviceId), Option<Rkey>>,
    keystore: BTreeMap<DeviceId, BTreeSet<Rkey>>,
    in_flight: Vec<Welcome>,
    failed_receives: u32,
    /// Welcomes whose underlying MLS commit was rejected (lost the epoch
    /// race). Tracks them separately because they should *not* be processed
    /// by the receiver — in production they are filtered out by the MLS
    /// layer when the rejected commit becomes visible. The model only marks
    /// them; the test driver decides whether to call `receive` on them.
    rejected_welcomes: BTreeSet<WelcomeId>,
}

impl SlotModel {
    fn publish_for(&mut self, owner: DeviceId, intended_for: DeviceId) -> Rkey {
        self.next_rkey += 1;
        let kp = Rkey(self.next_rkey);
        self.slots.insert((owner, intended_for), Some(kp));
        self.keystore.entry(owner).or_default().insert(kp);
        kp
    }
    fn fetch_for_me(&self, target: DeviceId, me: DeviceId) -> Option<Rkey> {
        *self.slots.get(&(target, me))?
    }
    fn consume(&mut self, sender: DeviceId, target: DeviceId, kp: Rkey) -> WelcomeId {
        self.next_welcome_id += 1;
        let id = WelcomeId(self.next_welcome_id);
        self.in_flight.push(Welcome { id, sender, target, init_kp: kp });
        id
    }
    /// Receive consumes the init key and *clears the slot* synchronously.
    fn receive(&mut self, receiver: DeviceId, kp: Rkey) -> Result<(), ()> {
        let idx = self.in_flight.iter().position(|w| w.target == receiver && w.init_kp == kp);
        let Some(idx) = idx else {
            self.failed_receives += 1;
            return Err(());
        };
        let w = self.in_flight.remove(idx);
        let ks = self.keystore.entry(receiver).or_default();
        if !ks.remove(&kp) {
            self.failed_receives += 1;
            return Err(());
        }
        self.slots.insert((receiver, w.sender), None);
        Ok(())
    }
    /// The MLS layer rejected `welcome`'s underlying commit. Mark it.
    fn reject(&mut self, welcome: WelcomeId) {
        self.rejected_welcomes.insert(welcome);
    }
}

// ── Devices used across scenarios ─────────────────────────────────────────────

const D1: DeviceId = DeviceId(1);
const D2: DeviceId = DeviceId(2);
const D3: DeviceId = DeviceId(3);
const D4: DeviceId = DeviceId(4);

// ── Scenarios that REPRODUCE the protocol violation ──────────────────────────

/// Happy path. Two devices, two operations, no race.
#[test]
fn two_device_ring_join_succeeds() {
    let mut m = ProtocolModel::new();
    let kp_a = m.publish(D2);
    let w = m.consume(D1, D2, kp_a).expect("ring add ok");
    m.receive(D2, kp_a).expect("D2 processes ring welcome");
    assert!(m.invariant_every_welcome_receivable());
    assert!(m.in_flight.is_empty());
    let _ = w;
}

/// Reproduces the failing 3-device case at its essence: D1 consumes the only
/// KP D3 has ever published, *and so does D2*, before D3 has any chance to
/// replenish.
///
/// In the real system this happens when D1 fans out to user conversations on
/// the same tick that D2 (already in those conversations) also fans out.
/// Both fetch newest, both pick the same KP, both produce Welcomes targeting
/// the same init key. Only one of those Welcomes can ever be received.
#[test]
fn three_device_two_consumers_same_kp_creates_undeliverable_welcome() {
    let mut m = ProtocolModel::new();
    let kp_a = m.publish(D3);

    // Both D1 and D2 pick the newest KP — and get the same one.
    assert_eq!(m.pick_newest_kp(D3), Some(kp_a));
    assert_eq!(m.pick_newest_kp(D3), Some(kp_a));

    // Both build Welcomes targeting init_a.
    m.consume(D1, D3, kp_a).unwrap();
    m.consume(D2, D3, kp_a).unwrap();

    // D3 processes the first one successfully…
    m.receive(D3, kp_a).expect("first welcome processed");
    // …and the second fails: init_a is gone.
    let err = m.receive(D3, kp_a).expect_err("second welcome must fail");
    assert!(matches!(err, ActionError::InitKeyAlreadyConsumed { .. }));

    // This is the property we want to FUTURE-violate-by-construction.
    assert!(
        !m.invariant_every_welcome_receivable(),
        "without protocol-level protection this trace produces a dead welcome:\n{}",
        m.dump_trace()
    );
}

/// Reproduces the timing flavour of the bug: a single consumer picks a stale
/// (already-consumed) KP because the owner hasn't yet deleted the orphan
/// record from the PDS.
///
/// This is the exact failure I observed in the beacon logs: D1 ring-adds D3
/// using KP_X, D3 processes the ring Welcome (consuming init_X), then D1's
/// poll_for_new_devices fetches D3's newest KP. If KP_X is still on the PDS
/// — and it is, because nobody has deleted it yet — D1 picks it again.
#[test]
fn single_consumer_picks_orphan_kp_after_consumption() {
    let mut m = ProtocolModel::new();
    let kp_a = m.publish(D3);

    // First add: D1 uses KP_A. D3 receives. init_A is now consumed.
    m.consume(D1, D3, kp_a).unwrap();
    m.receive(D3, kp_a).unwrap();

    // KP_A is still on the PDS — nobody deleted it.
    assert_eq!(m.pick_newest_kp(D3), Some(kp_a));
    assert!(
        !m.invariant_no_orphan_kp_on_pds(),
        "orphan KP_A still on PDS:\n{}",
        m.dump_trace()
    );

    // D1's next add: picks the orphan and builds an undeliverable Welcome.
    m.consume(D1, D3, kp_a).unwrap();
    let err = m.receive(D3, kp_a).expect_err("orphan welcome must fail");
    assert!(matches!(err, ActionError::InitKeyAlreadyConsumed { .. }));
}

// ── Scenarios that EVALUATE candidate fixes ──────────────────────────────────

/// Candidate fix #1: the **consumer** deletes the KP from the PDS immediately
/// after using it (the half-fix I implemented in moat-cli's
/// `poll_for_new_devices`).
///
/// Outcome: prevents the *single-consumer orphan* case, but does NOT prevent
/// the *two-consumer same-KP* case. The second consumer can have fetched
/// before the first consumer's delete lands.
#[test]
fn fix_consumer_deletes_after_use_does_not_prevent_double_consumer_race() {
    let mut m = ProtocolModel::new();
    let kp_a = m.publish(D3);

    // Both consumers fetch — both see KP_A.
    let d1_choice = m.pick_newest_kp(D3).unwrap();
    let d2_choice = m.pick_newest_kp(D3).unwrap();
    assert_eq!(d1_choice, kp_a);
    assert_eq!(d2_choice, kp_a);

    // D1 consumes, deletes. (Delete happens BEFORE D2 acts but AFTER D2
    // fetched, which is exactly the race we observed in the beacon logs.)
    m.consume(D1, D3, kp_a).unwrap();
    m.delete_kp(D3, kp_a);

    // D2 still has KP_A in hand and goes ahead.
    m.consume(D2, D3, kp_a).unwrap();

    // D3 processes the first welcome…
    m.receive(D3, kp_a).unwrap();
    // …and the second still fails.
    let err = m.receive(D3, kp_a).unwrap_err();
    assert!(matches!(err, ActionError::InitKeyAlreadyConsumed { .. }));
    assert!(!m.invariant_every_welcome_receivable());
}

/// Candidate fix #2: the **owner** deletes the KP from the PDS as part of
/// `receive` (atomic with consuming the init key).
///
/// Outcome: still races. A consumer can have already fetched the KP and
/// built the Welcome before the owner ever sees the first Welcome.
#[test]
fn fix_owner_deletes_on_receive_does_not_prevent_double_consumer_race() {
    let mut m = ProtocolModel::new();
    let kp_a = m.publish(D3);

    // Both consumers fetch and build.
    m.consume(D1, D3, kp_a).unwrap();
    m.consume(D2, D3, kp_a).unwrap();

    // D3 processes the first Welcome and deletes the orphan.
    m.receive(D3, kp_a).unwrap();
    m.delete_kp(D3, kp_a);

    // D2's Welcome was built before the delete and is undeliverable anyway.
    let err = m.receive(D3, kp_a).unwrap_err();
    assert!(matches!(err, ActionError::InitKeyAlreadyConsumed { .. }));
    assert!(!m.invariant_every_welcome_receivable());
}

/// Candidate fix #3: the PDS supports an **atomic fetch-and-claim**. A
/// consumer fetching a KP atomically removes the record from the PDS. This
/// is what an MLS-aware key-package directory ought to support; ATProto does
/// not have this primitive natively.
///
/// Outcome: bug eliminated. Every consumer that successfully fetches owns the
/// KP exclusively. The owner's keystore still ends up with the right
/// number of consumed init keys.
#[test]
fn fix_atomic_claim_eliminates_the_race() {
    let mut m = ProtocolModel::new();

    fn fetch_and_claim(m: &mut ProtocolModel, target: DeviceId) -> Option<Rkey> {
        let kp = m.pick_newest_kp(target)?;
        // Atomic claim semantics: the act of fetching removes the record.
        m.delete_kp(target, kp);
        Some(kp)
    }

    // D3 pre-publishes a pool so multiple claims have something to grab.
    let kp_a = m.publish(D3);
    let kp_b = m.publish(D3);

    // D1 and D2 each fetch — they get *different* KPs.
    let d1_kp = fetch_and_claim(&mut m, D3).unwrap();
    let d2_kp = fetch_and_claim(&mut m, D3).unwrap();
    assert_ne!(d1_kp, d2_kp);
    let _ = (kp_a, kp_b);

    m.consume(D1, D3, d1_kp).unwrap();
    m.consume(D2, D3, d2_kp).unwrap();

    // D3 processes both Welcomes. Both succeed.
    m.receive(D3, d1_kp).unwrap();
    m.receive(D3, d2_kp).unwrap();
    assert!(m.invariant_every_welcome_receivable());
}

/// Candidate fix #5: **per-consumer key-package slots**.
///
/// The publisher writes a KP record *for each known sibling* — e.g.
/// `(D3, intended_for: D1, kp_bytes)` and `(D3, intended_for: D2, …)`.
/// Each consumer fetches only its dedicated slot. There is no shared pool
/// to race on, so two consumers can never pick the same KP by definition.
///
/// Replenish is also per-slot: when D3 sees a Welcome that targeted the
/// init key in the D1 slot, D3 publishes a fresh KP into that slot only.
///
/// This is the cleanest fix that works with the primitives ATProto already
/// has — the (owner, intended_for) tuple is just two extra fields on the
/// keyPackage record and a different lexicon query.
///
/// Trade-offs the model is honest about:
/// - linear-in-siblings storage (N KPs per device on the PDS),
/// - new sibling discovery still needs a first-contact path (the publisher
///   doesn't yet have a slot for an unknown peer); the existing stealth +
///   coord-group bootstrap can carry that without a generic KP slot
///   (see the trace at the end of the test).
#[test]
fn fix_per_consumer_kp_slot_eliminates_the_race() {
    let mut m = SlotModel::default();

    // D3 logs in. Once it has discovered D1 and D2 as siblings (via the
    // stealth-encrypted bootstrap path, which doesn't itself use a generic
    // KP slot — coord-group invites flow over D3's freshly-published
    // stealth address), D3 publishes one KP into each per-sibling slot.
    let kp_d3_for_d1 = m.publish_for(D3, D1);
    let kp_d3_for_d2 = m.publish_for(D3, D2);
    assert_ne!(kp_d3_for_d1, kp_d3_for_d2);

    // D1 and D2 each fetch their own slot. Even in the same instant.
    let d1_choice = m.fetch_for_me(D3, D1).unwrap();
    let d2_choice = m.fetch_for_me(D3, D2).unwrap();
    assert_eq!(d1_choice, kp_d3_for_d1);
    assert_eq!(d2_choice, kp_d3_for_d2);
    assert_ne!(d1_choice, d2_choice, "different consumers, different KPs");

    // D1 adds D3 to the ring. D2 (independently, possibly later in the same
    // tick) adds D3 to a user conversation.
    m.consume(D1, D3, d1_choice);
    m.consume(D2, D3, d2_choice);

    // D3 processes both Welcomes. Both succeed. Both slots are now empty.
    m.receive(D3, d1_choice).unwrap();
    m.receive(D3, d2_choice).unwrap();
    assert_eq!(m.failed_receives, 0);
    assert!(m.fetch_for_me(D3, D1).is_none());
    assert!(m.fetch_for_me(D3, D2).is_none());

    // D3 replenishes the D1 slot (because D3 observed the D1 Welcome
    // consume it). D1 can now do further adds.
    let kp_d3_for_d1_v2 = m.publish_for(D3, D1);
    assert_ne!(kp_d3_for_d1_v2, kp_d3_for_d1);
    m.consume(D1, D3, kp_d3_for_d1_v2);
    m.receive(D3, kp_d3_for_d1_v2).unwrap();
    assert_eq!(m.failed_receives, 0);

    // If D1 tries to act when the slot is empty, fetch returns None and D1
    // has to wait. No re-use of stale KPs.
    assert!(m.fetch_for_me(D3, D1).is_none());
}

/// Candidate fix #4: a **single designated consumer** (e.g. leaf-0 of the
/// device ring) is the only device allowed to call `consume` for a given
/// target. All other ring members defer the user-conv add to leaf-0.
///
/// Outcome: bug eliminated if leaf-0 also avoids reusing an orphan (i.e. it
/// observes that the KP it just consumed has not yet been replenished and
/// waits). Modelled here by leaf-0 fetching only KPs that are also still in
/// the owner's keystore (the "freshness" check).
#[test]
fn fix_single_consumer_with_freshness_check_eliminates_the_race() {
    let mut m = ProtocolModel::new();

    fn fetch_fresh(m: &ProtocolModel, target: DeviceId) -> Option<Rkey> {
        let pds = m.pds.get(&target)?;
        let ks = m.keystore.get(&target)?;
        pds.iter().rev().find(|kp| ks.contains(kp)).copied()
    }

    let kp_a = m.publish(D3);

    // Leaf-0 (D1) does the ring add.
    let kp = fetch_fresh(&m, D3).unwrap();
    assert_eq!(kp, kp_a);
    m.consume(D1, D3, kp).unwrap();
    m.receive(D3, kp).unwrap();

    // Without a fresh KP available, D1 must wait. The freshness check
    // returns None until D3 has replenished.
    assert_eq!(fetch_fresh(&m, D3), None);

    // D3 replenishes.
    let kp_b = m.publish(D3);
    assert_eq!(fetch_fresh(&m, D3), Some(kp_b));

    m.consume(D1, D3, kp_b).unwrap();
    m.receive(D3, kp_b).unwrap();
    assert!(m.invariant_every_welcome_receivable());
}

// ── Stress tests for the SlotModel ───────────────────────────────────────────
//
// These scenarios probe assumptions the simple "every Welcome receivable"
// invariant glossed over. If any of them break the slot scheme, we have to
// extend the proposed protocol with extra primitives before treating it as
// done.

/// **MLS commit race under the slot scheme.**
///
/// Both D1 and D2 try to add D3 to the same user conversation at the same
/// MLS epoch. The PDS serialises their commits — D1's lands first, D2's
/// loses. D1 uses slot (D3 → D1); D2 uses slot (D3 → D2). Both Welcomes are
/// on the wire.
///
/// What happens?
/// - D3 processes D1's Welcome and joins the group at epoch N+1.
/// - D2's Welcome was built against epoch N; the MLS layer must reject it
///   on D3's side. The model represents this via `reject(welcome_id)` —
///   the test driver doesn't call `receive` on rejected Welcomes.
///
/// Invariant: `failed_receives == 0` (rejected Welcomes are NEVER received,
/// so they never count as a failure). D2's slot's init key is NOT consumed
/// because D3 never called process_welcome on it.
///
/// Consequence the model surfaces: D2 must be able to RETRY its add. The
/// retry needs a fresh KP from slot (D3 → D2). But the slot still holds the
/// unused KP from the failed attempt, so D2 can re-fetch and re-use it.
/// That works — the same KP is reused across a retry, not across two
/// distinct adds.
#[test]
fn slot_mls_commit_conflict_does_not_burn_loser_slot() {
    let mut m = SlotModel::default();
    let kp_d3_for_d1 = m.publish_for(D3, D1);
    let kp_d3_for_d2 = m.publish_for(D3, D2);

    // Both consumers fetch their dedicated slot — different KPs.
    let d1_kp = m.fetch_for_me(D3, D1).unwrap();
    let d2_kp = m.fetch_for_me(D3, D2).unwrap();
    assert_ne!(d1_kp, d2_kp);

    // Both build Welcomes for "add D3 to alice-bob" at the same epoch.
    let _d1_w = m.consume(D1, D3, d1_kp);
    let d2_w = m.consume(D2, D3, d2_kp);

    // The PDS sequences them; D1's commit lands first, D2 loses the epoch
    // race and the MLS layer rejects its commit when D3 observes it.
    m.reject(d2_w);

    // D3 processes the winning Welcome. Its init key is consumed and the
    // (D3 → D1) slot is cleared.
    m.receive(D3, d1_kp).expect("winner welcome processes cleanly");

    // D3 does NOT call receive on the rejected Welcome — MLS would refuse
    // it on epoch grounds and crucially the init key for slot (D3 → D2) is
    // left intact.
    assert!(m.rejected_welcomes.contains(&d2_w));
    assert_eq!(m.failed_receives, 0);

    // D2 retries against the new epoch. It re-fetches the (D3 → D2) slot
    // and finds the SAME kp (D3 never replenished it because it was never
    // consumed). D2 builds a new Welcome — same init_kp, different MLS
    // commit — and D3 receives it.
    let d2_retry_kp = m.fetch_for_me(D3, D2).unwrap();
    assert_eq!(d2_retry_kp, kp_d3_for_d2);
    m.consume(D2, D3, d2_retry_kp);
    m.receive(D3, d2_retry_kp).expect("d2 retry processes");
    assert_eq!(m.failed_receives, 0);

    let _ = kp_d3_for_d1;
}

/// **Delayed replenish: the owner is slow / restarted / batches its work.**
///
/// The honest model of `receive` is that consumption of the init key and
/// the PDS-side slot clear are *not* atomic in production. A device might
/// process a Welcome (consume the init key in its local keystore), then
/// crash before clearing the slot on the PDS. After restart it observes
/// "my slot still has KP_X on the PDS, but init_X is gone from my local
/// store" and reconciles by replenishing.
///
/// The risk: in the lag window between consumption and slot-clear, the
/// dedicated consumer could re-fetch the slot and re-use KP_X.
///
/// This test exposes that risk by splitting `receive` into two steps and
/// driving them out of order.
#[test]
fn slot_orphan_within_window_when_clear_lags_consumption() {
    #[derive(Debug, Default)]
    struct DelayedSlotModel {
        next_rkey: u32,
        next_welcome_id: u32,
        slots: BTreeMap<(DeviceId, DeviceId), Option<Rkey>>,
        keystore: BTreeMap<DeviceId, BTreeSet<Rkey>>,
        in_flight: Vec<Welcome>,
        failed_receives: u32,
    }
    impl DelayedSlotModel {
        fn publish_for(&mut self, owner: DeviceId, intended_for: DeviceId) -> Rkey {
            self.next_rkey += 1;
            let kp = Rkey(self.next_rkey);
            self.slots.insert((owner, intended_for), Some(kp));
            self.keystore.entry(owner).or_default().insert(kp);
            kp
        }
        fn fetch_for_me(&self, target: DeviceId, me: DeviceId) -> Option<Rkey> {
            *self.slots.get(&(target, me))?
        }
        fn consume(&mut self, sender: DeviceId, target: DeviceId, kp: Rkey) -> WelcomeId {
            self.next_welcome_id += 1;
            let id = WelcomeId(self.next_welcome_id);
            self.in_flight.push(Welcome { id, sender, target, init_kp: kp });
            id
        }
        /// Process the Welcome (consume init key) but DO NOT clear the slot.
        fn process_welcome(&mut self, receiver: DeviceId, kp: Rkey) -> Result<DeviceId, ()> {
            let idx = self
                .in_flight
                .iter()
                .position(|w| w.target == receiver && w.init_kp == kp)
                .ok_or(())?;
            let w = self.in_flight.remove(idx);
            let ks = self.keystore.entry(receiver).or_default();
            if !ks.remove(&kp) {
                self.failed_receives += 1;
                return Err(());
            }
            Ok(w.sender)
        }
        /// Owner observes a consumption and clears the slot.
        fn observe_and_clear(&mut self, owner: DeviceId, used_for: DeviceId) {
            self.slots.insert((owner, used_for), None);
        }
    }

    let mut m = DelayedSlotModel::default();
    let kp_for_d1 = m.publish_for(D3, D1);

    // D1 fetches and consumes.
    let kp = m.fetch_for_me(D3, D1).unwrap();
    m.consume(D1, D3, kp);
    let sender = m.process_welcome(D3, kp).expect("welcome processes");
    assert_eq!(sender, D1);

    // D3 has NOT yet cleared the slot. From D1's vantage, the slot still
    // looks occupied.
    assert_eq!(m.fetch_for_me(D3, D1), Some(kp_for_d1));

    // If D1 naively re-fetches the slot and re-uses the value, we get the
    // exact orphan-within-slot bug.
    let stale = m.fetch_for_me(D3, D1).unwrap();
    m.consume(D1, D3, stale);
    let err = m.process_welcome(D3, stale).expect_err("re-use must fail");
    assert_eq!(err, ());
    assert_eq!(m.failed_receives, 1, "delayed clear can reintroduce the bug");

    // Cleanup: owner observes and clears.
    m.observe_and_clear(D3, D1);
    assert!(m.fetch_for_me(D3, D1).is_none());
}

/// **Defence against the delayed-clear orphan: consumer tracks last-used
/// per slot.**
///
/// The simplest mitigation that doesn't require atomic clear: each consumer
/// records the rkey of the KP it used per slot. If a future fetch returns
/// the same rkey, the consumer treats the slot as exhausted and waits.
///
/// The model shows this restores the every-welcome-receivable property
/// even under arbitrary clear lag.
#[test]
fn slot_consumer_side_tracking_closes_the_delayed_clear_window() {
    let mut m = SlotModel::default();
    let mut consumer_last_used: BTreeMap<(DeviceId, DeviceId), Rkey> = BTreeMap::new();

    fn fetch_fresh(
        m: &SlotModel,
        target: DeviceId,
        me: DeviceId,
        last_used: &BTreeMap<(DeviceId, DeviceId), Rkey>,
    ) -> Option<Rkey> {
        let kp = m.fetch_for_me(target, me)?;
        match last_used.get(&(target, me)) {
            Some(prev) if *prev == kp => None,
            _ => Some(kp),
        }
    }

    m.publish_for(D3, D1);

    // First use: slot is fresh, consumer records it.
    let kp1 = fetch_fresh(&m, D3, D1, &consumer_last_used).unwrap();
    m.consume(D1, D3, kp1);
    consumer_last_used.insert((D3, D1), kp1);

    // Simulate the lag: D3 has not yet cleared the slot. D1's poll runs.
    // The freshness check correctly returns None because the slot still
    // shows the rkey D1 already used.
    assert!(fetch_fresh(&m, D3, D1, &consumer_last_used).is_none());

    // D3 catches up: receives the Welcome and clears the slot.
    m.receive(D3, kp1).unwrap();
    assert!(m.fetch_for_me(D3, D1).is_none());

    // Eventually D3 replenishes. Consumer sees a *different* rkey and is
    // willing to use the slot again.
    let kp2 = m.publish_for(D3, D1);
    assert_ne!(kp1, kp2);
    let next = fetch_fresh(&m, D3, D1, &consumer_last_used).unwrap();
    assert_eq!(next, kp2);
    m.consume(D1, D3, next);
    consumer_last_used.insert((D3, D1), next);
    m.receive(D3, next).unwrap();
    assert_eq!(m.failed_receives, 0);
}

/// **First-contact bootstrap: a new device with no slots yet.**
///
/// A brand-new D4 has just logged in. D1, D2, D3 are already an established
/// ring with bidirectional slots between every pair. D4 has zero slots
/// either incoming or outgoing.
///
/// The model question: can D4 establish its first round of slots without
/// reintroducing the shared-pool race?
///
/// Walkthrough:
/// 1. D4 publishes its own stealth address (no KP yet — there's no
///    consumer to publish for).
/// 2. The existing ring members observe D4's stealth address, learn its
///    device_id, and each writes a (self → D4) slot.
/// 3. D4 observes the new (D1 → D4), (D2 → D4), (D3 → D4) slots, and now
///    writes (D4 → D1), (D4 → D2), (D4 → D3) slots in return.
/// 4. From step 3 onward, every add uses dedicated slots and the model's
///    invariant holds.
///
/// The crucial property: between step 1 and step 2 there is NO key-package
/// race — there are no KPs in play. The "first contact" handshake is
/// carried by stealth-encrypted coord-group invites that target D4's
/// stealth pubkey only (as today). Slots come into existence one direction
/// at a time, and each one is dedicated from the moment it's created.
#[test]
fn slot_first_contact_bootstrap_avoids_shared_pool() {
    let mut m = SlotModel::default();

    // Initial steady state: D1, D2, D3 already have bidirectional slots.
    m.publish_for(D1, D2);
    m.publish_for(D1, D3);
    m.publish_for(D2, D1);
    m.publish_for(D2, D3);
    m.publish_for(D3, D1);
    m.publish_for(D3, D2);

    // Step 1: D4 announces itself (modelled here as just being known to the
    // others; the actual mechanism is publishing a stealth address, which
    // the model elides because it's not where the KP race lives).

    // Step 2: existing members each create an outbound slot for D4.
    // CRUCIAL: each creator writes a *dedicated* slot for D4 — there is
    // never a moment where multiple consumers (D1, D2, D3) contend on a
    // shared D4 KP.
    let kp_d1_for_d4 = m.publish_for(D1, D4);
    let kp_d2_for_d4 = m.publish_for(D2, D4);
    let kp_d3_for_d4 = m.publish_for(D3, D4);
    let all = [kp_d1_for_d4, kp_d2_for_d4, kp_d3_for_d4];
    assert_eq!(all.iter().collect::<BTreeSet<_>>().len(), 3, "all KPs distinct");

    // Step 3: D4 observes the new slots and reciprocates.
    m.publish_for(D4, D1);
    m.publish_for(D4, D2);
    m.publish_for(D4, D3);

    // Step 4: every add can now be carried out using a dedicated slot.
    // Concretely, the ring members fetch (D4 → self) to invite D4 into the
    // ring, and D4 fetches (self → D4) for any reciprocal adds. None of
    // these fetches contend.
    let d1_to_d4_kp = m.fetch_for_me(D4, D1).unwrap();
    let d2_to_d4_kp = m.fetch_for_me(D4, D2).unwrap();
    let d3_to_d4_kp = m.fetch_for_me(D4, D3).unwrap();
    assert_ne!(d1_to_d4_kp, d2_to_d4_kp);
    assert_ne!(d2_to_d4_kp, d3_to_d4_kp);
    assert_ne!(d1_to_d4_kp, d3_to_d4_kp);

    m.consume(D1, D4, d1_to_d4_kp);
    m.consume(D2, D4, d2_to_d4_kp);
    m.consume(D3, D4, d3_to_d4_kp);
    m.receive(D4, d1_to_d4_kp).unwrap();
    m.receive(D4, d2_to_d4_kp).unwrap();
    m.receive(D4, d3_to_d4_kp).unwrap();
    assert_eq!(m.failed_receives, 0);
}

/// **Revocation: removing a device from the ring also retires its slots.**
///
/// Bobby-Tables scenario: D2 is revoked. Going forward no Welcomes should
/// be deliverable into D2's slots, but D2's existing in-flight Welcomes
/// (built before revocation) might still be on the PDS. The model checks
/// that after revocation:
/// - all (D2 → *) and (* → D2) slots are removed,
/// - any further `consume` targeting D2 fails because no slot exists.
#[test]
fn slot_revocation_retires_slots_in_both_directions() {
    let mut m = SlotModel::default();
    // Set up bidirectional slots between D1, D2, D3.
    for (a, b) in [(D1, D2), (D1, D3), (D2, D1), (D2, D3), (D3, D1), (D3, D2)] {
        m.publish_for(a, b);
    }

    // Revoke D2.
    let revoked = D2;
    m.slots.retain(|(owner, intended_for), _| *owner != revoked && *intended_for != revoked);
    // Drop D2's keystore entries while we're at it; in the real system the
    // revocation commit makes D2's MLS state obsolete but its local keys
    // remain on its own device. The model only cares that no one else can
    // build a deliverable Welcome targeting D2.
    m.keystore.remove(&revoked);

    // Other devices observe D2 is gone — there is no slot to fetch.
    assert!(m.fetch_for_me(D2, D1).is_none());
    assert!(m.fetch_for_me(D2, D3).is_none());

    // And no one can publish into a D2 slot either.
    assert!(!m.slots.contains_key(&(D1, revoked)));
    assert!(!m.slots.contains_key(&(D3, revoked)));
}
