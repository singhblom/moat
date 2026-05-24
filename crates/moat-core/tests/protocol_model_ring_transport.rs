//! Protocol-level model of the **ring-transport** design.
//!
//! Companion to `protocol_model.rs`. That file models the world where every
//! key-package fetch and every Welcome flows through the PDS. This file
//! models a design where:
//!
//! - Cross-user discovery and first-contact bootstrap still use the PDS.
//! - Once the device ring is established between same-user devices, the
//!   ring becomes the transport for *every subsequent operation between
//!   those devices*. Key packages flow from the new device to existing
//!   members as ring application messages; Welcomes flow back as ring
//!   application messages too.
//! - The PDS is no longer in the critical path for the user-conversation
//!   fan-out that happens when a new sibling joins.
//!
//! The properties checked here:
//!
//! 1. Single-use is preserved: a key package is consumed at most once and
//!    every Welcome reaches a receiver that still holds the matching init
//!    key (`failed_receives == 0`).
//! 2. Pool management is safe under concurrent refill requests, replayed
//!    batches, and offline-receiver windows.
//! 3. Batched fan-out across multiple groups in a single tick draws a
//!    distinct KP per add and produces deliverable Welcomes for all of
//!    them.
//!
//! The model is deliberately MLS-naive: it doesn't represent epochs or
//! commits because those are orthogonal to the KP-consumption invariant.
//! Where MLS would refuse an old commit, the model has the receiver simply
//! decline to call `process_welcome` on a rejected message (see
//! `slot_mls_commit_conflict_does_not_burn_loser_slot` in
//! `protocol_model.rs`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

// ── Identities ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct DeviceId(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Rkey(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Seq(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct WelcomeId(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct GroupId(u32);

// ── Ring messages ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfferedKp {
    rkey: Rkey,
    /// Owner-issued sequence number. Owner increments per published KP so
    /// the consumer can dedupe and order.
    seq: Seq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WelcomeMsg {
    id: WelcomeId,
    /// The init key (= KP rkey) this Welcome was built from.
    init_kp: Rkey,
    /// The group the Welcome admits the receiver into.
    group: GroupId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RingMessage {
    /// Owner → consumer: "here are N fresh KPs you may use".
    KpBatch(Vec<OfferedKp>),
    /// Consumer → owner: "I want more KPs".
    KpRequest { count: u32 },
    /// Consumer → owner: a Welcome for an add the consumer just performed.
    Welcome(WelcomeMsg),
}

// ── The model ─────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct RingTransportModel {
    next_rkey: u32,
    next_welcome_id: u32,
    /// Per-owner monotonic sequence stamped on each published KP.
    next_seq: BTreeMap<DeviceId, u64>,
    /// Init keys currently in each device's keystore (KP rkey → present).
    /// Adding a KP via `publish_kp` adds the rkey here; `receive_welcome`
    /// removes the entry that matches the Welcome's `init_kp`.
    keystore: BTreeMap<DeviceId, BTreeSet<Rkey>>,
    /// In-order ring channel from sender → receiver. Modelled as a FIFO
    /// queue; MLS application messages are delivered in order, with no
    /// drops, once the receiver is online.
    ring: BTreeMap<(DeviceId, DeviceId), VecDeque<RingMessage>>,
    /// Consumer's local pool: KPs the consumer has received from `owner`
    /// over the ring but has not yet used.
    local_pool: BTreeMap<(DeviceId /* consumer */, DeviceId /* owner */), Vec<OfferedKp>>,
    /// Consumer-side dedupe: the highest seq this consumer has *ever*
    /// observed from `owner`, used or not. Lets the consumer reject
    /// duplicate ring messages without re-checking the pool.
    highest_seq_observed: BTreeMap<(DeviceId, DeviceId), Seq>,
    /// Consumer-side tracking of which KPs have actually been used. Even
    /// if the same seq somehow reappeared, "used" gates re-use.
    used_kps: BTreeMap<(DeviceId, DeviceId), BTreeSet<Seq>>,
    /// Failures observed. Any non-zero value here is the model raising the
    /// alarm.
    failed_receives: u32,
}

impl RingTransportModel {
    fn fresh_rkey(&mut self) -> Rkey {
        self.next_rkey += 1;
        Rkey(self.next_rkey)
    }

    fn fresh_seq(&mut self, owner: DeviceId) -> Seq {
        let s = self.next_seq.entry(owner).or_insert(0);
        *s += 1;
        Seq(*s)
    }

    fn fresh_welcome_id(&mut self) -> WelcomeId {
        self.next_welcome_id += 1;
        WelcomeId(self.next_welcome_id)
    }

    fn ring_send(&mut self, from: DeviceId, to: DeviceId, msg: RingMessage) {
        self.ring.entry((from, to)).or_default().push_back(msg);
    }

    fn ring_pop(&mut self, from: DeviceId, to: DeviceId) -> Option<RingMessage> {
        self.ring.get_mut(&(from, to))?.pop_front()
    }

    fn ring_pending(&self, from: DeviceId, to: DeviceId) -> usize {
        self.ring.get(&(from, to)).map(|q| q.len()).unwrap_or(0)
    }

    // ── Owner-side actions ────────────────────────────────────────────────────

    /// `owner` publishes a batch of `count` fresh KPs (each adds its init
    /// key to the owner's keystore) and sends them over the ring to
    /// `consumer`.
    fn publish_and_offer(&mut self, owner: DeviceId, consumer: DeviceId, count: usize) {
        let mut batch = Vec::with_capacity(count);
        for _ in 0..count {
            let rkey = self.fresh_rkey();
            let seq = self.fresh_seq(owner);
            self.keystore.entry(owner).or_default().insert(rkey);
            batch.push(OfferedKp { rkey, seq });
        }
        self.ring_send(owner, consumer, RingMessage::KpBatch(batch));
    }

    /// `owner` processes any inbound ring messages from `consumer`. Welcomes
    /// get processed (init key consumed); `KpRequest`s trigger an immediate
    /// `publish_and_offer` of `count` KPs.
    fn owner_drain_inbound(&mut self, owner: DeviceId, consumer: DeviceId) {
        while let Some(msg) = self.ring_pop(consumer, owner) {
            match msg {
                RingMessage::Welcome(w) => {
                    self.receive_welcome(owner, w);
                }
                RingMessage::KpRequest { count } => {
                    self.publish_and_offer(owner, consumer, count as usize);
                }
                RingMessage::KpBatch(_) => {
                    // Owner should not receive batches from a consumer.
                    self.failed_receives += 1;
                }
            }
        }
    }

    fn receive_welcome(&mut self, receiver: DeviceId, w: WelcomeMsg) {
        let ks = self.keystore.entry(receiver).or_default();
        if !ks.remove(&w.init_kp) {
            self.failed_receives += 1;
        }
    }

    // ── Consumer-side actions ─────────────────────────────────────────────────

    /// `consumer` processes any inbound ring messages from `owner`. KP
    /// batches are appended to the local pool (deduped by seq).
    fn consumer_drain_inbound(&mut self, consumer: DeviceId, owner: DeviceId) {
        while let Some(msg) = self.ring_pop(owner, consumer) {
            match msg {
                RingMessage::KpBatch(batch) => {
                    let mut highest = self
                        .highest_seq_observed
                        .get(&(consumer, owner))
                        .copied()
                        .unwrap_or(Seq(0));
                    for kp in batch {
                        if kp.seq <= highest {
                            // Already observed (or stale); drop.
                            continue;
                        }
                        highest = kp.seq;
                        self.local_pool
                            .entry((consumer, owner))
                            .or_default()
                            .push(kp);
                    }
                    self.highest_seq_observed
                        .insert((consumer, owner), highest);
                }
                RingMessage::Welcome(_) | RingMessage::KpRequest { .. } => {
                    // Consumer should not receive these from an owner.
                    self.failed_receives += 1;
                }
            }
        }
    }

    /// `consumer` claims the next unused KP from its pool of `owner`'s KPs.
    /// Returns `None` if the pool is empty — caller must `request_refill`
    /// and wait.
    fn claim_kp(&mut self, consumer: DeviceId, owner: DeviceId) -> Option<OfferedKp> {
        let pool = self.local_pool.get_mut(&(consumer, owner))?;
        // Pick the first unused one (could just as well be newest; FIFO is
        // easier to reason about).
        let used = self.used_kps.entry((consumer, owner)).or_default();
        let idx = pool.iter().position(|kp| !used.contains(&kp.seq))?;
        let kp = pool.remove(idx);
        used.insert(kp.seq);
        Some(kp)
    }

    fn pool_size(&self, consumer: DeviceId, owner: DeviceId) -> usize {
        self.local_pool
            .get(&(consumer, owner))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// `consumer` performs `add_device(target, kp)` and sends the resulting
    /// Welcome to `target` over the ring. The model treats the MLS commit
    /// as out of scope; only the Welcome flows here.
    fn consume_and_send_welcome(
        &mut self,
        consumer: DeviceId,
        target: DeviceId,
        kp: OfferedKp,
        group: GroupId,
    ) {
        let id = self.fresh_welcome_id();
        let welcome = WelcomeMsg {
            id,
            init_kp: kp.rkey,
            group,
        };
        self.ring_send(consumer, target, RingMessage::Welcome(welcome));
    }

    fn request_refill(&mut self, consumer: DeviceId, owner: DeviceId, count: u32) {
        self.ring_send(consumer, owner, RingMessage::KpRequest { count });
    }
}

// ── Devices and groups used across scenarios ─────────────────────────────────

const D1: DeviceId = DeviceId(1);
const D3: DeviceId = DeviceId(3);
const ALICE_BOB: GroupId = GroupId(100);
const ALICE_CHARLIE: GroupId = GroupId(101);
const ALICE_DAVE: GroupId = GroupId(102);
const ALICE_BOOKCLUB: GroupId = GroupId(103);
const ALICE_RING: GroupId = GroupId(200);

// ── Scenarios ────────────────────────────────────────────────────────────────

/// Happy path: D3 sends a batch, D1 uses one for an add, D3 processes the
/// Welcome.
#[test]
fn ring_transport_happy_path() {
    let mut m = RingTransportModel::default();

    // D3 has joined the ring; sends an initial batch of 4 KPs over the ring
    // to D1.
    m.publish_and_offer(D3, D1, 4);

    // D1 drains its inbound and now has 4 KPs in its local pool.
    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 4);

    // D1 claims one and adds D3 to alice-bob.
    let kp = m.claim_kp(D1, D3).unwrap();
    m.consume_and_send_welcome(D1, D3, kp, ALICE_BOB);
    assert_eq!(m.pool_size(D1, D3), 3);

    // D3 processes the Welcome.
    m.owner_drain_inbound(D3, D1);
    assert_eq!(m.failed_receives, 0);
}

/// **Fan-out across multiple groups in a single tick.**
///
/// D3 has just joined the ring. D1 immediately needs to add D3 to four
/// existing user conversations. With a PDS-slot scheme this would be
/// four sequential round trips, each waiting for D3 to replenish. Under
/// ring-transport D3 sends a batch up front and D1 fans out without
/// re-fetching.
#[test]
fn ring_transport_fan_out_with_no_lag() {
    let mut m = RingTransportModel::default();

    // Right after the ring is up, D3 ships D1 a batch big enough for the
    // expected fan-out (with some slack).
    m.publish_and_offer(D3, D1, 8);
    m.consumer_drain_inbound(D1, D3);

    // D1 adds D3 to four user conversations *in a single tick*. Each add
    // uses a distinct KP from the pool.
    let groups = [ALICE_BOB, ALICE_CHARLIE, ALICE_DAVE, ALICE_BOOKCLUB];
    let mut used_init_kps = BTreeSet::new();
    for g in groups {
        let kp = m.claim_kp(D1, D3).unwrap();
        used_init_kps.insert(kp.rkey);
        m.consume_and_send_welcome(D1, D3, kp, g);
    }
    assert_eq!(used_init_kps.len(), 4, "every add used a distinct KP");
    assert_eq!(m.pool_size(D1, D3), 4, "four KPs left in the pool");
    assert_eq!(m.ring_pending(D1, D3), 4, "four Welcomes pending to D3");

    // D3 processes all four Welcomes in one go.
    m.owner_drain_inbound(D3, D1);
    assert_eq!(m.failed_receives, 0);
    assert_eq!(m.ring_pending(D1, D3), 0);
}

/// **Pool exhaustion forces a refill before further adds.** D3 sends a small
/// batch; D1 uses it up. Pool empty → `claim_kp` returns None. D1 must
/// send a `KpRequest` and wait. D3 receives it and ships another batch.
#[test]
fn ring_transport_pool_exhaustion_requires_refill() {
    let mut m = RingTransportModel::default();
    m.publish_and_offer(D3, D1, 2);
    m.consumer_drain_inbound(D1, D3);

    // D1 uses both.
    let kp1 = m.claim_kp(D1, D3).unwrap();
    let kp2 = m.claim_kp(D1, D3).unwrap();
    m.consume_and_send_welcome(D1, D3, kp1, ALICE_BOB);
    m.consume_and_send_welcome(D1, D3, kp2, ALICE_CHARLIE);
    assert_eq!(m.pool_size(D1, D3), 0);

    // Trying to claim again returns None.
    assert!(m.claim_kp(D1, D3).is_none());

    // D1 requests a refill.
    m.request_refill(D1, D3, 4);

    // D3 drains its inbound: processes both Welcomes AND the KpRequest, and
    // sends a fresh batch.
    m.owner_drain_inbound(D3, D1);
    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 4);
    assert_eq!(m.failed_receives, 0);

    // D1 can now claim again. The new KPs have higher seqs than the
    // previously used ones, so the consumer's dedupe never trips.
    let kp3 = m.claim_kp(D1, D3).unwrap();
    assert!(kp3.seq > Seq(2));
}

/// **Duplicate refill responses.** D1 sends two `KpRequest`s in quick
/// succession (e.g. because two ring-ticks fired before D3 had a chance to
/// answer). D3 honours both and sends two batches. The consumer-side
/// `highest_seq_observed` dedupes nothing — but the sequence numbers are
/// distinct across batches, so the pool just grows. The invariant holds.
#[test]
fn ring_transport_concurrent_refill_requests_do_not_collide() {
    let mut m = RingTransportModel::default();

    // D1 issues two requests before D3 has a chance to drain.
    m.request_refill(D1, D3, 3);
    m.request_refill(D1, D3, 3);

    // D3 drains its inbound: sees both requests, ships two batches.
    m.owner_drain_inbound(D3, D1);
    assert_eq!(m.ring_pending(D3, D1), 2, "two batches on the wire");

    // D1 drains.
    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 6);

    // All KPs have distinct seqs — every claim returns a unique one.
    let mut seqs = BTreeSet::new();
    for _ in 0..6 {
        let kp = m.claim_kp(D1, D3).unwrap();
        seqs.insert(kp.seq);
    }
    assert_eq!(seqs.len(), 6);
}

/// **Replayed batch.** A malicious or buggy node redelivers the same KP
/// batch twice. The consumer's `highest_seq_observed` rejects the duplicate
/// — the pool doesn't grow on the second drain.
#[test]
fn ring_transport_replayed_batch_is_rejected_by_seq_dedupe() {
    let mut m = RingTransportModel::default();
    m.publish_and_offer(D3, D1, 3);

    // Capture the batch and replay it.
    let batch = m.ring.get(&(D3, D1)).unwrap().front().cloned().unwrap();

    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 3);

    // Replay.
    m.ring_send(D3, D1, batch);
    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 3, "replayed batch dropped");
}

/// **D3 is offline when D1 fans out.** Ring messages from D1 to D3 just
/// queue. The moment D3 comes online and drains, every Welcome processes
/// cleanly. No KP is consumed twice.
#[test]
fn ring_transport_d3_offline_does_not_break_invariant() {
    let mut m = RingTransportModel::default();
    m.publish_and_offer(D3, D1, 4);
    m.consumer_drain_inbound(D1, D3);

    // D1 fans out while D3 is "offline" — we don't call owner_drain_inbound.
    for g in [ALICE_BOB, ALICE_CHARLIE, ALICE_DAVE, ALICE_BOOKCLUB] {
        let kp = m.claim_kp(D1, D3).unwrap();
        m.consume_and_send_welcome(D1, D3, kp, g);
    }
    assert_eq!(m.ring_pending(D1, D3), 4);

    // D3 comes online much later and drains. Everything just works.
    m.owner_drain_inbound(D3, D1);
    assert_eq!(m.failed_receives, 0);
    assert_eq!(m.ring_pending(D1, D3), 0);

    // Owner's keystore has had four init keys removed.
    let ks = m.keystore.get(&D3).unwrap();
    assert_eq!(ks.len(), 0);
}

/// **No KP is ever used twice by the consumer.**
///
/// Consumer-side single-use enforcement: the local pool's `used_kps` set
/// guarantees a claimed KP is never returned again, even if the same
/// `OfferedKp` somehow re-enters the pool (buggy refill, malicious
/// replay, or out-of-order delivery). Verify by injecting a manual
/// duplicate and checking the second claim skips it.
#[test]
fn ring_transport_consumer_never_reuses_a_used_kp() {
    let mut m = RingTransportModel::default();
    m.publish_and_offer(D3, D1, 2);
    m.consumer_drain_inbound(D1, D3);

    // Claim one — it's now in `used_kps`.
    let kp = m.claim_kp(D1, D3).unwrap();
    m.consume_and_send_welcome(D1, D3, kp.clone(), ALICE_BOB);

    // Adversarially re-insert it into the pool (simulating a buggy code path
    // that didn't remove it).
    m.local_pool.get_mut(&(D1, D3)).unwrap().push(kp.clone());

    // Next claim skips the duplicate and returns the other KP.
    let next = m.claim_kp(D1, D3).expect("a KP is still available");
    assert_ne!(next.seq, kp.seq);

    // A third claim — pool is empty as far as unused KPs go.
    assert!(m.claim_kp(D1, D3).is_none());

    // D3 processes the Welcome.
    m.owner_drain_inbound(D3, D1);
    assert_eq!(m.failed_receives, 0);
}

/// **End-to-end new-sibling join under ring-transport.**
///
/// 1. D3 joins the ring (modelled by D3 sending a KP batch to D1 — the ring
///    is up).
/// 2. D1 fans D3 out to four existing user conversations in one tick.
/// 3. D3 processes all four Welcomes in one tick.
/// 4. The model's failure counter is zero.
///
/// The flow is one round trip plus four parallel commit-publishes (the
/// PDS writes for bob, charlie, dave, bookclub members — not modelled
/// because they don't bear on the KP invariant). Compare with a PDS-slot
/// scheme where this would be four sequential round trips.
#[test]
fn ring_transport_new_sibling_join_end_to_end() {
    let mut m = RingTransportModel::default();

    // Ring bootstrap (modelled as D3 publishing initial KP batch via ring).
    m.publish_and_offer(D3, D1, 8);
    m.consumer_drain_inbound(D1, D3);

    // D1 adds D3 to the ring itself first — that's one of the four
    // adds. The ring add uses the same shape as a user-conversation add.
    let groups = [ALICE_RING, ALICE_BOB, ALICE_CHARLIE, ALICE_DAVE];
    let mut welcome_init_kps = Vec::new();
    for g in groups {
        let kp = m.claim_kp(D1, D3).unwrap();
        welcome_init_kps.push(kp.rkey);
        m.consume_and_send_welcome(D1, D3, kp, g);
    }
    assert_eq!(welcome_init_kps.iter().collect::<BTreeSet<_>>().len(), 4);

    // D3 processes all four Welcomes in one drain. None fail.
    m.owner_drain_inbound(D3, D1);
    assert_eq!(m.failed_receives, 0);
    assert_eq!(m.ring_pending(D1, D3), 0);
}
