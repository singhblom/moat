//! Hybrid protocol model: **public key-package pool for bootstrap, ring
//! transport thereafter**.
//!
//! Composes the two designs modelled in `protocol_model.rs` and
//! `protocol_model_ring_transport.rs`.
//!
//! Why the composition is sound:
//!
//! - Before a ring exists between two sibling devices there is no
//!   authenticated channel between them, so the only KeyPackage source is
//!   the public `social.moat.keyPackage` pool that cross-user inviters
//!   already read. That pool **accumulates**: records are created with
//!   `createRecord` and never deleted, because a `deleteRecord` shortly
//!   after `createRecord` would be a distinctive firehose pattern. So a
//!   spent record stays visible next to its replacement and nothing on
//!   the wire tells them apart.
//! - Two rules make drawing from it safe. Publicly: take the **newest**
//!   record for the owner, since older ones are the likely-spent ones.
//!   Locally: skip records **we** have already burned, because a device
//!   needing both a coord group and a ring add for the same sibling draws
//!   twice and the newest-record rule alone would hand back the record
//!   the first draw killed.
//! - Neither rule makes concurrent draws safe, and they cannot: two
//!   readers see the identical list and pick the identical record. That
//!   is why draws are serialised — by electing the smallest-leaf member
//!   for ring adds, and by letting only the onboarding device initiate
//!   coord groups. The model records the collision as an observed
//!   property rather than a fixed one — see
//!   `hybrid_concurrent_consumers_race_for_the_same_pool_record`.
//! - Everything after the ring exists (user-conversation fan-out,
//!   subsequent device joins of *other* siblings, sync sessions) flows
//!   over the ring, where `protocol_model_ring_transport.rs` already
//!   shows the invariant holds without PDS round trips.
//!
//! Properties checked here:
//!
//! 1. A consumer's repeated draws against one owner never return a record
//!    that consumer has already burned.
//! 2. Concurrent draws by *different* consumers do collide, and the
//!    losing Welcome is undeliverable — the cost the election avoids.
//! 3. The handover is clean: pool draws while bootstrapping, then every
//!    subsequent KP exchange happens through the ring with the
//!    consumer-side `used_kps` tracking from the ring-transport model.
//! 4. A new device that arrives *after* a ring already exists composes
//!    with the existing members through the same path.

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

const D1: DeviceId = DeviceId(1);
const D2: DeviceId = DeviceId(2);
const D3: DeviceId = DeviceId(3);
const D4: DeviceId = DeviceId(4);

const RING: GroupId = GroupId(200);
const ALICE_BOB: GroupId = GroupId(100);
const ALICE_CHARLIE: GroupId = GroupId(101);
const ALICE_DAVE: GroupId = GroupId(102);
const ALICE_BOOKCLUB: GroupId = GroupId(103);

// ── Bootstrap and steady-state messages ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfferedKp {
    rkey: Rkey,
    seq: Seq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WelcomeMsg {
    id: WelcomeId,
    init_kp: Rkey,
    group: GroupId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RingMessage {
    KpBatch(Vec<OfferedKp>),
    KpRequest { count: u32 },
    Welcome(WelcomeMsg),
}

// ── The hybrid model ─────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct HybridModel {
    next_rkey: u32,
    next_seq: BTreeMap<DeviceId, u64>,
    next_welcome_id: u32,

    /// Init keys currently in each device's keystore.
    keystore: BTreeMap<DeviceId, BTreeSet<Rkey>>,

    // ── Bootstrap-phase public key-package pool ──────────────────────────────
    /// `owner → published key packages, oldest first`. The public
    /// `social.moat.keyPackage` collection: append-only, never deleted,
    /// and every reader sees the identical list.
    pds_pool: BTreeMap<DeviceId, Vec<Rkey>>,
    /// Consumer-side: pool records this consumer has already burned.
    /// Keyed by consumer alone, not `(consumer, owner)` — a record
    /// belongs to exactly one owner, and the consumer's obligation is
    /// simply never to reuse bytes whose init key it already spent.
    used_pool_kps: BTreeMap<DeviceId, BTreeSet<Rkey>>,

    // ── Ring transport ────────────────────────────────────────────────────────
    /// FIFO message queue on the ring.
    ring: BTreeMap<(DeviceId, DeviceId), VecDeque<RingMessage>>,
    /// Which (consumer, owner) pairs have an active ring relationship
    /// (i.e. both are in the ring together).
    ring_members_of: BTreeMap<GroupId, BTreeSet<DeviceId>>,
    /// Consumer's local pool of KPs received from each owner.
    local_pool: BTreeMap<(DeviceId, DeviceId), Vec<OfferedKp>>,
    /// Consumer-side: highest seq observed per (consumer, owner). Replay
    /// defence.
    highest_seq_observed: BTreeMap<(DeviceId, DeviceId), Seq>,
    /// Consumer-side: KPs the consumer has already claimed. Single-use.
    used_kps: BTreeMap<(DeviceId, DeviceId), BTreeSet<Seq>>,

    /// Anything that should never happen and did.
    failures: Vec<String>,
}

impl HybridModel {
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

    // ── Bootstrap-phase: the public key-package pool ─────────────────────────

    /// Owner publishes a key package into its public pool. Appends;
    /// never replaces. Mirrors `createRecord` on `social.moat.keyPackage`.
    fn publish_pool_kp(&mut self, owner: DeviceId) -> Rkey {
        let rkey = self.fresh_rkey();
        self.pds_pool.entry(owner).or_default().push(rkey);
        self.keystore.entry(owner).or_default().insert(rkey);
        rkey
    }

    /// Consumer selects the newest package `owner` has published that this
    /// consumer has not already burned.
    ///
    /// `None` means the owner has not replenished since we last drew — an
    /// ordinary wait, not a failure. The real driver defers to a later
    /// tick, and the owner replenishes on every consumption (including on
    /// processing our coord Welcome), so a record normally appears within
    /// a tick or two.
    fn fetch_newest_unused_pool_kp(&self, consumer: DeviceId, owner: DeviceId) -> Option<Rkey> {
        let used = self.used_pool_kps.get(&consumer);
        self.pds_pool
            .get(&owner)?
            .iter()
            .rev()
            .find(|rkey| !used.map(|u| u.contains(rkey)).unwrap_or(false))
            .copied()
    }

    /// Consumer uses a pool KP to build an MLS Welcome admitting `owner`
    /// to the ring, and records the burn. The Welcome is delivered via
    /// the owner's normal poll path; here we enqueue it onto the
    /// consumer→owner ring queue, the same queue the ring uses once it
    /// exists.
    fn bootstrap_add_to_ring(&mut self, consumer: DeviceId, owner: DeviceId, kp: Rkey) {
        let id = self.fresh_welcome_id();
        let w = WelcomeMsg { id, init_kp: kp, group: RING };
        self.ring
            .entry((consumer, owner))
            .or_default()
            .push_back(RingMessage::Welcome(w));
        self.used_pool_kps.entry(consumer).or_default().insert(kp);
    }

    /// Draw-and-add in one step, the shape the driver actually uses.
    /// Returns the record drawn, or `None` if nothing usable is published.
    fn try_bootstrap_add(&mut self, consumer: DeviceId, owner: DeviceId) -> Option<Rkey> {
        let kp = self.fetch_newest_unused_pool_kp(consumer, owner)?;
        self.bootstrap_add_to_ring(consumer, owner, kp);
        Some(kp)
    }


    // ── Ring transport ────────────────────────────────────────────────────────

    /// Owner publishes a batch of KPs into the ring queue for the consumer.
    /// Only valid once both devices are in the ring.
    fn publish_and_offer(&mut self, owner: DeviceId, consumer: DeviceId, count: usize) {
        let mut batch = Vec::with_capacity(count);
        for _ in 0..count {
            let rkey = self.fresh_rkey();
            let seq = self.fresh_seq(owner);
            self.keystore.entry(owner).or_default().insert(rkey);
            batch.push(OfferedKp { rkey, seq });
        }
        self.ring
            .entry((owner, consumer))
            .or_default()
            .push_back(RingMessage::KpBatch(batch));
    }

    /// Consumer drains inbound ring messages from `owner`. KP batches go
    /// into the pool (deduped by seq); Welcomes are not expected on this
    /// direction.
    fn consumer_drain_inbound(&mut self, consumer: DeviceId, owner: DeviceId) {
        let mut pending = VecDeque::new();
        std::mem::swap(
            &mut pending,
            self.ring.entry((owner, consumer)).or_default(),
        );
        while let Some(msg) = pending.pop_front() {
            match msg {
                RingMessage::KpBatch(batch) => {
                    let mut highest = self
                        .highest_seq_observed
                        .get(&(consumer, owner))
                        .copied()
                        .unwrap_or(Seq(0));
                    for kp in batch {
                        if kp.seq <= highest {
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
                other => self
                    .failures
                    .push(format!("consumer got non-batch msg: {other:?}")),
            }
        }
    }

    /// Owner drains inbound ring messages from `consumer`. Welcomes get
    /// processed (init key consumed); `KpRequest` triggers a fresh
    /// `publish_and_offer`.
    fn owner_drain_inbound(&mut self, owner: DeviceId, consumer: DeviceId) {
        let mut pending = VecDeque::new();
        std::mem::swap(
            &mut pending,
            self.ring.entry((consumer, owner)).or_default(),
        );
        while let Some(msg) = pending.pop_front() {
            match msg {
                RingMessage::Welcome(w) => {
                    let ks = self.keystore.entry(owner).or_default();
                    if !ks.remove(&w.init_kp) {
                        self.failures.push(format!(
                            "owner {owner:?} cannot process welcome for init_kp {:?}",
                            w.init_kp
                        ));
                    }
                }
                RingMessage::KpRequest { count } => {
                    self.publish_and_offer(owner, consumer, count as usize);
                }
                RingMessage::KpBatch(_) => self
                    .failures
                    .push("owner got KpBatch from consumer".to_string()),
            }
        }
    }

    fn claim_kp(&mut self, consumer: DeviceId, owner: DeviceId) -> Option<OfferedKp> {
        let pool = self.local_pool.get_mut(&(consumer, owner))?;
        let used = self.used_kps.entry((consumer, owner)).or_default();
        let idx = pool.iter().position(|kp| !used.contains(&kp.seq))?;
        let kp = pool.remove(idx);
        used.insert(kp.seq);
        Some(kp)
    }

    fn consume_and_send_welcome(
        &mut self,
        consumer: DeviceId,
        target: DeviceId,
        kp: OfferedKp,
        group: GroupId,
    ) {
        let id = self.fresh_welcome_id();
        let w = WelcomeMsg {
            id,
            init_kp: kp.rkey,
            group,
        };
        self.ring
            .entry((consumer, target))
            .or_default()
            .push_back(RingMessage::Welcome(w));
    }

    fn pool_size(&self, consumer: DeviceId, owner: DeviceId) -> usize {
        self.local_pool
            .get(&(consumer, owner))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    fn ring_pending(&self, from: DeviceId, to: DeviceId) -> usize {
        self.ring.get(&(from, to)).map(|q| q.len()).unwrap_or(0)
    }

    /// True iff no scenario has reported a failure.
    fn ok(&self) -> bool {
        self.failures.is_empty()
    }
}

// ── Scenarios ────────────────────────────────────────────────────────────────

/// **The full life of a new device, end-to-end.**
///
/// D3 logs in. D1 and D2 are already in the ring with one another, and
/// each has a key package sitting in its public pool. The flow:
///
///   1. D3 draws D1's newest pool record to open a coord group with D1.
///   2. D1 processes that Welcome and replenishes — the replenishment is
///      what makes step 3 possible.
///   3. D3 draws again for the ring add. It must get a *different*
///      record; the first is spent.
///   4. D1 processes the ring Welcome and joins D3's ring.
///   5. Steady state: D3 ships ring KP batches to D1.
///   6. D1 fans D3 out to four user conversations in one tick.
///   7. D3 processes all four Welcomes in one drain.
///
/// Invariant: zero failures.
#[test]
fn hybrid_new_device_end_to_end() {
    let mut m = HybridModel::default();
    m.ring_members_of.insert(RING, [D1, D2].into());

    // 1. D1 and D2 each have one package published. D3 draws D1's for the
    //    coord group. (The coord group and the ring add are two different
    //    MLS groups; the model only distinguishes them by which record
    //    gets burned, which is the part that can go wrong.)
    m.publish_pool_kp(D1);
    m.publish_pool_kp(D2);
    let coord_kp = m.try_bootstrap_add(D3, D1).expect("D1 has a package published");
    m.owner_drain_inbound(D1, D3);
    assert!(m.ok());

    // 2. D1 replenishes on consuming its init key.
    let replenished = m.publish_pool_kp(D1);

    // 3. The ring add draws again and must not re-pick the spent record.
    let ring_kp = m.try_bootstrap_add(D3, D1).expect("D1 replenished");
    assert_ne!(ring_kp, coord_kp, "second draw must skip the record we burned");
    assert_eq!(ring_kp, replenished);

    // 4. D1 processes the ring Welcome.
    m.owner_drain_inbound(D1, D3);
    assert!(m.ok());
    m.ring_members_of.get_mut(&RING).unwrap().insert(D3);

    // Both records are still on the PDS — nothing is ever deleted.
    assert_eq!(m.pds_pool.get(&D1).unwrap().len(), 2);

    // 5. Steady state. D3 ships a KP batch to D1 via the ring.
    m.publish_and_offer(D3, D1, 8);
    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 8);

    // 6. Fan-out in one tick.
    for g in [ALICE_BOB, ALICE_CHARLIE, ALICE_DAVE, ALICE_BOOKCLUB] {
        let kp = m.claim_kp(D1, D3).unwrap();
        m.consume_and_send_welcome(D1, D3, kp, g);
    }
    assert_eq!(m.ring_pending(D1, D3), 4);

    // 7. D3 drains all four in one go.
    m.owner_drain_inbound(D3, D1);
    assert!(m.ok());
    assert_eq!(m.ring_pending(D1, D3), 0);
}

/// **A consumer's repeated draws never return a record it already burned.**
///
/// This is the property the shared pool needs and the dedicated-slot
/// design got for free. One device legitimately draws twice against the
/// same sibling — once for the coord group, once for the ring add — and
/// the newest-record rule alone would hand back the spent one.
#[test]
fn hybrid_repeated_draws_skip_records_we_burned() {
    let mut m = HybridModel::default();

    let kp1 = m.publish_pool_kp(D1);
    assert_eq!(m.fetch_newest_unused_pool_kp(D3, D1), Some(kp1));
    m.bootstrap_add_to_ring(D3, D1, kp1);

    // Nothing new published yet: the pool still holds exactly the record
    // we just spent, so there is nothing to draw.
    assert_eq!(m.pds_pool.get(&D1).unwrap().len(), 1);
    assert_eq!(
        m.fetch_newest_unused_pool_kp(D3, D1),
        None,
        "the only record is spent — defer rather than hand it back",
    );

    // Owner replenishes; the draw resumes and picks the new record.
    let kp2 = m.publish_pool_kp(D1);
    assert_eq!(m.fetch_newest_unused_pool_kp(D3, D1), Some(kp2));

    // Older records are never resurrected even once newer ones exist.
    let kp3 = m.publish_pool_kp(D1);
    m.bootstrap_add_to_ring(D3, D1, kp3);
    assert_eq!(
        m.fetch_newest_unused_pool_kp(D3, D1),
        Some(kp2),
        "newest-unused, so the untouched middle record is next",
    );

    m.owner_drain_inbound(D1, D3);
    assert!(m.ok());
}

/// **The burn record is the only defence against replay.**
///
/// The pool record is never deleted, so a consumer that bypassed its own
/// `used_pool_kps` set and reused a cached rkey would build a Welcome
/// whose init key is already gone from the owner's keystore. Shows the
/// orphan failure the set closes.
#[test]
fn hybrid_replaying_a_burned_record_produces_an_orphan() {
    let mut m = HybridModel::default();

    let kp = m.publish_pool_kp(D1);
    let drawn = m.try_bootstrap_add(D3, D1).unwrap();
    assert_eq!(drawn, kp);
    m.owner_drain_inbound(D1, D3);
    assert!(m.ok());

    // Poll repeatedly: the record still sits on the PDS, and the draw
    // keeps declining it. There is no "first poll after consumption is
    // special" — every poll is gated by the same set.
    for _ in 0..5 {
        assert!(m.fetch_newest_unused_pool_kp(D3, D1).is_none());
        assert!(m.pds_pool.get(&D1).unwrap().contains(&kp));
    }

    // A buggy consumer that cached the rkey and bypassed the set.
    m.bootstrap_add_to_ring(D3, D1, kp);
    m.owner_drain_inbound(D1, D3);
    assert!(
        !m.ok(),
        "bypassing the burn record must surface as a failed receive — it \
         is the only defence against replay under the don't-delete rule",
    );
}

/// **Concurrent consumers race for the same pool record.**
///
/// The inversion the shared pool forces, recorded deliberately: with a
/// dedicated per-consumer slot D1 and D2 held *different* KPs for D3 and
/// could both act. Reading one public pool they see the identical list
/// and pick the identical newest record, so only one of the two Welcomes
/// can ever be processed and the other is silently undeliverable.
///
/// No local rule fixes this — both consumers are behaving correctly. Two
/// different mechanisms serialise the draws: `do_ring_add` elects the
/// smallest-leaf member, while coord-group creation avoids the race
/// entirely by letting only the onboarding device initiate. This test
/// pins the cost of getting either wrong.
#[test]
fn hybrid_concurrent_consumers_race_for_the_same_pool_record() {
    let mut m = HybridModel::default();

    m.publish_pool_kp(D3);

    // Both draw in the same tick, before either burn is visible to the
    // other — burns are local, and the pool has no shared claim.
    let d1_pick = m.fetch_newest_unused_pool_kp(D1, D3).unwrap();
    let d2_pick = m.fetch_newest_unused_pool_kp(D2, D3).unwrap();
    assert_eq!(
        d1_pick, d2_pick,
        "identical list, identical rule → identical record",
    );

    m.bootstrap_add_to_ring(D1, D3, d1_pick);
    m.bootstrap_add_to_ring(D2, D3, d2_pick);

    // D3 drains D1's Welcome first and consumes the init key.
    m.owner_drain_inbound(D3, D1);
    assert!(m.ok());

    // D2's Welcome targets the same, now-spent init key. Draining it
    // surfaces the orphan.
    m.owner_drain_inbound(D3, D2);
    assert!(
        !m.ok(),
        "the losing consumer's Welcome is undeliverable — this is what \
         the add election exists to prevent",
    );
}

/// **A second new device joins after the ring is up.**
///
/// D4 logs in later and draws from the same pools, independently of the
/// ring traffic already established for D3. Distinct records, no
/// disturbance to D3's ring pool.
#[test]
fn hybrid_second_new_device_draws_independently() {
    let mut m = HybridModel::default();

    // D3 is already in the ring with D1 and D2 (modelled by skipping the
    // bootstrap and just establishing a ring KP batch).
    m.publish_and_offer(D3, D1, 4);
    m.consumer_drain_inbound(D1, D3);

    // D4 logs in. D1, D2 and D3 are all siblings with published packages.
    for owner in [D1, D2, D3] {
        m.publish_pool_kp(owner);
    }

    let from_d1 = m.try_bootstrap_add(D4, D1).unwrap();
    m.owner_drain_inbound(D1, D4);
    assert!(m.ok());

    // D3's ring pool from earlier is undisturbed.
    assert_eq!(m.pool_size(D1, D3), 4);

    // D2's and D3's packages are untouched and distinct from D1's.
    let from_d2 = m.fetch_newest_unused_pool_kp(D4, D2).unwrap();
    let from_d3 = m.fetch_newest_unused_pool_kp(D4, D3).unwrap();
    assert_ne!(from_d2, from_d3);
    assert_ne!(from_d1, from_d2);
}

/// **Two new devices joining concurrently.**
///
/// D1 and D2 are already in the ring. D3 and D4 both come online. Each
/// draws from D1's pool to add D1 to its own ring; MLS serialises the
/// commits but the *draws* are independent, so D1 must have replenished
/// between them. The two flows must not cross-contaminate: no shared
/// record, no orphan Welcomes.
#[test]
fn hybrid_two_new_devices_join_concurrently_independent_flows() {
    let mut m = HybridModel::default();
    m.ring_members_of.insert(RING, [D1, D2].into());

    let d1_first = m.publish_pool_kp(D1);
    let d2_first = m.publish_pool_kp(D2);
    assert_ne!(d1_first, d2_first);

    // D3 draws D1's record and adds D1 (epoch N).
    let d3_pick = m.try_bootstrap_add(D3, D1).unwrap();
    assert_eq!(d3_pick, d1_first);
    m.owner_drain_inbound(D1, D3);
    assert!(m.ok());
    m.ring_members_of.get_mut(&RING).unwrap().insert(D3);

    // D1 replenishes on consuming the init key. Without this, D4's draw
    // returns None and D4 defers — correct, but nothing to assert about.
    let d1_second = m.publish_pool_kp(D1);

    // D4 draws (epoch N+1). It gets D1's *replenished* record, not D3's.
    let d4_pick = m.try_bootstrap_add(D4, D1).unwrap();
    assert_eq!(d4_pick, d1_second);
    assert_ne!(d4_pick, d3_pick);
    m.owner_drain_inbound(D1, D4);
    assert!(m.ok());
    m.ring_members_of.get_mut(&RING).unwrap().insert(D4);

    // Final state: ring has all four devices. D1 has burned both of its
    // published init keys; both records remain on the PDS.
    assert_eq!(m.ring_members_of.get(&RING).unwrap().len(), 4);
    assert!(m.keystore.get(&D1).unwrap().is_empty());
    assert_eq!(m.pds_pool.get(&D1).unwrap().len(), 2);

    // Burn sets are per-consumer and independent.
    assert!(m.used_pool_kps.get(&D3).unwrap().contains(&d3_pick));
    assert!(!m.used_pool_kps.get(&D3).unwrap().contains(&d4_pick));
    assert!(m.used_pool_kps.get(&D4).unwrap().contains(&d4_pick));
    assert!(!m.used_pool_kps.get(&D4).unwrap().contains(&d3_pick));

    // D2's package is untouched — D2 has not been added to anything yet.
    assert_eq!(m.fetch_newest_unused_pool_kp(D3, D2), Some(d2_first));
}

/// **Mixed trace: bootstrap + ring-transport + replay + refill.**
///
/// Interleaves pool draws and ring-transport actions, replays a KP batch,
/// runs the pool to empty, refills via `KpRequest`, and fans out one more
/// add. Confirms zero failures across the whole sequence.
#[test]
fn hybrid_mixed_trace_holds_invariant() {
    let mut m = HybridModel::default();

    // D3 bootstraps against D1 via the public pool.
    m.publish_pool_kp(D1);
    m.try_bootstrap_add(D3, D1).unwrap();
    m.owner_drain_inbound(D1, D3);

    // Ring KP supply, with a replay of the first batch midway.
    m.publish_and_offer(D3, D1, 3);
    let batch_replay = m.ring.get(&(D3, D1)).unwrap().front().cloned().unwrap();
    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 3);

    // Replay.
    m.ring.get_mut(&(D3, D1)).unwrap().push_back(batch_replay);
    m.consumer_drain_inbound(D1, D3);
    assert_eq!(m.pool_size(D1, D3), 3);

    // Fan-out three adds.
    for g in [ALICE_BOB, ALICE_CHARLIE, ALICE_DAVE] {
        let kp = m.claim_kp(D1, D3).unwrap();
        m.consume_and_send_welcome(D1, D3, kp, g);
    }
    m.owner_drain_inbound(D3, D1);
    assert!(m.ok());

    // Pool now empty; D1 requests a refill, D3 honours it, fan-out one more.
    assert_eq!(m.pool_size(D1, D3), 0);
    m.ring
        .entry((D1, D3))
        .or_default()
        .push_back(RingMessage::KpRequest { count: 2 });
    m.owner_drain_inbound(D3, D1);
    m.consumer_drain_inbound(D1, D3);
    let kp = m.claim_kp(D1, D3).unwrap();
    m.consume_and_send_welcome(D1, D3, kp, ALICE_BOOKCLUB);
    m.owner_drain_inbound(D3, D1);
    assert!(m.ok());
}

/// **Cross-user adds use the very same pool.**
///
/// When bob wants to start a conversation with alice, bob doesn't share a
/// ring with alice — there's no ring transport between them. bob reads
/// alice's public `keyPackage` pool, which since the bootstrap KP lane
/// was removed is the *identical* mechanism siblings use. The single
/// difference is that a cross-user sender draws once per conversation
/// rather than twice per sibling, so it never hits the repeat-draw case.
///
/// Two senders racing for alice's newest record collide exactly as two
/// siblings would; the MLS layer accepts the first commit and the loser
/// retries after alice replenishes.
#[test]
fn hybrid_cross_user_uses_the_same_pool_and_is_still_safe() {
    let mut m = HybridModel::default();

    // Alice (D1) keeps four packages published.
    for _ in 0..4 {
        m.publish_pool_kp(D1);
    }
    assert_eq!(m.pds_pool.get(&D1).unwrap().len(), 4);

    // Four cross-user senders, modelled as distinct consumers, each draw
    // and add. Alice replenishes after each consumption, so each sender
    // gets a live record.
    let mut claimed = Vec::new();
    for i in 0..4u8 {
        let sender = DeviceId(100 + i);
        let kp = m.fetch_newest_unused_pool_kp(sender, D1).unwrap();
        claimed.push(kp);

        let id = m.fresh_welcome_id();
        let w = WelcomeMsg { id, init_kp: kp, group: GroupId(900 + kp.0) };
        m.ring.entry((D2, D1)).or_default().push_back(RingMessage::Welcome(w));
        m.used_pool_kps.entry(sender).or_default().insert(kp);

        // Alice processes it and replenishes, which is what frees the
        // next sender to draw a distinct record.
        m.owner_drain_inbound(D1, D2);
        m.publish_pool_kp(D1);
    }

    assert!(m.ok());
    let distinct: BTreeSet<Rkey> = claimed.iter().copied().collect();
    assert_eq!(distinct.len(), 4, "each sender drew a live, distinct record");
}
