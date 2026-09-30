//! `PairChannelDriver` end to end: several devices of one user, each with
//! its own driver, joined by an in-memory relay that plays Drawbridge's
//! rendezvous and pair-WS forwarding.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use moat_core::{
    decode_ring_msg, stealth_pubkey_from_privkey, ConvHistory, DeviceId, DeviceRingState,
    MoatCredential, MoatSession, PairChannelCommand as Cmd, PairChannelDriver, PairEnv,
    PairIdentity, PairingUiState, SiblingStealth, SyncMessage, SyncRequestUiState,
    SYNC_REQUEST_TTL_MS,
};

const DID: &str = "did:plc:alice";
const NOW: i64 = 1_000_000;

struct Device {
    name: &'static str,
    mls: MoatSession,
    ring: DeviceRingState,
    identity: PairIdentity,
    siblings: Vec<SiblingStealth>,
    driver: PairChannelDriver,
    history: BTreeMap<String, Vec<SyncMessage>>,
    /// Ring events this device published, as `(tag, ciphertext)`, oldest
    /// first.
    published: Vec<([u8; 16], Vec<u8>)>,
    /// Hold `LoadHistory` until released, so frames arrive first.
    defer_history: bool,
    deferred_history: Option<[u8; 16]>,
    /// The token of the rendezvous this device is on at the relay.
    on_token: Option<[u8; 16]>,
    admitted: bool,
    joined: bool,
    transfers_completed: usize,
}

impl Device {
    fn new(name: &'static str) -> Self {
        let mls = MoatSession::new();
        let credential = MoatCredential::new(DID, name, *mls.device_id());
        let (_kp, key_bundle) = mls.generate_key_package(&credential).unwrap();
        let mut stealth_priv = [0u8; 32];
        stealth_priv[0] = name.len() as u8 + 1;
        let identity = PairIdentity {
            credential,
            key_bundle,
            stealth_pubkey: stealth_pubkey_from_privkey(&stealth_priv),
        };
        Self {
            name,
            mls,
            ring: DeviceRingState::new(),
            identity,
            siblings: Vec::new(),
            driver: PairChannelDriver::new(),
            history: BTreeMap::new(),
            published: Vec::new(),
            defer_history: false,
            deferred_history: None,
            on_token: None,
            admitted: false,
            joined: false,
            transfers_completed: 0,
        }
    }

    fn with_env<T>(
        &mut self,
        now_ms: i64,
        f: impl FnOnce(&mut PairChannelDriver, &mut PairEnv<'_>) -> T,
    ) -> T {
        let mut env = PairEnv {
            mls: &self.mls,
            ring: &mut self.ring,
            now_ms,
        };
        f(&mut self.driver, &mut env)
    }

    fn device_id(&self) -> DeviceId {
        *self.mls.device_id()
    }

    fn history_for_sync(&self) -> Vec<ConvHistory> {
        self.history
            .iter()
            .map(|(conv_id, messages)| ConvHistory {
                group_id: hex::decode(conv_id).unwrap(),
                messages: messages.clone(),
            })
            .collect()
    }

    fn rkeys(&self, conv_id: &str) -> Vec<String> {
        let mut rkeys: Vec<String> = self
            .history
            .get(conv_id)
            .map(|m| m.iter().map(|m| m.rkey.clone()).collect())
            .unwrap_or_default();
        rkeys.sort();
        rkeys
    }
}

fn message(rkey: &str) -> SyncMessage {
    SyncMessage {
        rkey: rkey.to_string(),
        message_id: None,
        sender_did: DID.to_string(),
        sender_device_name: "laptop".to_string(),
        timestamp_ms: 0,
        content: rkey.to_string(),
        blob_uri: None,
        blob_key: None,
        blob_ciphertext_hash: None,
        blob_ciphertext_size: None,
        blob_content_hash: None,
        blob_mime: None,
        blob_width: None,
        blob_height: None,
        blob_thumbhash: None,
        reactions: Vec::new(),
    }
}

enum Event {
    PairReady { token: [u8; 16] },
    Paired { token: [u8; 16] },
    Frame { token: [u8; 16], data: Vec<u8> },
    Closed { token: [u8; 16] },
}

/// The devices plus a relay that matches offers to joins, forwards frames
/// between the two attached ends, and tells the survivor when one leaves.
struct World {
    devices: Vec<Device>,
    offers: BTreeMap<[u8; 16], usize>,
    joins: BTreeMap<[u8; 16], usize>,
    attached: BTreeMap<[u8; 16], Vec<usize>>,
    queue: VecDeque<(usize, Event)>,
    now_ms: i64,
    /// Drop offers and joins instead of registering them.
    relay_down: bool,
}

impl World {
    fn new(names: &[&'static str]) -> Self {
        Self {
            devices: names.iter().map(|n| Device::new(*n)).collect(),
            offers: BTreeMap::new(),
            joins: BTreeMap::new(),
            attached: BTreeMap::new(),
            queue: VecDeque::new(),
            now_ms: NOW,
            relay_down: false,
        }
    }

    fn peer_of(&self, token: &[u8; 16], idx: usize) -> Option<usize> {
        let offerer = self.offers.get(token).copied();
        let joiner = self.joins.get(token).copied();
        match (offerer, joiner) {
            (Some(o), Some(j)) if o == idx => Some(j),
            (Some(o), Some(j)) if j == idx => Some(o),
            _ => None,
        }
    }

    fn leave(&mut self, idx: usize) {
        let Some(token) = self.devices[idx].on_token.take() else {
            return;
        };
        if let Some(peer) = self.peer_of(&token, idx) {
            if self.devices[peer].on_token == Some(token) {
                self.queue.push_back((peer, Event::Closed { token }));
            }
        }
        self.offers.remove(&token);
        self.joins.remove(&token);
        self.attached.remove(&token);
    }

    fn register(&mut self, idx: usize, token: [u8; 16], offer: bool) {
        if self.relay_down {
            return;
        }
        if self.devices[idx].on_token != Some(token) {
            self.leave(idx);
        }
        self.devices[idx].on_token = Some(token);
        if offer {
            self.offers.insert(token, idx);
        } else {
            self.joins.insert(token, idx);
        }
        if let (Some(&o), Some(&j)) = (self.offers.get(&token), self.joins.get(&token)) {
            self.queue.push_back((o, Event::PairReady { token }));
            self.queue.push_back((j, Event::PairReady { token }));
        }
    }

    fn apply(&mut self, idx: usize, cmds: Vec<Cmd>) {
        for cmd in cmds {
            match cmd {
                Cmd::SendPairOffer { token } => self.register(idx, token, true),
                Cmd::SendPairJoin { token } => self.register(idx, token, false),
                Cmd::ConnectPair { token, .. } => {
                    let ends = self.attached.entry(token).or_default();
                    ends.push(idx);
                    if ends.len() == 2 {
                        let ends = ends.clone();
                        for end in ends {
                            self.queue.push_back((end, Event::Paired { token }));
                        }
                    }
                }
                Cmd::SendFrame { data } => {
                    let token = self.devices[idx]
                        .on_token
                        .expect("sending with no pair channel");
                    let peer = self.peer_of(&token, idx).expect("sending with no peer");
                    self.queue.push_back((peer, Event::Frame { token, data }));
                }
                Cmd::ClosePair | Cmd::DropPair => self.leave(idx),
                Cmd::PublishRingEvent { tag, ciphertext } => {
                    self.devices[idx].published.push((tag, ciphertext))
                }
                Cmd::LoadHistory { token } => {
                    if self.devices[idx].defer_history {
                        self.devices[idx].deferred_history = Some(token);
                    } else {
                        self.provide_history(idx, token);
                    }
                }
                Cmd::StoreMessages { conv_id, messages } => self.devices[idx]
                    .history
                    .entry(conv_id)
                    .or_default()
                    .extend(messages),
                Cmd::SiblingStealthLearned {
                    device_id,
                    scan_pubkey,
                } => {
                    let siblings = &mut self.devices[idx].siblings;
                    siblings.retain(|s| s.device_id != device_id);
                    siblings.push(SiblingStealth {
                        device_id,
                        scan_pubkey,
                    });
                }
                Cmd::DeviceAdmitted { .. } => self.devices[idx].admitted = true,
                Cmd::RingJoined { .. } => self.devices[idx].joined = true,
                Cmd::TransferComplete { .. } => self.devices[idx].transfers_completed += 1,
                Cmd::SaveMlsState
                | Cmd::SaveRingState
                | Cmd::TransferFailed { .. }
                | Cmd::Log(_) => {}
            }
        }
    }

    fn provide_history(&mut self, idx: usize, token: [u8; 16]) {
        let now = self.now_ms;
        let history = self.devices[idx].history_for_sync();
        let cmds =
            self.devices[idx].with_env(now, |d, env| d.provide_history(env, &token, history));
        self.apply(idx, cmds);
    }

    fn release_history(&mut self, idx: usize) {
        let token = self.devices[idx]
            .deferred_history
            .take()
            .expect("no deferred history");
        self.provide_history(idx, token);
        self.run();
    }

    fn run(&mut self) {
        let mut steps = 0;
        while let Some((idx, event)) = self.queue.pop_front() {
            steps += 1;
            assert!(steps < 10_000, "the relay never went quiet");
            let now = self.now_ms;
            let cmds = match event {
                Event::PairReady { token } => self.devices[idx]
                    .driver
                    .on_pair_ready(&token, "wss://relay/pair".into()),
                Event::Paired { token } => {
                    self.devices[idx].with_env(now, |d, env| d.on_paired(env, &token))
                }
                Event::Frame { token, data } => {
                    self.devices[idx].with_env(now, |d, env| d.on_frame(env, &token, data))
                }
                Event::Closed { token } => self.devices[idx]
                    .driver
                    .on_pair_closed(Some(&token), "peer_gone".into()),
            };
            self.apply(idx, cmds);
        }
    }

    fn call(
        &mut self,
        idx: usize,
        f: impl FnOnce(&mut PairChannelDriver, &mut PairEnv<'_>) -> Vec<Cmd>,
    ) {
        let now = self.now_ms;
        let cmds = self.devices[idx].with_env(now, f);
        self.apply(idx, cmds);
        self.run();
    }

    /// `idx` shows a pairing code.
    fn show_code(&mut self, idx: usize) -> String {
        let identity = self.devices[idx].identity.clone();
        let (code, cmds) = self.devices[idx].driver.pair_new(identity);
        self.apply(idx, cmds);
        self.run();
        code
    }

    /// `idx` enters a pairing code.
    fn enter_code(&mut self, idx: usize, code: &str) {
        let identity = self.devices[idx].identity.clone();
        self.call(idx, |d, _| d.pair_confirm(identity, code).unwrap());
    }

    fn approve(&mut self, idx: usize) {
        let siblings = self.devices[idx].siblings.clone();
        self.call(idx, |d, env| d.pair_approve(env, &siblings).unwrap());
    }

    fn request(&mut self, idx: usize) {
        let key_bundle = self.devices[idx].identity.key_bundle.clone();
        self.call(idx, |d, env| {
            d.sync_request(env, &key_bundle, None).unwrap()
        });
    }

    fn offer(&mut self, idx: usize, target: DeviceId) {
        let key_bundle = self.devices[idx].identity.key_bundle.clone();
        self.call(idx, |d, env| {
            d.sync_offer(env, &key_bundle, target).unwrap()
        });
    }

    /// `new_device` shows a code, `existing` enters and approves it.
    fn pair(&mut self, existing: usize, new_device: usize) {
        let code = self.show_code(new_device);
        self.enter_code(existing, &code);
        assert!(matches!(
            self.devices[existing].driver.pairing_ui_state(),
            PairingUiState::AwaitingApproval { .. }
        ));
        self.approve(existing);
        for idx in [existing, new_device] {
            assert!(
                matches!(
                    self.devices[idx].driver.pairing_ui_state(),
                    PairingUiState::Done { .. }
                ),
                "{} did not finish pairing: {:?}",
                self.devices[idx].name,
                self.devices[idx].driver.pairing_ui_state()
            );
        }
    }

    /// Hand `from`'s newest ring event to `to`, as its poll would.
    fn deliver_ring_msg(&mut self, from: usize, to: usize) {
        let (_, ciphertext) = self.devices[from].published.last().unwrap().clone();
        let ring_id = self.devices[to].ring.ring_id().unwrap().to_vec();
        let decrypted = self.devices[to]
            .mls
            .decrypt_event(&ring_id, &ciphertext)
            .unwrap()
            .into_result();
        let msg = decode_ring_msg(&decrypted.event.payload).unwrap();
        let sender = decrypted.sender.unwrap().device_name;
        let own = *self.devices[to].mls.device_id();
        let now = self.now_ms;
        let cmds = self.devices[to].driver.on_ring_msg(msg, sender, &own, now);
        self.apply(to, cmds);
        self.run();
    }

    fn sync_state(&self, idx: usize) -> SyncRequestUiState {
        self.devices[idx].driver.sync_request_ui_state()
    }

    fn pairing_state(&self, idx: usize) -> PairingUiState {
        self.devices[idx].driver.pairing_ui_state()
    }

    fn known_siblings(&self, idx: usize) -> BTreeSet<DeviceId> {
        self.devices[idx]
            .siblings
            .iter()
            .map(|s| s.device_id)
            .collect()
    }
}

const CONV: &str = "c0ffee";

/// A code from a device outside the world, which never joins.
fn stray_code() -> String {
    PairChannelDriver::new()
        .pair_new(Device::new("stray").identity)
        .0
}

fn seed(world: &mut World, idx: usize, rkeys: &[&str]) {
    world.devices[idx]
        .history
        .insert(CONV.to_string(), rkeys.iter().map(|r| message(r)).collect());
}

/// A laptop and a phone, paired, the laptop holding four messages.
fn paired_pair() -> World {
    let mut world = World::new(&["laptop", "phone"]);
    seed(&mut world, 0, &["r1", "r2", "r3", "r4"]);
    world.pair(0, 1);
    world
}

#[test]
fn pairing_hands_the_new_device_its_history() {
    let world = paired_pair();
    assert!(world.devices[0].admitted);
    assert!(world.devices[1].joined);
    assert_eq!(world.devices[1].rkeys(CONV), ["r1", "r2", "r3", "r4"]);
    for device in &world.devices {
        assert_eq!(
            device.transfers_completed, 1,
            "{} never finished its transfer",
            device.name
        );
        assert!(!device.driver.is_transferring());
    }
    assert_eq!(
        world.devices[0].ring.ring_id(),
        world.devices[1].ring.ring_id()
    );
}

#[test]
fn the_approver_learns_the_newcomers_stealth_address() {
    let world = paired_pair();
    let phone = *world.devices[1].mls.device_id();
    assert!(world.devices[0]
        .siblings
        .iter()
        .any(|s| s.device_id == phone));
}

#[test]
fn a_requested_sync_delivers_history_and_names_the_donor() {
    let mut world = paired_pair();
    world.devices[0]
        .history
        .get_mut(CONV)
        .unwrap()
        .push(message("r5"));

    world.request(1);
    world.deliver_ring_msg(1, 0);
    assert!(matches!(
        world.sync_state(0),
        SyncRequestUiState::AwaitingApproval { .. }
    ));
    world.call(0, |d, _| d.sync_accept().unwrap());

    assert_eq!(world.devices[1].rkeys(CONV), ["r1", "r2", "r3", "r4", "r5"]);
    match world.sync_state(1) {
        SyncRequestUiState::Complete { tally, device_name } => {
            assert_eq!(tally.messages, 1);
            assert_eq!(device_name.as_deref(), Some("laptop"));
        }
        other => panic!("expected complete, got {other:?}"),
    }
}

#[test]
fn an_offer_is_joined_without_a_prompt() {
    let mut world = paired_pair();
    world.devices[0]
        .history
        .get_mut(CONV)
        .unwrap()
        .push(message("r5"));
    let phone = world.devices[1].device_id();

    world.offer(0, phone);
    world.deliver_ring_msg(0, 1);

    assert_eq!(world.devices[1].rkeys(CONV), ["r1", "r2", "r3", "r4", "r5"]);
    assert!(matches!(
        world.sync_state(1),
        SyncRequestUiState::Complete { .. }
    ));
}

/// B2: a cancelled pairing is over, so it stops holding the channel.
#[test]
fn a_request_after_a_cancelled_pairing_prompts() {
    let mut world = paired_pair();
    let code = stray_code();
    world.enter_code(0, &code);
    world.call(0, |d, _| d.pair_cancel().unwrap());
    assert!(matches!(
        world.devices[0].driver.pairing_ui_state(),
        PairingUiState::Failed { .. }
    ));

    world.request(1);
    world.deliver_ring_msg(1, 0);

    assert!(matches!(
        world.sync_state(0),
        SyncRequestUiState::AwaitingApproval { .. }
    ));
}

/// B2, the other half: a pairing in flight holds the channel.
#[test]
fn a_request_during_a_pairing_is_ignored() {
    let mut world = paired_pair();
    let code = stray_code();
    world.enter_code(0, &code);

    world.request(1);
    world.deliver_ring_msg(1, 0);

    assert_eq!(world.sync_state(0), SyncRequestUiState::Idle);
    assert_eq!(
        world.devices[0].driver.pairing_ui_state(),
        PairingUiState::AwaitingPeer
    );
}

#[test]
fn a_request_while_one_is_awaiting_approval_is_ignored() {
    let mut world = World::new(&["laptop", "phone", "tablet"]);
    world.pair(0, 1);
    world.pair(0, 2);
    world.request(1);
    world.deliver_ring_msg(1, 0);
    world.request(2);
    world.deliver_ring_msg(2, 0);

    match world.sync_state(0) {
        SyncRequestUiState::AwaitingApproval { device_name } => assert_eq!(device_name, "phone"),
        other => panic!("expected the first prompt to stand, got {other:?}"),
    }
}

#[test]
fn an_expired_request_frees_the_channel() {
    let mut world = World::new(&["laptop", "phone", "tablet"]);
    world.pair(0, 1);
    world.pair(0, 2);
    world.request(0);

    world.now_ms += SYNC_REQUEST_TTL_MS;
    let now = world.now_ms;
    let cmds = world.devices[0].driver.tick(now);
    world.apply(0, cmds);
    assert!(matches!(
        world.sync_state(0),
        SyncRequestUiState::Failed { .. }
    ));

    world.request(1);
    world.deliver_ring_msg(1, 0);
    assert!(matches!(
        world.sync_state(0),
        SyncRequestUiState::AwaitingApproval { .. }
    ));
}

#[test]
fn a_close_for_a_superseded_rendezvous_is_ignored() {
    let mut world = paired_pair();
    world.enter_code(0, &stray_code());
    let old_token = world.devices[0].on_token.unwrap();

    world.request(0);
    let cmds = world.devices[0]
        .driver
        .on_pair_closed(Some(&old_token), "peer_gone".into());
    world.apply(0, cmds);

    assert_eq!(world.sync_state(0), SyncRequestUiState::AwaitingPeer);
}

#[test]
fn a_close_mid_transfer_fails_the_request() {
    let mut world = paired_pair();
    world.devices[0].defer_history = true;
    world.request(1);
    world.deliver_ring_msg(1, 0);
    world.call(0, |d, _| d.sync_accept().unwrap());
    assert!(world.devices[1].driver.is_transferring());

    world.leave(0);
    world.run();

    assert!(matches!(
        world.sync_state(1),
        SyncRequestUiState::Failed { .. }
    ));
    assert!(!world.devices[1].driver.is_transferring());
}

/// The peer's `Hello` can arrive before this side has loaded its history.
#[test]
fn frames_before_the_history_is_loaded_wait_for_it() {
    let mut world = World::new(&["laptop", "phone"]);
    seed(&mut world, 0, &["r1", "r2"]);
    world.devices[1].defer_history = true;
    world.pair(0, 1);
    assert!(world.devices[1].driver.is_transferring());

    world.release_history(1);

    assert_eq!(world.devices[1].rkeys(CONV), ["r1", "r2"]);
    assert!(!world.devices[1].driver.is_transferring());
}

#[test]
fn an_unacknowledged_offer_is_resent_when_the_relay_comes_back() {
    let mut world = paired_pair();
    world.relay_down = true;
    world.request(1);
    world.relay_down = false;

    let cmds = world.devices[1].driver.on_relay_connected();
    assert!(matches!(cmds.as_slice(), [Cmd::SendPairOffer { .. }]));
}

#[test]
fn a_new_gesture_supersedes_a_running_transfer() {
    let mut world = paired_pair();
    world.devices[0].defer_history = true;
    world.request(1);
    world.deliver_ring_msg(1, 0);
    world.call(0, |d, _| d.sync_accept().unwrap());

    let identity = world.devices[0].identity.clone();
    let (_, cmds) = world.devices[0].driver.pair_new(identity);
    assert!(matches!(cmds.first(), Some(Cmd::DropPair)));
    assert!(!world.devices[0].driver.is_transferring());
    assert_eq!(world.sync_state(0), SyncRequestUiState::Idle);
}

#[test]
fn a_third_device_learns_every_existing_siblings_stealth_address() {
    let mut world = World::new(&["laptop", "phone", "tablet"]);
    world.pair(0, 1);
    world.pair(0, 2);
    let [laptop, phone, tablet] = [0, 1, 2].map(|i| world.devices[i].device_id());

    assert_eq!(world.known_siblings(2), BTreeSet::from([laptop, phone]));
    assert_eq!(world.known_siblings(0), BTreeSet::from([phone, tablet]));
    assert_eq!(
        world.devices[2].ring.ring_id(),
        world.devices[0].ring.ring_id()
    );
}

#[test]
fn rejecting_a_pairing_fails_it_on_both_devices() {
    let mut world = World::new(&["laptop", "phone"]);
    let code = world.show_code(1);
    world.enter_code(0, &code);

    let cmds = world.devices[0].driver.pair_reject().unwrap();
    world.apply(0, cmds);
    world.run();

    for idx in [0, 1] {
        assert!(
            matches!(world.pairing_state(idx), PairingUiState::Failed { .. }),
            "{}: {:?}",
            world.devices[idx].name,
            world.pairing_state(idx)
        );
    }
}

#[test]
fn a_failed_publish_fails_the_request_and_frees_the_channel() {
    let mut world = paired_pair();
    world.request(1);
    let (tag, _) = *world.devices[1].published.last().unwrap();

    let cmds = world.devices[1]
        .driver
        .on_ring_publish_failed(&tag, "pds down".into());
    world.apply(1, cmds);

    assert!(matches!(
        world.sync_state(1),
        SyncRequestUiState::Failed { .. }
    ));
    assert_eq!(world.devices[1].on_token, None);
}

/// A socket from a superseded rendezvous can still reach `paired` after a
/// new gesture has taken the channel.
#[test]
fn a_stale_socket_reaching_paired_does_not_start_the_live_session() {
    let mut world = paired_pair();
    world.enter_code(0, &stray_code());
    let stale = world.devices[0].on_token.unwrap();
    world.request(0);

    let cmds = world.devices[0].with_env(NOW, |d, env| d.on_paired(env, &stale));

    assert!(cmds.iter().all(|c| matches!(c, Cmd::Log(_))), "{cmds:?}");
    assert_eq!(world.sync_state(0), SyncRequestUiState::AwaitingPeer);
    assert!(!world.devices[0].driver.is_transferring());
}
