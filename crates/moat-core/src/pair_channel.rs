//! The one owner of a device's Drawbridge pair channel.
//!
//! A device drives one pair-channel session at a time: a pairing, a sync
//! request or offer, or the history transfer either of those hands on to.
//! [`PairChannelDriver`] holds all of them, decides which one a relay event
//! or frame belongs to, and turns every input into [`PairChannelCommand`]s
//! for the host's own I/O. Hosts keep no pair-channel state of their own.
//!
//! The channel is busy while a rendezvous is live, a transfer is running,
//! or a sync request is still waiting on a peer or a decision. A sibling's
//! request or offer that arrives while it is busy is ignored; a gesture of
//! the user's own supersedes whatever held the channel.

use rand::RngCore;

use crate::device_ring::{DeviceId, DeviceRingState, SiblingStealth, KP_POOL_TARGET};
use crate::pairing::{
    PairingCommand, PairingPayload, PairingSession, PairingUiState, SiblingInfo, PAIRING_TOKEN_LEN,
    PAIRING_URI_SCHEME,
};
use crate::sync::{
    decode_sync_msg, encode_sync_msg, ConvHistory, SyncOutput, SyncProgress, SyncSession, SyncTally,
};
use crate::sync_request::{
    encode_ring_msg, RingMsg, SyncFailure, SyncRequestSession, SyncRequestUiState,
};
use crate::{Error, Event, MoatCredential, MoatSession, PairingFrameChannel, Result, SyncMessage};

/// Who this device is, for the steps that need its keys.
#[derive(Debug, Clone)]
pub struct PairIdentity {
    pub credential: MoatCredential,
    pub key_bundle: Vec<u8>,
    /// 32-byte X25519 stealth scan public key.
    pub stealth_pubkey: [u8; 32],
}

/// Local state a driver call may read or change.
pub struct PairEnv<'a> {
    pub mls: &'a MoatSession,
    pub ring: &'a mut DeviceRingState,
    pub identity: &'a PairIdentity,
    /// Other ring members' stealth addresses, for `Admit.roster`.
    pub sibling_stealth: &'a [SiblingStealth],
    pub now_ms: i64,
}

/// Host I/O requested by [`PairChannelDriver`], to be carried out in order.
#[derive(Debug, Clone)]
pub enum PairChannelCommand {
    /// Send `pair_offer{token}` on the main WS.
    SendPairOffer {
        token: [u8; PAIRING_TOKEN_LEN],
    },
    /// Send `pair_join{token}` on the main WS.
    SendPairJoin {
        token: [u8; PAIRING_TOKEN_LEN],
    },
    /// Open the pair WS at `url` and attach with `token`.
    ConnectPair {
        url: String,
        token: [u8; PAIRING_TOKEN_LEN],
    },
    /// Write a sealed frame to the pair WS.
    SendFrame {
        data: Vec<u8>,
    },
    /// Close the pair WS behind the frames already sent.
    ClosePair,
    /// Tear the pair WS down now, and stop resending any unacknowledged
    /// offer or join.
    DropPair,
    /// Publish a ring event to this device's repo and tell the relay.
    /// A failed publish is reported back through
    /// [`PairChannelDriver::on_ring_publish_failed`].
    PublishRingEvent {
        tag: [u8; 16],
        ciphertext: Vec<u8>,
    },
    /// Load this device's settled history for every conversation and hand
    /// it to [`PairChannelDriver::provide_history`] with this token.
    LoadHistory {
        token: [u8; PAIRING_TOKEN_LEN],
    },
    /// Persist messages received by sync.
    StoreMessages {
        conv_id: String,
        messages: Vec<SyncMessage>,
    },
    SaveMlsState,
    SaveRingState,
    /// This device joined the ring through a pairing.
    RingJoined {
        ring_id: Vec<u8>,
    },
    /// This device admitted a new device into the ring, whose epoch has
    /// advanced; the newcomer is owed its conversations.
    DeviceAdmitted {
        ring_id: Vec<u8>,
    },
    /// A sibling's stealth address, learned from the pairing exchange.
    SiblingStealthLearned {
        device_id: DeviceId,
        scan_pubkey: [u8; 32],
    },
    /// A history transfer finished.
    TransferComplete {
        tally: SyncTally,
    },
    /// A history transfer ended early. `during_pairing` when it was the
    /// one a pairing hands on to, whose pairing now reports as failed.
    TransferFailed {
        detail: String,
        during_pairing: bool,
    },
    /// A line for the host's debug log.
    Log(String),
}

use PairChannelCommand as Cmd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    Pairing,
    SyncRequest,
}

/// The rendezvous the pair channel is bound to.
#[derive(Debug)]
struct Rendezvous {
    token: [u8; PAIRING_TOKEN_LEN],
    /// `pair_offer` rather than `pair_join`.
    offer: bool,
    owner: Owner,
    /// The relay answered with `pair_ready`.
    acknowledged: bool,
}

#[derive(Debug)]
struct Transfer {
    channel: PairingFrameChannel,
    origin: Owner,
    /// `None` until the host provides history.
    session: Option<SyncSession>,
    /// Frames that arrived before the session could be built.
    buffered: Vec<Vec<u8>>,
}

/// See the module docs.
#[derive(Debug, Default)]
pub struct PairChannelDriver {
    /// Kept once terminal so its outcome stays reportable.
    pairing: Option<PairingSession>,
    /// Kept once terminal so its outcome stays reportable.
    sync_request: Option<SyncRequestSession>,
    rendezvous: Option<Rendezvous>,
    transfer: Option<Transfer>,
    /// Tag of our own published sync request or offer.
    published_tag: Option<[u8; 16]>,
}

impl PairChannelDriver {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Projections ──────────────────────────────────────────────────────────

    pub fn pairing_ui_state(&self) -> PairingUiState {
        self.pairing
            .as_ref()
            .map_or(PairingUiState::Idle, PairingSession::ui_state)
    }

    /// The pairing's role: `Some(true)` for the new device.
    pub fn pairing_is_new_device(&self) -> Option<bool> {
        self.pairing.as_ref().map(PairingSession::is_new_device)
    }

    pub fn sync_request_ui_state(&self) -> SyncRequestUiState {
        SyncRequestSession::ui_state_of(self.sync_request.as_ref())
    }

    /// `true` while a history transfer holds the channel.
    pub fn is_transferring(&self) -> bool {
        self.transfer.is_some()
    }

    /// How far the running transfer has got; `None` when none is running.
    pub fn progress(&self) -> Option<SyncProgress> {
        let transfer = self.transfer.as_ref()?;
        Some(
            transfer
                .session
                .as_ref()
                .map_or(SyncProgress::Starting, SyncSession::progress),
        )
    }

    fn busy(&self, now_ms: i64) -> bool {
        self.rendezvous.is_some()
            || self.transfer.is_some()
            || self
                .sync_request
                .as_ref()
                .is_some_and(|s| !s.is_terminal() && !s.is_expired(now_ms))
    }

    fn live_token(&self) -> Option<[u8; PAIRING_TOKEN_LEN]> {
        self.rendezvous.as_ref().map(|r| r.token)
    }

    // ── User gestures ────────────────────────────────────────────────────────

    /// New device: start a pairing and return the code to show.
    pub fn pair_new(&mut self) -> (String, Vec<PairChannelCommand>) {
        let mut cmds = self.supersede();
        let payload = PairingPayload {
            token: random_bytes(),
            secret: random_bytes(),
        };
        let code = payload.to_text();
        self.pairing = Some(PairingSession::new_device(&payload));
        self.open_rendezvous(payload.token, true, Owner::Pairing, &mut cmds);
        (code, cmds)
    }

    /// Existing device: enter a code, in its text or `moat-pair:` form.
    pub fn pair_confirm(&mut self, code: &str) -> Result<Vec<PairChannelCommand>> {
        let code = code.trim();
        let payload = if code.starts_with(PAIRING_URI_SCHEME) {
            PairingPayload::from_uri(code)?
        } else {
            PairingPayload::from_text(code)?
        };
        let mut cmds = self.supersede();
        self.pairing = Some(PairingSession::existing_device(
            &payload.secret,
            &payload.token,
        ));
        self.open_rendezvous(payload.token, false, Owner::Pairing, &mut cmds);
        Ok(cmds)
    }

    /// Existing device: approve the pending `Enroll`. `Err` only when
    /// there is nothing to approve; a failure while approving fails the
    /// pairing, which [`pairing_ui_state`](Self::pairing_ui_state) reports.
    pub fn pair_approve(&mut self, env: &mut PairEnv<'_>) -> Result<Vec<PairChannelCommand>> {
        let session = self
            .pairing
            .as_mut()
            .filter(|s| s.pending_enroll().is_some())
            .ok_or_else(|| Error::PairingProtocol("no pending Enroll to approve".to_string()))?;
        let existing_ring_id = env.ring.ring_id().map(<[u8]>::to_vec);
        let known_siblings = known_siblings(env);
        // `approve` consumes the Enroll, and `Admit.roster` carries only
        // siblings already known, so the newcomer's address is taken here.
        let newcomer = session
            .pending_enroll()
            .map(|e| (*e.credential.device_id(), e.stealth_scan_pubkey));
        let result = session.approve(
            env.mls,
            &env.identity.credential,
            &env.identity.key_bundle,
            env.identity.stealth_pubkey,
            &known_siblings,
            existing_ring_id.as_deref(),
        );
        let ring_id = session.ring_id().map(<[u8]>::to_vec);

        let mut cmds = vec![Cmd::SaveMlsState];
        let pairing_cmds = match result {
            Ok(pairing_cmds) => pairing_cmds,
            Err(e) => {
                cmds.push(Cmd::Log(format!("pairing: approve failed: {e}")));
                self.close_rendezvous(Owner::Pairing, &mut cmds);
                return Ok(cmds);
            }
        };
        if let (Some(ring_id), None) = (&ring_id, &existing_ring_id) {
            if let Err(e) = env
                .ring
                .record_ring_membership(env.mls, ring_id.clone(), env.now_ms)
            {
                cmds.push(Cmd::Log(format!(
                    "pairing: record_ring_membership failed: {e}"
                )));
            }
            cmds.push(Cmd::SaveRingState);
        }
        if let Some((device_id, scan_pubkey)) = newcomer {
            cmds.push(Cmd::SiblingStealthLearned {
                device_id,
                scan_pubkey,
            });
        }
        self.apply_pairing(env, pairing_cmds, &mut cmds);
        if let Some(ring_id) = ring_id {
            cmds.push(Cmd::DeviceAdmitted { ring_id });
        }
        Ok(cmds)
    }

    /// Existing device: decline the pending `Enroll`.
    pub fn pair_reject(&mut self) -> Result<Vec<PairChannelCommand>> {
        let session = self
            .pairing
            .as_mut()
            .ok_or_else(|| Error::PairingProtocol("no active pairing session".to_string()))?;
        session.reject()?;
        let mut cmds = Vec::new();
        self.close_rendezvous(Owner::Pairing, &mut cmds);
        Ok(cmds)
    }

    /// Either role: abandon an in-flight pairing.
    pub fn pair_cancel(&mut self) -> Result<Vec<PairChannelCommand>> {
        let session = self
            .pairing
            .as_mut()
            .ok_or_else(|| Error::PairingProtocol("no active pairing session".to_string()))?;
        session.cancel()?;
        let mut cmds = Vec::new();
        self.close_rendezvous(Owner::Pairing, &mut cmds);
        Ok(cmds)
    }

    /// Ask the user's other devices for history. `target` names one
    /// sibling; `None` asks them all.
    pub fn sync_request(
        &mut self,
        env: &mut PairEnv<'_>,
        target: Option<DeviceId>,
    ) -> Result<Vec<PairChannelCommand>> {
        let token = random_bytes();
        let secret = random_bytes();
        let msg = RingMsg::SyncRequest {
            token,
            secret,
            target_device_id: target,
        };
        let publish = seal_ring_msg(env, &msg)?;
        let mut cmds = self.supersede();
        self.sync_request = Some(SyncRequestSession::request(token, secret, env.now_ms));
        self.start_ring_rendezvous(token, publish, &mut cmds);
        Ok(cmds)
    }

    /// Offer this device's history to `target`, which joins without a
    /// prompt of its own.
    pub fn sync_offer(
        &mut self,
        env: &mut PairEnv<'_>,
        target: DeviceId,
    ) -> Result<Vec<PairChannelCommand>> {
        if &target == env.mls.device_id() {
            return Err(Error::SyncRequestProtocol(
                "cannot offer history to this device".to_string(),
            ));
        }
        let token = random_bytes();
        let secret = random_bytes();
        let msg = RingMsg::SyncOffer {
            token,
            secret,
            target_device_id: target,
        };
        let publish = seal_ring_msg(env, &msg)?;
        let mut cmds = self.supersede();
        self.sync_request = Some(SyncRequestSession::request(token, secret, env.now_ms));
        self.start_ring_rendezvous(token, publish, &mut cmds);
        Ok(cmds)
    }

    /// Serve the sibling whose request is awaiting approval.
    pub fn sync_accept(&mut self) -> Result<Vec<PairChannelCommand>> {
        let session = self
            .sync_request
            .as_mut()
            .ok_or_else(|| Error::SyncRequestProtocol("no sync request to accept".to_string()))?;
        let token = session.accept()?;
        let mut cmds = Vec::new();
        self.drop_channel(&mut cmds);
        self.pairing = None;
        self.open_rendezvous(token, false, Owner::SyncRequest, &mut cmds);
        Ok(cmds)
    }

    /// Refuse the sibling's request. Local only: the requester keeps
    /// waiting for another sibling.
    pub fn sync_decline(&mut self) -> Result<()> {
        let session = self
            .sync_request
            .as_mut()
            .ok_or_else(|| Error::SyncRequestProtocol("no sync request to decline".to_string()))?;
        session.decline();
        Ok(())
    }

    // ── Ring messages ────────────────────────────────────────────────────────

    /// A sibling's `ring.msg`. `sender_name` must come from the sender's
    /// MLS leaf credential.
    pub fn on_ring_msg(
        &mut self,
        msg: RingMsg,
        sender_name: String,
        own_device_id: &DeviceId,
        now_ms: i64,
    ) -> Vec<PairChannelCommand> {
        match msg {
            RingMsg::SyncRequest {
                token,
                secret,
                target_device_id,
            } => {
                if target_device_id.is_some_and(|t| &t != own_device_id) {
                    return vec![Cmd::Log(
                        "sync: ignoring a request addressed elsewhere".into(),
                    )];
                }
                if self.busy(now_ms) {
                    return vec![Cmd::Log(
                        "sync: ignoring a sibling's request — the pair channel is busy".into(),
                    )];
                }
                self.sync_request = Some(SyncRequestSession::received(
                    token,
                    secret,
                    sender_name.clone(),
                    now_ms,
                ));
                vec![Cmd::Log(format!(
                    "sync: {sender_name} is asking for history"
                ))]
            }
            RingMsg::SyncOffer {
                token,
                secret,
                target_device_id,
            } => {
                if &target_device_id != own_device_id {
                    return vec![Cmd::Log(
                        "sync: ignoring an offer addressed elsewhere".into(),
                    )];
                }
                if self.busy(now_ms) {
                    return vec![Cmd::Log(
                        "sync: ignoring an offer — the pair channel is busy".into(),
                    )];
                }
                self.sync_request = Some(SyncRequestSession::accept_offer(token, secret, now_ms));
                let mut cmds = vec![Cmd::Log(format!(
                    "sync: accepting {sender_name}'s offer of history"
                ))];
                self.open_rendezvous(token, false, Owner::SyncRequest, &mut cmds);
                cmds
            }
        }
    }

    /// Publishing our own request or offer failed.
    pub fn on_ring_publish_failed(
        &mut self,
        tag: &[u8; 16],
        detail: String,
    ) -> Vec<PairChannelCommand> {
        let mut cmds = Vec::new();
        if self.published_tag.as_ref() != Some(tag) {
            return cmds;
        }
        if let Some(session) = self.sync_request.as_mut() {
            session.fail(SyncFailure::PublishFailed { detail });
        }
        self.close_rendezvous(Owner::SyncRequest, &mut cmds);
        cmds
    }

    // ── Relay and pair-WS events ─────────────────────────────────────────────

    /// The main WS (re)authenticated: resend an offer or join the relay
    /// has not acknowledged, which it may have lost.
    pub fn on_relay_connected(&self) -> Vec<PairChannelCommand> {
        match &self.rendezvous {
            Some(r) if !r.acknowledged => vec![rendezvous_cmd(r)],
            _ => Vec::new(),
        }
    }

    /// `pair_ready{token, pair_url}` from the relay.
    pub fn on_pair_ready(&mut self, token: &[u8], url: String) -> Vec<PairChannelCommand> {
        match self.rendezvous.as_mut() {
            Some(r) if r.token.as_slice() == token => {
                r.acknowledged = true;
                vec![Cmd::ConnectPair {
                    url,
                    token: r.token,
                }]
            }
            _ => vec![Cmd::Log(
                "pair: ignoring pair_ready for a superseded rendezvous".into(),
            )],
        }
    }

    /// The pair WS reported `paired`: both ends are attached.
    pub fn on_paired(&mut self, env: &mut PairEnv<'_>) -> Vec<PairChannelCommand> {
        let mut cmds = Vec::new();
        let Some(rendezvous) = self.rendezvous.as_ref() else {
            cmds.push(Cmd::Log("pair: paired with no rendezvous live".into()));
            return cmds;
        };
        let token = rendezvous.token;
        match rendezvous.owner {
            Owner::Pairing => {
                let Some(session) = self.pairing.as_mut() else {
                    return cmds;
                };
                if !session.is_new_device() {
                    cmds.push(Cmd::Log("pairing: paired — waiting for Enroll".into()));
                    return cmds;
                }
                let conv_kps = env
                    .ring
                    .mint_kp_batch(
                        env.mls,
                        &env.identity.credential,
                        &env.identity.key_bundle,
                        KP_POOL_TARGET,
                    )
                    .unwrap_or_default();
                cmds.push(Cmd::SaveRingState);
                let result = session.start_enroll(
                    env.mls,
                    &env.identity.credential,
                    &env.identity.key_bundle,
                    env.identity.stealth_pubkey,
                    conv_kps,
                );
                cmds.push(Cmd::SaveMlsState);
                match result {
                    Ok(pairing_cmds) => self.apply_pairing(env, pairing_cmds, &mut cmds),
                    Err(e) => {
                        cmds.push(Cmd::Log(format!("pairing: start_enroll failed: {e}")));
                        self.close_rendezvous(Owner::Pairing, &mut cmds);
                    }
                }
            }
            Owner::SyncRequest => {
                let channel = self.sync_request.as_mut().and_then(|s| {
                    s.on_channel_up().ok()?;
                    s.transfer_channel()
                });
                match channel {
                    Some(channel) => {
                        self.start_transfer(channel, Owner::SyncRequest, token, &mut cmds)
                    }
                    None => {
                        cmds.push(Cmd::Log(
                            "sync: paired, but no request holds the channel".into(),
                        ));
                        self.fail_origin(Owner::SyncRequest, "not ready to sync".into());
                        self.close_rendezvous(Owner::SyncRequest, &mut cmds);
                    }
                }
            }
        }
        cmds
    }

    /// A binary frame from the pair WS.
    pub fn on_frame(&mut self, env: &mut PairEnv<'_>, data: Vec<u8>) -> Vec<PairChannelCommand> {
        let mut cmds = Vec::new();
        if let Some(transfer) = self.transfer.as_mut() {
            if transfer.session.is_none() {
                transfer.buffered.push(data);
            } else {
                self.transfer_frame(env, data, &mut cmds);
            }
            return cmds;
        }
        let owned_by_pairing = self
            .rendezvous
            .as_ref()
            .is_some_and(|r| r.owner == Owner::Pairing);
        let Some(session) = self
            .pairing
            .as_mut()
            .filter(|s| !s.is_terminal() && owned_by_pairing)
        else {
            cmds.push(Cmd::Log("pair: frame with nothing to receive it".into()));
            return cmds;
        };
        let result = session.on_frame_received(env.mls, &env.identity.credential, &data);
        cmds.push(Cmd::SaveMlsState);
        match result {
            Ok(pairing_cmds) => self.apply_pairing(env, pairing_cmds, &mut cmds),
            Err(e) => {
                cmds.push(Cmd::Log(format!("pairing: frame rejected: {e}")));
                self.close_rendezvous(Owner::Pairing, &mut cmds);
            }
        }
        cmds
    }

    /// The history `LoadHistory` asked for. Ignored if the transfer it was
    /// for has since ended.
    pub fn provide_history(
        &mut self,
        env: &mut PairEnv<'_>,
        token: &[u8; PAIRING_TOKEN_LEN],
        history: Vec<ConvHistory>,
    ) -> Vec<PairChannelCommand> {
        let mut cmds = Vec::new();
        if self.live_token().as_ref() != Some(token) {
            return cmds;
        }
        let Some(transfer) = self.transfer.as_mut().filter(|t| t.session.is_none()) else {
            return cmds;
        };
        let (session, outputs) = SyncSession::start(*env.mls.device_id(), history);
        transfer.session = Some(session);
        let buffered = std::mem::take(&mut transfer.buffered);
        self.apply_sync_outputs(env, outputs, &mut cmds);
        for frame in buffered {
            if self.transfer.is_none() {
                break;
            }
            self.transfer_frame(env, frame, &mut cmds);
        }
        cmds
    }

    /// The pair channel for `token` ended: the pair WS closed, or the
    /// relay's `pair_closed` came with no socket to wait for. A notice for
    /// a superseded rendezvous is ignored.
    pub fn on_pair_closed(
        &mut self,
        token: Option<&[u8]>,
        reason: String,
    ) -> Vec<PairChannelCommand> {
        let mut cmds = Vec::new();
        let Some(live) = self.live_token() else {
            cmds.push(Cmd::Log(format!(
                "pair: ignoring close ({reason}) with nothing live"
            )));
            return cmds;
        };
        if token.is_some_and(|t| t != live.as_slice()) {
            cmds.push(Cmd::Log(format!(
                "pair: ignoring close ({reason}) for a superseded session"
            )));
            return cmds;
        }
        cmds.push(Cmd::Log(format!("pair: channel closed: {reason}")));
        self.end_channel(reason, &mut cmds);
        cmds
    }

    /// Sending the offer or join, or connecting the pair WS, failed.
    pub fn on_rendezvous_failed(&mut self, reason: String) -> Vec<PairChannelCommand> {
        let mut cmds = vec![Cmd::Log(format!("pair: rendezvous failed: {reason}"))];
        if self.rendezvous.is_some() {
            self.end_channel(reason, &mut cmds);
        }
        cmds
    }

    /// Expire an unanswered sync request. Driven from the host's tick and
    /// from every status read, since the driver has no clock.
    pub fn tick(&mut self, now_ms: i64) -> Vec<PairChannelCommand> {
        let mut cmds = Vec::new();
        if self
            .sync_request
            .as_mut()
            .is_some_and(|s| s.expire_if_due(now_ms))
        {
            cmds.push(Cmd::Log(
                "sync: request expired with no device answering".into(),
            ));
            self.close_rendezvous(Owner::SyncRequest, &mut cmds);
        }
        cmds
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// A user gesture takes the channel from whatever held it.
    fn supersede(&mut self) -> Vec<PairChannelCommand> {
        let mut cmds = Vec::new();
        self.drop_channel(&mut cmds);
        self.pairing = None;
        self.sync_request = None;
        cmds
    }

    fn drop_channel(&mut self, cmds: &mut Vec<PairChannelCommand>) {
        let had_rendezvous = self.rendezvous.take().is_some();
        let had_transfer = self.transfer.take().is_some();
        self.published_tag = None;
        if had_rendezvous || had_transfer {
            cmds.push(Cmd::DropPair);
        }
    }

    fn open_rendezvous(
        &mut self,
        token: [u8; PAIRING_TOKEN_LEN],
        offer: bool,
        owner: Owner,
        cmds: &mut Vec<PairChannelCommand>,
    ) {
        let rendezvous = Rendezvous {
            token,
            offer,
            owner,
            acknowledged: false,
        };
        cmds.push(rendezvous_cmd(&rendezvous));
        self.rendezvous = Some(rendezvous);
    }

    fn start_ring_rendezvous(
        &mut self,
        token: [u8; PAIRING_TOKEN_LEN],
        (tag, ciphertext): ([u8; 16], Vec<u8>),
        cmds: &mut Vec<PairChannelCommand>,
    ) {
        cmds.push(Cmd::SaveMlsState);
        self.open_rendezvous(token, true, Owner::SyncRequest, cmds);
        self.published_tag = Some(tag);
        cmds.push(Cmd::PublishRingEvent { tag, ciphertext });
    }

    /// Release the rendezvous if `owner` holds it.
    fn close_rendezvous(&mut self, owner: Owner, cmds: &mut Vec<PairChannelCommand>) {
        if self.rendezvous.as_ref().is_some_and(|r| r.owner == owner) {
            self.drop_channel(cmds);
        }
    }

    /// The live channel ended from outside: fail whatever ran on it.
    fn end_channel(&mut self, reason: String, cmds: &mut Vec<PairChannelCommand>) {
        let owner = self.rendezvous.as_ref().map(|r| r.owner);
        if let Some(transfer) = self.transfer.take() {
            self.fail_transfer(transfer.origin, reason, cmds);
        } else {
            match owner {
                Some(Owner::SyncRequest) => {
                    if let Some(session) = self.sync_request.as_mut() {
                        session.fail(SyncFailure::ChannelClosed { detail: reason });
                    }
                }
                Some(Owner::Pairing) => {
                    if let Some(session) = self.pairing.as_mut() {
                        let _ = session.cancel();
                    }
                }
                None => {}
            }
        }
        self.drop_channel(cmds);
    }

    fn fail_transfer(&mut self, origin: Owner, detail: String, cmds: &mut Vec<PairChannelCommand>) {
        cmds.push(Cmd::TransferFailed {
            detail: detail.clone(),
            during_pairing: origin == Owner::Pairing,
        });
        self.fail_origin(origin, detail);
    }

    fn fail_origin(&mut self, origin: Owner, detail: String) {
        match origin {
            Owner::SyncRequest => {
                if let Some(session) = self.sync_request.as_mut() {
                    session.fail(SyncFailure::ChannelClosed { detail });
                }
            }
            Owner::Pairing => {
                if let Some(session) = self.pairing.as_mut() {
                    session.transfer_failed(&detail);
                }
            }
        }
    }

    fn start_transfer(
        &mut self,
        channel: PairingFrameChannel,
        origin: Owner,
        token: [u8; PAIRING_TOKEN_LEN],
        cmds: &mut Vec<PairChannelCommand>,
    ) {
        self.transfer = Some(Transfer {
            channel,
            origin,
            session: None,
            buffered: Vec::new(),
        });
        cmds.push(Cmd::LoadHistory { token });
    }

    fn apply_pairing(
        &mut self,
        env: &mut PairEnv<'_>,
        pairing_cmds: Vec<PairingCommand>,
        cmds: &mut Vec<PairChannelCommand>,
    ) {
        for cmd in pairing_cmds {
            match cmd {
                PairingCommand::SendFrame { ciphertext } => {
                    cmds.push(Cmd::SendFrame { data: ciphertext })
                }
                PairingCommand::SeedKpPool { device_id, kps } => {
                    env.ring.ingest_kp_batch(&device_id, kps);
                    cmds.push(Cmd::SaveRingState);
                }
                PairingCommand::PublishRingCommit { tag, ciphertext } => {
                    cmds.push(Cmd::PublishRingEvent { tag, ciphertext })
                }
                PairingCommand::SurfaceApprovalPrompt { .. } => {}
                PairingCommand::PersistRing { ring_id } => {
                    if env.ring.ring_id() != Some(ring_id.as_slice()) {
                        if let Err(e) =
                            env.ring
                                .record_ring_membership(env.mls, ring_id.clone(), env.now_ms)
                        {
                            cmds.push(Cmd::Log(format!(
                                "pairing: record_ring_membership failed: {e}"
                            )));
                        }
                    }
                    cmds.push(Cmd::SaveRingState);
                    cmds.push(Cmd::RingJoined { ring_id });
                }
                PairingCommand::RosterReceived { roster } => {
                    for sibling in roster {
                        if &sibling.device_id != env.mls.device_id() {
                            cmds.push(Cmd::SiblingStealthLearned {
                                device_id: sibling.device_id,
                                scan_pubkey: sibling.stealth_pubkey,
                            });
                        }
                    }
                }
                PairingCommand::StartSync => {
                    let token = self.live_token();
                    let channel = self
                        .pairing
                        .as_mut()
                        .and_then(PairingSession::transfer_channel);
                    if let (Some(channel), Some(token)) = (channel, token) {
                        self.start_transfer(channel, Owner::Pairing, token, cmds);
                    }
                }
            }
        }
    }

    fn transfer_frame(
        &mut self,
        env: &mut PairEnv<'_>,
        data: Vec<u8>,
        cmds: &mut Vec<PairChannelCommand>,
    ) {
        let Some(transfer) = self.transfer.as_mut() else {
            return;
        };
        // A frame that fails to open ends the channel: its counter is the
        // nonce, and the peer sealed the next one expecting it to advance.
        let payload = match transfer.channel.open(&data) {
            Ok(p) => p,
            Err(e) => return self.abort_transfer(format!("frame failed to open: {e}"), cmds),
        };
        let msg = match decode_sync_msg(&payload) {
            Ok(m) => m,
            Err(e) => return self.abort_transfer(format!("undecodable sync frame: {e}"), cmds),
        };
        let Some(session) = transfer.session.as_mut() else {
            return;
        };
        match session.on_message(msg) {
            Ok(outputs) => self.apply_sync_outputs(env, outputs, cmds),
            // The peer believes it delivered something we did not take.
            Err(e) => self.abort_transfer(format!("protocol error: {e}"), cmds),
        }
    }

    fn apply_sync_outputs(
        &mut self,
        env: &mut PairEnv<'_>,
        outputs: Vec<SyncOutput>,
        cmds: &mut Vec<PairChannelCommand>,
    ) {
        let Some(transfer) = self.transfer.as_mut() else {
            return;
        };
        for output in outputs {
            match output {
                SyncOutput::Send(msg) => {
                    let data = transfer.channel.seal(&encode_sync_msg(&msg));
                    cmds.push(Cmd::SendFrame { data });
                }
                SyncOutput::Store { conv_id, messages } => {
                    cmds.push(Cmd::StoreMessages { conv_id, messages })
                }
            }
        }
        // Closed only after every output: closing mid-list would strand
        // whatever followed.
        let Some(session) = transfer.session.as_ref().filter(|s| s.is_done()) else {
            return;
        };
        let tally = session.tally();
        let peer = session.peer_device_id().copied();
        let origin = transfer.origin;
        self.transfer = None;
        self.rendezvous = None;
        self.published_tag = None;
        cmds.push(Cmd::ClosePair);
        if origin == Owner::SyncRequest {
            let peer_name = env
                .ring
                .ring_id()
                .zip(peer)
                .and_then(|(ring_id, device_id)| {
                    env.mls
                        .member_device_name(ring_id, &device_id)
                        .ok()
                        .flatten()
                });
            if let Some(session) = self.sync_request.as_mut() {
                session.on_complete(tally, peer_name);
            }
        }
        cmds.push(Cmd::TransferComplete { tally });
    }

    fn abort_transfer(&mut self, detail: String, cmds: &mut Vec<PairChannelCommand>) {
        cmds.push(Cmd::Log(format!("sync: {detail}")));
        if let Some(transfer) = self.transfer.take() {
            self.fail_transfer(transfer.origin, detail, cmds);
        }
        self.drop_channel(cmds);
    }
}

fn rendezvous_cmd(r: &Rendezvous) -> PairChannelCommand {
    if r.offer {
        Cmd::SendPairOffer { token: r.token }
    } else {
        Cmd::SendPairJoin { token: r.token }
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// Seal a ring message to the device ring, ready to publish.
fn seal_ring_msg(env: &PairEnv<'_>, msg: &RingMsg) -> Result<([u8; 16], Vec<u8>)> {
    let ring_id = env.ring.ring_id().ok_or_else(|| {
        Error::SyncRequestProtocol("no device ring — pair a device first".to_string())
    })?;
    let epoch = env.mls.get_group_epoch(ring_id)?.unwrap_or(0);
    let event = Event::ring_msg(ring_id.to_vec(), epoch, encode_ring_msg(msg));
    let encrypted = env
        .mls
        .encrypt_event(ring_id, &env.identity.key_bundle, &event)?;
    Ok((encrypted.tag, encrypted.ciphertext))
}

/// Already-known ring siblings, for `Admit.roster`: names from the ring's
/// member credentials, stealth keys from the host's cache.
fn known_siblings(env: &PairEnv<'_>) -> Vec<SiblingInfo> {
    let Some(ring_id) = env.ring.ring_id() else {
        return Vec::new();
    };
    let members = env.mls.get_group_members(ring_id).unwrap_or_default();
    env.sibling_stealth
        .iter()
        .filter_map(|s| {
            let device_name = members
                .iter()
                .filter_map(|(_, cred)| cred.as_ref())
                .find(|c| c.device_id() == &s.device_id)?
                .device_name()
                .to_string();
            Some(SiblingInfo {
                device_id: s.device_id,
                device_name,
                stealth_pubkey: s.scan_pubkey,
            })
        })
        .collect()
}
