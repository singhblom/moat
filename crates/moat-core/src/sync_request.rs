//! User-initiated history sync between two established ring members.
//!
//! Onboarding history sync rides the pairing channel: the user carries a
//! code from one device to the other, and the transfer runs inside that
//! session's AEAD. That covers a device's *first* moments, and nothing
//! else. A device already in the ring can still be missing history — the
//! sibling it paired with may not have held it, a conversation may have
//! reached it as a membership-only `UserConvWelcome` after its pairing
//! sync had already finished, or a transfer may have been cut short, and
//! the pairing channel cannot be reopened because its secret is
//! deliberately ephemeral.
//!
//! The answer is the same shape as pairing: make it an explicit gesture.
//! The device that wants history publishes a [`RingMsg::SyncRequest`] on
//! the device ring; every online sibling shows a prompt naming it; the
//! user approves on whichever device they know holds the history, and
//! that device joins the rendezvous. No election, no liveness detector,
//! no policy guessing which sibling has the deepest history — the person
//! holding the devices decides, exactly as they do when pairing.
//!
//! Riding the ring (rather than the stealth sibling lane) buys two
//! things: one publish reaches every sibling, and MLS authenticates the
//! sender, so the prompt can name the requesting device from its leaf
//! credential instead of trusting a field in the payload. The cost is
//! that ring application messages are epoch-bound — a device asleep past
//! the ring's usable epoch window cannot use this lane, and its recourse
//! is to pair again, which is a first-class affordance.
//!
//! The ring message also carries a fresh channel secret, so the transfer
//! itself runs on the same [`PairingFrameChannel`] AEAD as a pairing and
//! never touches ring MLS state.

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::device_ring::DeviceId;
use crate::drawbridge_url::DrawbridgeUrl;
use crate::pairing::{
    derive_pairing_keys, PairingFrameChannel, PairingRole, PAIRING_SECRET_LEN, PAIRING_TOKEN_LEN,
};
use crate::sync::SyncTally;
use crate::{Error, Result};

/// How long a published request stays valid, matching the relay's own
/// token TTL. A prompt that outlived the token would offer the user a
/// rendezvous that can no longer be joined.
pub const SYNC_REQUEST_TTL_MS: i64 = 5 * 60 * 1000;

// ── Wire type ─────────────────────────────────────────────────────────────────

/// An application message on the device ring, MLS-encrypted and published
/// to the PDS under a ring tag (so it also reaches siblings through
/// Drawbridge's tag watch, and survives for one that is merely polling).
///
/// The sender is not named in the payload: it is read from the MLS leaf
/// credential at decrypt time, which is authenticated where a payload
/// field would not be. The payload does name the sender's Drawbridge,
/// where the rendezvous is: the sender registered its token there, so the
/// message is where that fact is known for certain.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RingMsg {
    /// "I am missing history — open a sync channel with me at this
    /// rendezvous token."
    ///
    /// `target_device_id` names one sibling when the user picked a
    /// specific device to ask; `None` is a broadcast, and every sibling
    /// prompts. A sibling that is named but is not the target ignores the
    /// message entirely rather than prompting about someone else's
    /// business.
    SyncRequest {
        #[serde_as(as = "Base64")]
        token: [u8; PAIRING_TOKEN_LEN],
        #[serde_as(as = "Base64")]
        secret: [u8; PAIRING_SECRET_LEN],
        #[serde_as(as = "Option<Base64>")]
        target_device_id: Option<DeviceId>,
        drawbridge_url: DrawbridgeUrl,
    },

    /// "I have history you don't — I am opening a channel; join me."
    ///
    /// The mirror of `SyncRequest`, for when the device holding the
    /// history is the one in the user's hands. Always targeted: an
    /// untargeted offer would have every sibling race for a rendezvous
    /// that admits exactly two, making the winner arbitrary.
    ///
    /// Only one human approves a session, on the side that can judge. For
    /// a request that is the donor; for an offer it is the offerer, who
    /// has already decided. The recipient joins without prompting — the
    /// offer comes from an authenticated ring member that can already
    /// read everything it is about to send.
    SyncOffer {
        #[serde_as(as = "Base64")]
        token: [u8; PAIRING_TOKEN_LEN],
        #[serde_as(as = "Base64")]
        secret: [u8; PAIRING_SECRET_LEN],
        #[serde_as(as = "Base64")]
        target_device_id: DeviceId,
        drawbridge_url: DrawbridgeUrl,
    },
}

/// Encode a [`RingMsg`] to bytes suitable for use as `Event.payload`.
pub fn encode_ring_msg(msg: &RingMsg) -> Vec<u8> {
    serde_json::to_vec(msg).expect("RingMsg serialization should never fail")
}

/// Decode a [`RingMsg`] from `Event.payload` bytes.
pub fn decode_ring_msg(bytes: &[u8]) -> Result<RingMsg> {
    serde_json::from_slice(bytes).map_err(|e| Error::Deserialization(e.to_string()))
}

// ── Session state ─────────────────────────────────────────────────────────────

/// Why a sync session ended badly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncFailure {
    NoAnswer,
    RequestExpired,
    Declined,
    ChannelClosed { detail: String },
    PublishFailed { detail: String },
    /// The rendezvous Drawbridge could not be reached.
    DrawbridgeUnreachable { drawbridge_url: String, detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Requester,
    Responder,
}

/// Presentation projection of [`SyncRequestSession`]. Every host renders
/// this; none derives its own — the same contract [`crate::PairingUiState`]
/// holds for pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SyncRequestUiState {
    /// No sync request in flight. Reported by a host wrapping an
    /// `Option<SyncRequestSession>` when that option is `None`.
    Idle,
    /// Waiting on the rendezvous: either we published a request and no
    /// sibling has joined yet, or we accepted one and are dialling in.
    AwaitingPeer,
    /// A sibling asked for history and the user has not yet decided.
    /// `device_name` comes from the requester's MLS leaf credential.
    AwaitingApproval { device_name: String },
    /// The channel is up and [`crate::SyncSession`] is running on it.
    Active,
    /// Transfer finished, with what it moved.
    ///
    /// The counts are the point: with one donor per gesture, a sync that
    /// transferred nothing and one that transferred everything are
    /// otherwise indistinguishable, and only the first means "try a
    /// different device". `device_name` is the ring member the peer named
    /// in its `Hello`, so it names the device the history actually came
    /// from rather than one the user assumed.
    Complete {
        tally: SyncTally,
        device_name: Option<String>,
    },
    /// Terminal failure, carrying a structured reason. Retained rather
    /// than discarded so a failed sync is distinguishable from a slow one.
    Failed { reason: SyncFailure },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Request published (requester) or accepted (responder); waiting for
    /// the pair channel to come up.
    AwaitingPeer,
    /// Responder only: prompt shown, no decision yet. `drawbridge_url` is
    /// where the requester's rendezvous is.
    AwaitingApproval { device_name: String, drawbridge_url: DrawbridgeUrl },
    /// Pair channel established.
    Active,
    Complete {
        tally: SyncTally,
        device_name: Option<String>,
    },
    Failed { reason: SyncFailure },
}

/// The sync-request gesture as a small state machine.
///
/// Deliberately thinner than [`crate::PairingSession`]: there is no
/// key exchange and no MLS work here. The secret arrived inside an
/// MLS-encrypted ring message, so only ring members hold it; once the
/// channel is up the existing [`crate::SyncSession`] runs on
/// [`transfer_channel`](Self::transfer_channel).
#[derive(Debug)]
pub struct SyncRequestSession {
    phase: Phase,
    role: Role,
    token: [u8; PAIRING_TOKEN_LEN],
    /// Taken once by [`transfer_channel`](Self::transfer_channel).
    channel: Option<PairingFrameChannel>,
    /// When the request was published or received, for TTL comparison.
    started_at_ms: i64,
}

impl SyncRequestSession {
    /// Start a request of our own. The caller publishes
    /// [`RingMsg::SyncRequest`] with this token and secret on the ring, and
    /// registers the same token with the relay via `pair_offer`.
    pub fn request(
        token: [u8; PAIRING_TOKEN_LEN],
        secret: [u8; PAIRING_SECRET_LEN],
        now_ms: i64,
    ) -> Self {
        Self::new(Phase::AwaitingPeer, Role::Requester, token, secret, now_ms)
    }

    /// A sibling offered us history and we are joining its rendezvous.
    ///
    /// No prompt: the offer already carries one human decision, made on
    /// the side that could judge, and the offerer is an authenticated
    /// ring member that can read everything it is about to send. A second
    /// prompt here would ask the user to approve receiving their own
    /// messages.
    pub fn accept_offer(
        token: [u8; PAIRING_TOKEN_LEN],
        secret: [u8; PAIRING_SECRET_LEN],
        now_ms: i64,
    ) -> Self {
        Self::new(Phase::AwaitingPeer, Role::Responder, token, secret, now_ms)
    }

    /// A sibling's request arrived on the ring. `device_name` must come
    /// from the sender's MLS leaf credential, not from the payload.
    pub fn received(
        token: [u8; PAIRING_TOKEN_LEN],
        secret: [u8; PAIRING_SECRET_LEN],
        device_name: String,
        drawbridge_url: DrawbridgeUrl,
        now_ms: i64,
    ) -> Self {
        Self::new(
            Phase::AwaitingApproval { device_name, drawbridge_url },
            Role::Responder,
            token,
            secret,
            now_ms,
        )
    }

    /// The side that published the ring message registered the rendezvous
    /// with `pair_offer`, as a new device does when pairing, and takes
    /// that role's keys.
    fn new(
        phase: Phase,
        role: Role,
        token: [u8; PAIRING_TOKEN_LEN],
        secret: [u8; PAIRING_SECRET_LEN],
        now_ms: i64,
    ) -> Self {
        let channel_role = match role {
            Role::Requester => PairingRole::NewDevice,
            Role::Responder => PairingRole::ExistingDevice,
        };
        Self {
            phase,
            role,
            token,
            channel: Some(PairingFrameChannel::new(
                &derive_pairing_keys(&secret, &token),
                channel_role,
            )),
            started_at_ms: now_ms,
        }
    }

    /// Render the state of an optional session, so hosts don't hand-roll
    /// the `None` case differently from each other.
    pub fn ui_state_of(session: Option<&Self>) -> SyncRequestUiState {
        session.map_or(SyncRequestUiState::Idle, Self::ui_state)
    }

    /// Current projection. Computed fresh, never cached.
    pub fn ui_state(&self) -> SyncRequestUiState {
        match &self.phase {
            Phase::AwaitingPeer => SyncRequestUiState::AwaitingPeer,
            Phase::AwaitingApproval { device_name, .. } => {
                SyncRequestUiState::AwaitingApproval { device_name: device_name.clone() }
            }
            Phase::Active => SyncRequestUiState::Active,
            Phase::Complete { tally, device_name } => SyncRequestUiState::Complete {
                tally: *tally,
                device_name: device_name.clone(),
            },
            Phase::Failed { reason } => {
                SyncRequestUiState::Failed { reason: reason.clone() }
            }
        }
    }

    /// The user approved a sibling's request. Returns the token to
    /// `pair_join` with, and the Drawbridge to join it on.
    ///
    /// Refused unless a decision is actually outstanding: approving twice
    /// would dial a rendezvous that already has its two attaches.
    pub fn accept(&mut self) -> Result<([u8; PAIRING_TOKEN_LEN], DrawbridgeUrl)> {
        match &self.phase {
            Phase::AwaitingApproval { drawbridge_url, .. } => {
                let drawbridge_url = drawbridge_url.clone();
                self.phase = Phase::AwaitingPeer;
                Ok((self.token, drawbridge_url))
            }
            _ => Err(Error::SyncRequestProtocol(
                "no sync request is awaiting approval".to_string(),
            )),
        }
    }

    /// The user declined. Purely local: with several siblings prompted,
    /// one decline must not cancel the requester's outstanding request,
    /// so nothing goes on the wire. The requester simply keeps waiting
    /// until another sibling accepts or the token expires.
    pub fn decline(&mut self) {
        self.fail(SyncFailure::Declined);
    }

    /// This session's end of the channel, for the transfer to run on.
    /// `None` until the channel is up, and on every call after the first,
    /// so the counters continue in exactly one place.
    pub fn transfer_channel(&mut self) -> Option<PairingFrameChannel> {
        if self.phase != Phase::Active {
            return None;
        }
        self.channel.take()
    }

    /// The pair channel reached `paired`.
    pub fn on_channel_up(&mut self) -> Result<()> {
        if self.is_terminal() {
            return Err(Error::SyncRequestProtocol(
                "sync request is already finished".to_string(),
            ));
        }
        self.phase = Phase::Active;
        Ok(())
    }

    /// The [`crate::SyncSession`] running on this channel finished.
    ///
    /// `tally` comes from that session; `device_name` is the ring member
    /// the peer named in its `Hello`, `None` if it is not one we know.
    pub fn on_complete(&mut self, tally: SyncTally, device_name: Option<String>) {
        if !self.is_terminal() {
            self.phase = Phase::Complete { tally, device_name };
        }
    }

    /// Terminal failure. The first reason wins: a late teardown notice
    /// must not overwrite the failure that actually explains the outcome,
    /// nor a completed transfer.
    pub fn fail(&mut self, reason: SyncFailure) {
        if !self.is_terminal() {
            self.phase = Phase::Failed { reason };
        }
    }

    /// `true` once the session can no longer change state.
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, Phase::Complete { .. } | Phase::Failed { .. })
    }

    /// Move an unanswered session to `Failed`, if its rendezvous has
    /// outlived the relay's token TTL. Returns `true` only on the call
    /// that actually changed the state, so a host driving this from a
    /// periodic tick has exactly one edge to react to.
    ///
    /// Without this the session sits in `AwaitingPeer` for as long as the
    /// process lives: the state and the TTL both exist, but a clock only
    /// the host has must supply the "now". Nobody answering is by far the
    /// most likely way this ends — the other device is asleep, its app is
    /// closed, its user declined, or it was busy with another sync — and
    /// none of those need telling apart, because the user's next move is
    /// the same for all of them.
    pub fn expire_if_due(&mut self, now_ms: i64) -> bool {
        if !self.is_expired(now_ms) {
            return false;
        }
        // The same expiry, named for whoever is reading it.
        self.fail(match self.role {
            Role::Requester => SyncFailure::NoAnswer,
            Role::Responder => SyncFailure::RequestExpired,
        });
        true
    }

    /// `true` once the rendezvous token has outlived the relay's TTL.
    ///
    /// Only the rendezvous is bounded. A session that reached the channel
    /// is exempt: a large history can legitimately take longer to transfer
    /// than the relay allows for *finding* a peer.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        matches!(self.phase, Phase::AwaitingPeer | Phase::AwaitingApproval { .. })
            && now_ms - self.started_at_ms >= SYNC_REQUEST_TTL_MS
    }
}

#[cfg(test)]
mod tests;
