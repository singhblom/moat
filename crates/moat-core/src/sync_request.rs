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

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::{Error, Result};

/// Length of the Drawbridge rendezvous token carried in a sync request.
/// Matches `PAIRING_TOKEN_LEN` — it is the same relay mechanism.
pub const SYNC_REQUEST_TOKEN_LEN: usize = 16;

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
/// field would not be.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RingMsg {
    /// "I am missing history — one of you please open a sync channel with
    /// me at this rendezvous token."
    SyncRequest {
        #[serde_as(as = "Base64")]
        token: [u8; SYNC_REQUEST_TOKEN_LEN],
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
    /// Transfer finished.
    Complete,
    /// Terminal failure, carrying a structured reason. Retained rather
    /// than discarded so a failed sync is distinguishable from a slow one.
    Failed { reason: SyncFailure },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Request published (requester) or accepted (responder); waiting for
    /// the pair channel to come up.
    AwaitingPeer,
    /// Responder only: prompt shown, no decision yet.
    AwaitingApproval { device_name: String },
    /// Pair channel established.
    Active,
    Complete,
    Failed { reason: SyncFailure },
}

/// The sync-request gesture as a small state machine.
///
/// Deliberately thinner than [`crate::PairingSession`]: there is no
/// key exchange and no MLS work here. Once the channel is up the existing
/// [`crate::SyncSession`] does all of the work, encrypted to the ring —
/// both ends are already ring members, so unlike onboarding there is no
/// need for a channel key derived from a user-carried secret.
#[derive(Debug, Clone)]
pub struct SyncRequestSession {
    phase: Phase,
    role: Role,
    token: [u8; SYNC_REQUEST_TOKEN_LEN],
    /// When the request was published or received, for TTL comparison.
    started_at_ms: i64,
}

impl SyncRequestSession {
    /// Start a request of our own. The caller publishes
    /// [`RingMsg::SyncRequest`] with this token on the ring and registers
    /// the same token with the relay via `pair_offer`.
    pub fn request(token: [u8; SYNC_REQUEST_TOKEN_LEN], now_ms: i64) -> Self {
        Self {
            phase: Phase::AwaitingPeer,
            role: Role::Requester,
            token,
            started_at_ms: now_ms,
        }
    }

    /// A sibling's request arrived on the ring. `device_name` must come
    /// from the sender's MLS leaf credential, not from the payload.
    pub fn received(
        token: [u8; SYNC_REQUEST_TOKEN_LEN],
        device_name: String,
        now_ms: i64,
    ) -> Self {
        Self {
            phase: Phase::AwaitingApproval { device_name },
            role: Role::Responder,
            token,
            started_at_ms: now_ms,
        }
    }

    /// The rendezvous token this session is bound to.
    pub fn token(&self) -> &[u8; SYNC_REQUEST_TOKEN_LEN] {
        &self.token
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
            Phase::AwaitingApproval { device_name } => {
                SyncRequestUiState::AwaitingApproval { device_name: device_name.clone() }
            }
            Phase::Active => SyncRequestUiState::Active,
            Phase::Complete => SyncRequestUiState::Complete,
            Phase::Failed { reason } => {
                SyncRequestUiState::Failed { reason: reason.clone() }
            }
        }
    }

    /// The user approved a sibling's request. Returns the token to
    /// `pair_join` with.
    ///
    /// Refused unless a decision is actually outstanding: approving twice
    /// would dial a rendezvous that already has its two attaches.
    pub fn accept(&mut self) -> Result<[u8; SYNC_REQUEST_TOKEN_LEN]> {
        match self.phase {
            Phase::AwaitingApproval { .. } => {
                self.phase = Phase::AwaitingPeer;
                Ok(self.token)
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

    /// The [`crate::SyncSession`] running on this channel reported
    /// `Complete`.
    pub fn on_complete(&mut self) {
        if !self.is_terminal() {
            self.phase = Phase::Complete;
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
        matches!(self.phase, Phase::Complete | Phase::Failed { .. })
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
