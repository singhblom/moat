//! Fetched events awaiting processing, and events parked until readable.
//!
//! An event is readable once its tag is a candidate tag. Tags only appear when
//! generated, so an unreadable event is parked under its tag and woken when
//! that tag is generated; nothing is retried. Hosts pop ready events in rkey
//! order, process known tags and park the rest. Events nothing wakes are
//! bounded by [`MAX_PARKED_EVENTS`] and [`MAX_PARKED_AGE_MS`]; such messages
//! predate the device's membership and arrive through history sync.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::error::{Error, Result};

/// The most events kept parked; parking another drops the one parked longest.
pub const MAX_PARKED_EVENTS: usize = 1000;

/// How long an event may stay parked before [`Inbox::expire`] drops it.
pub const MAX_PARKED_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// A fetched `social.moat.event` record.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxEvent {
    /// The DID whose PDS the record was fetched from.
    pub source_did: String,
    pub rkey: String,
    pub author_did: String,
    #[serde_as(as = "Base64")]
    pub tag: [u8; 16],
    #[serde_as(as = "Base64")]
    pub ciphertext: Vec<u8>,
    pub created_at_ms: i64,
}

/// A parked event, with when it was parked.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Parked {
    event: InboxEvent,
    parked_at_ms: i64,
}

type EventId = (String, String);

fn event_id(event: &InboxEvent) -> EventId {
    (event.source_did.clone(), event.rkey.clone())
}

/// See the module documentation.
#[derive(Debug, Default)]
pub struct Inbox {
    /// Events to process next, in rkey order. The source DID breaks ties.
    ready: BTreeMap<(String, String), InboxEvent>,
    /// Parked events in park order; the sequence number breaks ties.
    parked: BTreeMap<(i64, u64), Parked>,
    /// Which parked events carry each tag.
    parked_by_tag: HashMap<[u8; 16], Vec<(i64, u64)>>,
    /// Every event currently ready or parked, so one is never held twice.
    held: HashSet<EventId>,
    next_seq: u64,
}

impl Inbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a fetched event. Returns false if it is already held.
    pub fn push(&mut self, event: InboxEvent) -> bool {
        if !self.held.insert(event_id(&event)) {
            return false;
        }
        self.ready
            .insert((event.rkey.clone(), event.source_did.clone()), event);
        true
    }

    /// The ready event with the lowest rkey.
    pub fn pop_ready(&mut self) -> Option<InboxEvent> {
        let (_, event) = self.ready.pop_first()?;
        self.held.remove(&event_id(&event));
        Some(event)
    }

    /// Park an event until its tag is generated, dropping the oldest past
    /// [`MAX_PARKED_EVENTS`].
    pub fn park(&mut self, event: InboxEvent, now_ms: i64) {
        if !self.held.insert(event_id(&event)) {
            return;
        }
        self.insert_parked(Parked { event, parked_at_ms: now_ms });
        while self.parked.len() > MAX_PARKED_EVENTS {
            self.drop_oldest_parked();
        }
    }

    /// Move events parked under `tags` to the ready queue. Returns the count.
    pub fn wake<'a>(&mut self, tags: impl IntoIterator<Item = &'a [u8; 16]>) -> usize {
        let mut woken = 0;
        for tag in tags {
            let Some(keys) = self.parked_by_tag.remove(tag) else { continue };
            for key in keys {
                if let Some(parked) = self.parked.remove(&key) {
                    let event = parked.event;
                    self.ready
                        .insert((event.rkey.clone(), event.source_did.clone()), event);
                    woken += 1;
                }
            }
        }
        woken
    }

    /// Drop events parked longer than [`MAX_PARKED_AGE_MS`]. Returns the count.
    pub fn expire(&mut self, now_ms: i64) -> usize {
        let mut dropped = 0;
        while let Some((&(parked_at_ms, _), _)) = self.parked.first_key_value() {
            if now_ms.saturating_sub(parked_at_ms) < MAX_PARKED_AGE_MS {
                break;
            }
            self.drop_oldest_parked();
            dropped += 1;
        }
        dropped
    }

    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// Serialize parked events (not ready ones) for the host to persist.
    pub fn export_parked(&self) -> Vec<u8> {
        let parked: Vec<&Parked> = self.parked.values().collect();
        serde_json::to_vec(&parked).expect("parked events serialize")
    }

    /// Restore events from [`Inbox::export_parked`], skipping held ones.
    /// Returns the count.
    pub fn import_parked(&mut self, bytes: &[u8]) -> Result<usize> {
        let parked: Vec<Parked> =
            serde_json::from_slice(bytes).map_err(|e| Error::Deserialization(e.to_string()))?;
        let mut restored = 0;
        for p in parked {
            if self.held.insert(event_id(&p.event)) {
                self.insert_parked(p);
                restored += 1;
            }
        }
        while self.parked.len() > MAX_PARKED_EVENTS {
            self.drop_oldest_parked();
        }
        Ok(restored)
    }

    fn insert_parked(&mut self, parked: Parked) {
        let key = (parked.parked_at_ms, self.next_seq);
        self.next_seq += 1;
        self.parked_by_tag
            .entry(parked.event.tag)
            .or_default()
            .push(key);
        self.parked.insert(key, parked);
    }

    fn drop_oldest_parked(&mut self) {
        let Some((key, parked)) = self.parked.pop_first() else { return };
        self.held.remove(&event_id(&parked.event));
        if let Some(keys) = self.parked_by_tag.get_mut(&parked.event.tag) {
            keys.retain(|k| *k != key);
            if keys.is_empty() {
                self.parked_by_tag.remove(&parked.event.tag);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(rkey: &str, tag: u8) -> InboxEvent {
        InboxEvent {
            source_did: "did:plc:alice".to_string(),
            rkey: rkey.to_string(),
            author_did: "did:plc:alice".to_string(),
            tag: [tag; 16],
            ciphertext: vec![tag, 1, 2],
            created_at_ms: 0,
        }
    }

    fn drain(inbox: &mut Inbox) -> Vec<String> {
        std::iter::from_fn(|| inbox.pop_ready()).map(|e| e.rkey).collect()
    }

    #[test]
    fn ready_events_come_out_in_rkey_order() {
        let mut inbox = Inbox::new();
        inbox.push(event("0003", 1));
        inbox.push(event("0001", 1));
        inbox.push(event("0002", 1));
        assert_eq!(drain(&mut inbox), ["0001", "0002", "0003"]);
    }

    #[test]
    fn a_record_is_held_once() {
        let mut inbox = Inbox::new();
        assert!(inbox.push(event("0001", 1)));
        assert!(!inbox.push(event("0001", 1)));
        assert_eq!(inbox.ready_len(), 1);

        let e = inbox.pop_ready().unwrap();
        inbox.park(e, 0);
        assert!(!inbox.push(event("0001", 1)), "a parked record is still held");
        assert_eq!(inbox.ready_len(), 0);
    }

    #[test]
    fn waking_a_tag_moves_only_the_events_parked_under_it() {
        let mut inbox = Inbox::new();
        inbox.park(event("0001", 1), 0);
        inbox.park(event("0002", 2), 0);
        inbox.park(event("0003", 1), 0);

        assert_eq!(inbox.wake([&[1u8; 16]]), 2);
        assert_eq!(inbox.parked_len(), 1);
        assert_eq!(drain(&mut inbox), ["0001", "0003"]);

        assert_eq!(inbox.wake([&[9u8; 16]]), 0);
        assert_eq!(inbox.parked_len(), 1);
    }

    #[test]
    fn woken_events_take_their_rkey_place_among_ready_ones() {
        let mut inbox = Inbox::new();
        inbox.park(event("0002", 1), 0);
        inbox.push(event("0001", 5));
        inbox.push(event("0003", 5));
        inbox.wake([&[1u8; 16]]);
        assert_eq!(drain(&mut inbox), ["0001", "0002", "0003"]);
    }

    #[test]
    fn parking_past_the_cap_drops_the_event_parked_longest() {
        let mut inbox = Inbox::new();
        for i in 0..MAX_PARKED_EVENTS {
            inbox.park(event(&format!("{i:06}"), 1), i as i64);
        }
        inbox.park(event("newest", 2), MAX_PARKED_EVENTS as i64);

        assert_eq!(inbox.parked_len(), MAX_PARKED_EVENTS);
        inbox.wake([&[1u8; 16], &[2u8; 16]]);
        let rkeys = drain(&mut inbox);
        assert!(!rkeys.contains(&"000000".to_string()), "the oldest was not dropped");
        assert!(rkeys.contains(&"newest".to_string()));
        assert!(inbox.push(event("000000", 1)), "a dropped record is no longer held");
    }

    #[test]
    fn expiry_drops_only_events_parked_too_long() {
        let mut inbox = Inbox::new();
        let now = 10 * MAX_PARKED_AGE_MS;
        inbox.park(event("0001", 1), now - MAX_PARKED_AGE_MS);
        inbox.park(event("0002", 1), now - MAX_PARKED_AGE_MS + 1);

        assert_eq!(inbox.expire(now), 1);
        assert_eq!(inbox.parked_len(), 1);
        inbox.wake([&[1u8; 16]]);
        assert_eq!(drain(&mut inbox), ["0002"]);
    }

    #[test]
    fn parked_events_round_trip_with_their_park_times() {
        let mut inbox = Inbox::new();
        inbox.park(event("0001", 1), 100);
        inbox.park(event("0002", 2), 200);
        let bytes = inbox.export_parked();

        let mut restored = Inbox::new();
        assert_eq!(restored.import_parked(&bytes).unwrap(), 2);
        assert_eq!(restored.import_parked(&bytes).unwrap(), 0, "already held");
        assert_eq!(restored.expire(100 + MAX_PARKED_AGE_MS), 1);

        restored.wake([&[1u8; 16], &[2u8; 16]]);
        let e = restored.pop_ready().unwrap();
        assert_eq!(e, event("0002", 2));
        assert!(restored.pop_ready().is_none());
    }
}
