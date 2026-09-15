//! The inbox as a host drives it: events arrive in any order and are
//! processed once their tag becomes a candidate tag.

use moat_core::{ControlKind, Event, EventKind, InboxEvent, MoatCredential, MoatSession};

const NOW: i64 = 1_800_000_000_000;

struct Member {
    session: MoatSession,
    bundle: Vec<u8>,
    key_package: Vec<u8>,
}

fn member(did: &str, name: &str) -> Member {
    let session = MoatSession::new();
    let cred = MoatCredential::new(did, name, *session.device_id());
    let (key_package, bundle) = session.generate_key_package(&cred).unwrap();
    Member { session, bundle, key_package }
}

/// Alice's group, with Bob joined and his candidate tags populated.
fn alice_and_bob() -> (Member, Member, Vec<u8>) {
    let alice = member("did:plc:alice", "Alice");
    let bob = member("did:plc:bob", "Bob");
    let cred = MoatCredential::new("did:plc:alice", "Alice", *alice.session.device_id());
    let group_id = alice.session.create_group(&cred, &alice.bundle).unwrap();
    let added = alice
        .session
        .add_member(&group_id, &alice.bundle, &bob.key_package)
        .unwrap();
    bob.session.process_welcome(&added.welcome).unwrap();
    bob.session.populate_candidate_tags(&group_id, &[]).unwrap();
    (alice, bob, group_id)
}

fn fetched(rkey: &str, tag: [u8; 16], ciphertext: Vec<u8>) -> InboxEvent {
    InboxEvent {
        source_did: "did:plc:alice".to_string(),
        rkey: rkey.to_string(),
        author_did: "did:plc:alice".to_string(),
        tag,
        ciphertext,
        created_at_ms: NOW,
    }
}

fn send(alice: &Member, group_id: &[u8], text: &str) -> ([u8; 16], Vec<u8>) {
    let epoch = alice.session.get_group_epoch(group_id).unwrap().unwrap();
    let event = Event::message_from_bytes(group_id.to_vec(), epoch, text.as_bytes());
    let encrypted = alice
        .session
        .encrypt_event(group_id, &alice.bundle, &event)
        .unwrap();
    (encrypted.tag, encrypted.ciphertext)
}

/// What a processed event was, for assertions.
#[derive(Debug, PartialEq)]
enum Seen {
    Commit,
    Message(Vec<u8>),
}

/// The host loop: process ready events with known tags, park the rest.
fn drain(session: &MoatSession) -> Vec<Seen> {
    let mut seen = Vec::new();
    while let Some(event) = session.inbox_pop_ready() {
        let Some(group_id) = session.group_for_tag(&event.tag) else {
            session.inbox_park(event, NOW);
            continue;
        };
        let result = session
            .decrypt_event(&group_id, &event.ciphertext)
            .expect("an event is only attempted once its tag is known")
            .into_result();
        session.advance_scan_window(&event.tag);
        match result.event.kind {
            EventKind::Control(ControlKind::Commit) => {
                session.populate_candidate_tags(&group_id, &[]).unwrap();
                seen.push(Seen::Commit);
            }
            EventKind::Message(_) => seen.push(Seen::Message(result.event.payload.clone())),
            other => panic!("unexpected event kind {other:?}"),
        }
    }
    seen
}

/// The payload a message carrying `text` decrypts to.
fn payload(text: &str) -> Vec<u8> {
    Event::message_from_bytes(Vec::new(), 0, text.as_bytes()).payload
}

#[test]
fn a_message_that_arrives_before_its_commit_is_read_when_the_commit_arrives() {
    let (alice, bob, group_id) = alice_and_bob();
    let carol = member("did:plc:carol", "Carol");
    let add_carol = alice
        .session
        .add_member(&group_id, &alice.bundle, &carol.key_package)
        .unwrap();
    let (msg_tag, msg) = send(&alice, &group_id, "after carol");

    // The message is at the epoch Carol's commit reaches: not readable yet.
    bob.session.inbox_push(fetched("0003", msg_tag, msg));
    assert_eq!(drain(&bob.session), []);
    assert_eq!(bob.session.inbox_parked_len(), 1);

    bob.session
        .inbox_push(fetched("0002", add_carol.commit_tag, add_carol.commit));
    assert_eq!(
        drain(&bob.session),
        [Seen::Commit, Seen::Message(payload("after carol"))]
    );
    assert_eq!(bob.session.inbox_parked_len(), 0);
}

#[test]
fn commits_that_arrive_out_of_order_are_applied_in_order() {
    let (alice, bob, group_id) = alice_and_bob();
    let carol = member("did:plc:carol", "Carol");
    let dave = member("did:plc:dave", "Dave");
    let add_carol = alice
        .session
        .add_member(&group_id, &alice.bundle, &carol.key_package)
        .unwrap();
    let add_dave = alice
        .session
        .add_member(&group_id, &alice.bundle, &dave.key_package)
        .unwrap();

    bob.session
        .inbox_push(fetched("0003", add_dave.commit_tag, add_dave.commit));
    assert_eq!(drain(&bob.session), []);

    bob.session
        .inbox_push(fetched("0002", add_carol.commit_tag, add_carol.commit));
    assert_eq!(drain(&bob.session), [Seen::Commit, Seen::Commit]);
    assert_eq!(
        bob.session.get_group_epoch(&group_id).unwrap(),
        alice.session.get_group_epoch(&group_id).unwrap()
    );
    assert_eq!(bob.session.inbox_parked_len(), 0);
}

#[test]
fn a_message_that_arrives_before_the_welcome_is_read_after_joining() {
    let alice = member("did:plc:alice", "Alice");
    let bob = member("did:plc:bob", "Bob");
    let cred = MoatCredential::new("did:plc:alice", "Alice", *alice.session.device_id());
    let group_id = alice.session.create_group(&cred, &alice.bundle).unwrap();
    let added = alice
        .session
        .add_member(&group_id, &alice.bundle, &bob.key_package)
        .unwrap();
    let (msg_tag, msg) = send(&alice, &group_id, "welcome, bob");

    bob.session.inbox_push(fetched("0002", msg_tag, msg));
    assert_eq!(drain(&bob.session), []);

    // Welcomes arrive outside the inbox; joining populates candidate tags.
    bob.session.process_welcome(&added.welcome).unwrap();
    bob.session.populate_candidate_tags(&group_id, &[]).unwrap();
    assert_eq!(
        drain(&bob.session),
        [Seen::Message(payload("welcome, bob"))]
    );
}

#[test]
fn traffic_this_device_cannot_read_stays_parked_and_is_not_attempted() {
    let (alice, bob, group_id) = alice_and_bob();
    bob.session
        .inbox_push(fetched("0001", [0xAB; 16], vec![0xFF; 64]));
    assert_eq!(drain(&bob.session), []);

    // New tags and a commit don't wake it.
    let carol = member("did:plc:carol", "Carol");
    let add_carol = alice
        .session
        .add_member(&group_id, &alice.bundle, &carol.key_package)
        .unwrap();
    bob.session
        .inbox_push(fetched("0002", add_carol.commit_tag, add_carol.commit));
    assert_eq!(drain(&bob.session), [Seen::Commit]);
    assert_eq!(drain(&bob.session), []);
    assert_eq!(bob.session.inbox_parked_len(), 1);

    // It is only dropped by age.
    assert_eq!(bob.session.inbox_expire(NOW + moat_core::MAX_PARKED_AGE_MS), 1);
    assert_eq!(bob.session.inbox_parked_len(), 0);
}

#[test]
fn parked_events_survive_a_restart() {
    let (alice, bob, group_id) = alice_and_bob();
    let carol = member("did:plc:carol", "Carol");
    let add_carol = alice
        .session
        .add_member(&group_id, &alice.bundle, &carol.key_package)
        .unwrap();
    let (msg_tag, msg) = send(&alice, &group_id, "across a restart");

    bob.session.inbox_push(fetched("0003", msg_tag, msg));
    assert_eq!(drain(&bob.session), []);

    let state = bob.session.export_state().unwrap();
    let parked = bob.session.export_parked_events();
    drop(bob);

    let restarted = MoatSession::from_state(&state).unwrap();
    assert_eq!(restarted.import_parked_events(&parked).unwrap(), 1);
    // Startup populates every group's candidate tags, as hosts do on login.
    restarted.populate_candidate_tags(&group_id, &[]).unwrap();
    assert_eq!(drain(&restarted), [], "the message's epoch is not reached yet");

    restarted.inbox_push(fetched("0002", add_carol.commit_tag, add_carol.commit));
    assert_eq!(
        drain(&restarted),
        [Seen::Commit, Seen::Message(payload("across a restart"))]
    );
}
