# What needs a human

Read this when handing a local test environment over to a person, and suggest
the subset relevant to what changed. Handing someone the whole list every time
teaches them to skim it.

Everything here has one property in common: the HTTP API cannot answer it. It
returns state, not what was drawn, and not whether a sentence reads as success
or as failure.

## The four categories

**Rendering.** Layout under real content — long conversations, wrapped lines,
narrow terminals, images. Bugs here are invisible to tests that use three
short messages, because rows and messages are the same number at that size.

**Wording.** Whether a message explains itself to someone who did not write
it. Empty and zero-valued cases are the ones nobody has read: "nothing to
sync" is easy to word so it sounds like a failure. Failure wording matters
more than success wording, because it is read by someone already confused.

**Feel.** Whether something is pleasant. Does a gesture look inert while it
works? Is a code tolerable to type? Is scrolling smooth? No assertion covers
"felt broken", and "felt broken" is a real defect.

**Wandering.** Ten minutes off-script finds things no checklist contains,
because a checklist can only contain what someone already thought of.

## Before handing over

State plainly: what is running, on which ports, what state it holds, and what
you already verified so they do not repeat it. Then name the specific things
you want judged, and why each one matters.

Where an interaction spans two devices, say which one to watch. People
naturally watch the device they are typing on, which is often the wrong one.

## Questions worth asking about any change

Not a checklist to run top to bottom — prompts for choosing what to ask.

**Any new screen or list**
- Can two items be told apart? Identical names are common in multi-device
  systems, where every device shares a DID and a hostname.
- Are the actions discoverable, or do they depend on knowing a key?
- What does it look like empty? With one item? With a thousand?

**Any long-running operation**
- Does it say anything while it works, or look frozen?
- If it takes longer than a second or two, is there progress or just a wait?
- What happens if it is interrupted — does it resume or start over, and does
  the user find out which?

**Any completion or failure message**
- Read the zero case. Does it sound like success or like something broke?
- Does it name what it acted on? "Received 424 messages from <device>" is
  actionable; "Done" is not.
- If the two sides of an operation disagree, which does the user see?

**Any list that grows**
- Scroll to the very top with a realistic amount of content. Getting stuck
  partway is a common failure of offset arithmetic, and it is silent — there
  is rarely an indication that more exists above.
- Does anything degrade as it gets longer?

**Anything a user types**
- Try typing it, not pasting it. Length and character set matter.
- Is it case-sensitive? Does it tolerate the grouping it was displayed with?

## What not to ask a human to do

If the question is answerable through the HTTP API, it belongs to the agent or
to Beacon, not to a person. Before adding something to a handover, check
whether an existing suite already covers it:

| | |
|---|---|
| send/receive, reactions, images | `two_party_chat`, `image_smoke`, `sync_request_history` |
| pairing, cancel, reject, retry | `two_device_pairing` ×4 runtimes, `pairing_cancelled`, `pairing_rejected`, `pairing_retry_after_abandoned` |
| history sync, both directions | `sync_request_history` ×4, `sync_offer_history`, `three_device_pairing_history_sync` |
| delivery after device fan-out | `post_fan_out_delivery` rr/dr/rd |
| long uninterrupted sends | `sender_exceeds_tag_window` |
| push-only delivery | `push_latency`, `two_party_push`, `proptest_drawbridge` |
| restart catch-up | `two_party_restart`, `proptest_restart`, `proptest_push_restart` |

`ls moat-beacon/src/scenarios/` for the current set — it grows.

If a manual finding is mechanically checkable, the fix is a scenario, not a
line in a checklist. Then it runs in the gate forever instead of depending on
someone remembering.

## Scale

Several classes of defect only appear with real volume and are structurally
invisible to a suite whose conversations are a handful of short lines:
per-item work that rewrites a whole file, offset arithmetic that mixes units,
UI that assumes everything fits, storage that grows faster than expected.

If a change touches storage, sync, or a list, seed a few thousand messages
before handing over. `seed-history.py --messages 2000` costs a couple of
minutes and is the only way these surface before a user finds them.
