# Internal Payload Lexicons

These lexicons document the encrypted payload formats inside Moat's ATProto records.
They are **not** ATProto records themselves—they describe the structure of data
that observers cannot see.

## Why document these?

The public lexicons (`social.moat.event`, `social.moat.keyPackage`, `social.moat.stealthAddress`)
define what gets published to the PDS. But interoperating clients need to understand
what's *inside* the encrypted blobs to participate in conversations.

## Lexicon Overview

| Lexicon | Description |
|---------|-------------|
| `paddedPayload` | Binary format inside MLS ciphertext: length prefix + JSON + padding |
| `eventPayloads` | Payload semantics for each event kind (message, commit, welcome, checkpoint) |
| `stealthInvite` | ECDH-encrypted invite format for privacy-preserving invitations |
| `tagDerivation` | Algorithm for deriving rotating 16-byte conversation tags |

## Processing Pipeline

### Sending a message

To send a message, the client constructs an `Event` structure with the appropriate `kind`,
`group_id`, `epoch`, and `payload` fields. This structure is serialized to JSON, then
padded to the nearest bucket size (256, 1024, or 4096 bytes) by prepending a 4-byte
big-endian length and appending random bytes. The padded payload is encrypted using
the MLS group key. Finally, a 16-byte tag is derived from the group ID and epoch using
HKDF-SHA256, and the record is published as `social.moat.event`.

### Receiving a message

To receive messages, the client fetches `social.moat.event` records matching its known
conversation tags. For each record, it decrypts the ciphertext using the appropriate
MLS group key, reads the 4-byte length prefix to extract the JSON portion, and parses
the `Event` structure. The `payload` field is then interpreted according to the `kind`
discriminator.

### Stealth invites

Stealth invites bypass MLS encryption because the recipient is not yet part of any group.
The sender generates an ephemeral X25519 keypair, performs ECDH with the recipient's
published scan public key, and derives an encryption key via HKDF-SHA256 with the label
`moat-stealth-v1`. The MLS Welcome message is encrypted using XChaCha20-Poly1305, and
the result is published as `social.moat.event` with a random 16-byte tag.

The recipient scans events by attempting decryption with their stealth private key.
If decryption succeeds, the event was intended for them and contains an MLS Welcome
to join the conversation.

## Ciphersuite

All MLS operations use: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
