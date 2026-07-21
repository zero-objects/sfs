# Identity Verification (Fingerprints & Safety Numbers)

**Status:** reference · **Since:** Phase 8.1

sfs identities are raw 32-byte Ed25519 (signing) and X25519 (encryption) public
keys. Access control is cryptographic, not server-enforced — the blind SaaS
never vouches for who owns a key. So before you grant read access to a peer, or
adopt a Writer-Set that adds a new writer, you must confirm **out of band** that
the public key you hold really belongs to the person you think it does.
Otherwise a man-in-the-middle who substituted their own key during key exchange
could read your data or write as an authorized member.

A **fingerprint** makes that confirmation practical: it renders a key as a short,
transcription-safe string two humans can read aloud and compare.

## Fingerprint format

`SHA-256("sfs-identity-fingerprint-v1" || pubkey)`, truncated to 160 bits and
rendered as uppercase **Crockford base32** (the alphabet omits `I`, `L`, `O`,
`U` — the characters most often mis-heard or mis-typed), grouped into eight
blocks of four:

```
ABCD-EF12-3GHJ-KMNP-QRST-VWXY-Z012-3456
```

160 bits gives ~2^80 collision resistance — far beyond what a spoken comparison
needs. The rendering is deterministic and stable: the same key always produces
the same fingerprint.

## Where to see it

`sfs-info <container>` prints the container's signing identity fingerprints:

```
Sign mode : writer-set
Owner fpr : ABCD-EF12-...        # the Writer-Set owner
Writers   : 2
  [0]     : ABCD-EF12-...        # each authorized writer
  [1]     : Q7MN-8P0R-...
```

`sfs-info --json` exposes the same under `identity.{sign_mode, signer_fingerprint,
owner_fingerprint, writer_fingerprints}`.

## How to verify (one-directional)

You have a peer's public key (e.g. you are about to `grant_read` to their X25519
key, or add their Ed25519 key to the Writer-Set). Before you do:

1. Compute the fingerprint of the key you hold (e.g. via `sfs-info` on a
   container that lists them, or the `crypto::fingerprint::fingerprint` API).
2. Have the peer read *their* fingerprint aloud over a **trusted channel** — in
   person, a video call where you recognize them, or an already-authenticated
   messenger. Not over the same channel that delivered the key (that channel is
   exactly what a MITM controls).
3. Compare. If every group matches, the key is authentic. If any group differs,
   **stop** — do not grant access; the key may have been substituted.

## How to verify (mutual — safety number)

When two peers want to confirm each other's keys in one comparison, use the
**safety number**: `crypto::fingerprint::safety_number(a_pubkey, b_pubkey)`. It
sorts the two keys before hashing, so both peers compute the **identical** string
regardless of order. Each reads it; a single match confirms *both* keys at once.

## Notes

- Fingerprints are public — they reveal nothing secret and need no
  constant-time handling.
- A fingerprint identifies a key, not a human. It only proves "the key I hold is
  the key my peer holds"; binding that key to a real person is the human step
  (recognize the voice/face on the trusted channel).
- If a peer rotates their identity key, its fingerprint changes and must be
  re-verified — a silent fingerprint change on an existing peer is a red flag.
