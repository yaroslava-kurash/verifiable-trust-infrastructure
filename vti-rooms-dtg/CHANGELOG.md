# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.0](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/releases/tag/vti-rooms-dtg-v0.1.0) — 2026-09-04


### Added

- **rooms**: The lifecycle §9 describes, with the host never deciding ([#1242](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/pull/1242))

retention_days was stored and nothing read it. A room, once created, was
  live forever - so §9 of the design note existed entirely on paper.

  Live -> Lapsed -> Dormant -> Reclaimable, and every one of them is undone
  by a single renewal until the last. Lapsed is read-only: nothing is
  destroyed, nothing is even hidden, and the room simply stops accepting
  writes, which is a condition a member can notice and fix.

  The state is computed, never stored. A stored state is a decision
  somebody made and can get wrong; a computed one cannot drift from the
  facts, and there is no code path where a host marks a room dormant. That
  is §9's 'the host never decides' made structural rather than promised: on
  a sealed room the host cannot read the content and inactivity is not
  worthlessness, so it is the worst-placed party to judge.

  Minting an epoch is the renewal. There is no separate verb and there
  should not be one: a renewal that could be called without committing
  would let a room look live while its key material stood still. Admin is
  therefore exempt from the write gate - a gate that refused the one
  operation that escapes it would leave a lapsed room lapsed forever, and
  the exemption holds all the way to Reclaimable, because until the bytes
  are deleted the members' choice is renew or export.

  Two rules the tests pin because they are easy to get subtly wrong.
  Retention runs from the lapse, not from the dormancy notice, or the 90
  days an owner agreed to silently becomes 120. And reclamation never
  happens before the notice, so a retention shorter than the grace window
  skips Dormant rather than reclaiming early - erring later destroys
  nothing, erring earlier destroys a room somebody would have renewed.

  epoch_expires_at is Option, and None means never lapses rather than
  already lapsed. A room stored before this field existed deserialises to
  None, and the other reading would have turned every existing room
  read-only on deploy - the wrong direction for a migration to fail in.

  The design note gains a correction rather than a quiet divergence. §9
  said read activity counts as liveness; the implementation does not do
  that, because a host counting reads to decide a sealed room's lifecycle
  would make it depend on the one signal the host can see - the exact
  correlation the tiers exist to deny, and an access-frequency profile a
  private room's members were promised they would not have. The archive
  case is served by retentionDays, which is the member's own statement of
  how long the room matters.

  Not here, and it cannot be: anchoring renewals in the room's witnessed
  DID log. That log is controlled by the room's DID controller, which is
  the owner, not the host. A host's half of §9 is the above - never
  deciding, and never destroying anything a renewal could have saved.

- **rooms**: Data rooms end to end — storage, dispatch, verification, MLS, and a host ([#1237](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/pull/1237))

* feat(rooms): the data-room storage layer

  A data room is a shared space whose access is governed by credentials the
  room itself issues. This lands the storage and its invariants; the
  Trust-Task dispatch that authorizes operations follows once rooms/* is
  published in the registry (trustoverip/dtgwg-trust-tasks-tf#346) - the
  dispatcher refuses a URI the published registry has no schema for, and
  growing the unspecced allowlist is the wrong fix.

  Written first so that the dispatch layer is a thin wrapper over settled
  behaviour rather than a place where storage decisions get made under time
  pressure.

  The row deliberately carries an owner, a visibility, an epoch and a
  retention period, and NO member list. Not omitted for now - there must not
  be one. The moment this service keeps a roster and consults it, three
  things stop being true at once: the room can no longer move to another
  host without reissuing credentials, this service becomes part of the
  room's membership definition, and a room whose contents we cannot read
  acquires a member list we can.

  Invariants enforced in the store rather than trusted to callers, each with
  a test:

  - An open room refuses ciphertext and a sealed room refuses cleartext, so
    a tier promise cannot be broken by a caller passing the wrong shape.
  - A private room refuses a recorded author: on that tier authorship
    belongs inside the sealed body where only members can read it.
  - A record sealed under a stale epoch is refused, because a reader holding
    the current key could not open it.
  - An epoch advances by exactly one. A gap would leave records sealed under
    an epoch nobody holds a key for; a repeat would let a removed member's
    key open material written after their removal, which is the whole point
    of advancing.
  - Versions are monotonic per room, not per record - one comparable number
    is what a sinceVersion watermark needs. A conflict carries the current
    version so a caller need not re-read, because between a bare rejection
    and the re-read the record can change again.
  - A listing returns tombstones to a watermark caller. Without that a
    puller learns of every create and update and never of a delete, so
    retracted records resurrect on its next full rebuild.
  - Retract and purge are separate verbs: a tombstone keeps the key, version
    and epoch so sync converges and the audit chain holds, and erasure is a
    distinct, higher-trust act.

  Keyspaces registered in ALL and BACKED_UP - the two must partition ALL
  exactly - with the census count moved to 27 and the matching AppState
  fields opened, so the documented ALL-matches-AppState invariant stays
  true rather than merely passing a length check.


