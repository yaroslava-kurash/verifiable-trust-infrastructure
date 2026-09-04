# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.0](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/releases/tag/vti-rooms-v0.1.0) — 2026-09-04


### Added

- **rooms**: Group custody, so a key-holder still has the group tomorrow ([#1248](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/pull/1248))

* feat(rooms): group custody, so a key-holder still has the group tomorrow

  rooms/keys/open opens a record under its epoch's storage key, and an
  agent that lost its group between the welcome and the read has nothing
  to open with. Custody is not an optimisation here; it is the difference
  between an oracle and a demo. This is the layer the delivery handlers
  (dtgwg-trust-tasks-tf#355) and the open oracle both need, landed on its
  own because the choice below is worth reviewing separately from four
  handlers.

  The snapshot takes the provider's whole key-value store rather than
  serializing the group. OpenMLS persists a group THROUGH its storage
  provider rather than as a value you can serialize, and the pieces a
  group needs - its own state, the signature keypair, pending key packages
  - live in that store under keys OpenMLS owns. Reaching in to pick out
  'just the group' would mean reimplementing its layout and re-breaking on
  every upgrade. Taking the map whole is duller and survives the library
  moving.

  RoomIdentity now retains its member DID. The DID is inside the credential
  as opaque bytes, and reaching back in to parse it out would tie custody
  to the credential encoding; cheap to keep, and it keeps the two
  independent.

  Entries are base64url rather than raw byte vectors because a snapshot
  round-trips through JSON, where a Vec<u8> becomes a list of integers -
  an order of magnitude larger and unreadable in a dump.

  Restore fails rather than returning a half-built group. One that loaded
  its store but not its group, or not its signer, would look usable and
  fail at the first read or the first commit, which is the worst time to
  find out.

  What the blob contains is worth being plain about: group secrets. Whoever
  holds it can decrypt everything the group could, up to its epoch. It
  belongs in a keyspace at the same protection level as the key store and
  the credential vault - in a TEE deployment that means the KMS storage
  key, and outside one it means the VTA's data directory is trusted,
  exactly as it already is for those two.

  Four tests, and the first is the one that matters: a group that went to
  disk and came back opens what it sealed before it went. Then the JSON
  round trip, because an in-process-only snapshot would pass that first
  test and fail in a service; the epoch surviving a membership change,
  because an agent that silently falls behind finds out as 'this record
  does not open'; and a snapshot whose store lost the group being refused.

- **rooms**: A member can curate a record ([#1245](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/pull/1245))

retract_record, purge_record, Action::Curate and RecordStatus::{Deprecated,
  Retracted} all existed, were tested, and were unreachable - there was no
  Trust Task that could invoke any of them. A member who had put something
  into a shared room by mistake had no answer.

  Implements rooms/records/curate/0.1 (dtgwg-trust-tasks-tf#354) in both
  hosts, against hand-written wire types until the generated bindings
  publish - the same arrangement the rest of the family shipped under.

  Separate from put for two reasons, and the second is load-bearing. A
  record's standing is not its content: on a sealed tier the host cannot
  read what it stores, so 'replace this with the same body, marked
  deprecated' would make a member re-seal and re-upload bytes the host
  already holds, to say something that is not about the bytes. And curate
  is its own authority action, deliberately not implied by write - deciding
  what a room's shared knowledge is worth is a different grant from being
  able to add to it. A test drives that end to end: the fixture's agent
  chain confers read alone, so an agent that can read a room cannot demote
  what a person wrote in it.

  Retraction is a tombstone, not an erasure. The body goes; the key,
  version and epoch stay, because that is what makes incremental sync
  converge - a caller that never saw the tombstone resurrects the record on
  its next full rebuild, which is why list returns them. A test retracts
  and then asserts the listing still reports it while the body is gone.
  Restoring a retracted record is refused rather than reported as a success
  that restored nothing.

  A demotion keeps its body. deprecated means demote in recall, not hide -
  an agent that could no longer read a deprecated record could not explain
  why it ranked it lower.

  Every curation assigns a new version. A change others are expected to
  converge on is a change like any other, and one that left the version
  alone would be invisible to every sinceVersion watermark in the room.
  That is also why pinning goes through this path rather than being a cheap
  side-channel: a pin nobody syncs is a pin only its author can see.

  pinned is orthogonal to status - a room may want its superseded canonical
  decision kept in view - so Record carries both.

  Curation is a write, so a lapsed room refuses it. The gate is the one
  added with the lifecycle, not a second copy.

  The three curation inputs travel as a Curation struct rather than three
  parameters: they are one decision, they land as one version, and clippy's
  argument-count lint was right to ask.

- **rooms**: Audit every room operation, without learning who ([#1244](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/pull/1244))

Room operations wrote no audit entry at all. Every other consequential
  VTC surface does - join, members, credentials, backup - and the VTA has
  a census whose stated position is that a task which did its work and
  left no trace is a gap with no defensible reading. The rooms family was
  that gap.

  Reads are audited alongside writes, and on shared material they are the
  more interesting half: a write log says what a room contains, a read log
  says who has seen it, which is the question an incident review actually
  asks. Listing and fetching are distinct actions in the log - both are
   on the authority axis and different events to anyone reading it.

  The part worth the review time is which actor may be recorded.

  Every host has audit machinery and every one of them wants to write the
  acting party's DID into it. On a private room that single line hands the
  host the membership it was built never to learn - assembled one entry at
  a time by the component least able to notice it is doing so. It is a
  silent failure: nothing breaks, no test goes red, and the log looks
  exactly like an attributed room's.

  So the decision is a function in vti_rooms::audit rather than a judgement
  at each host's call sites, and AuditActor has no constructor that takes a
  DID unconditionally. On the disclosing tiers it carries the verified
  subject; on private it carries Member, which is true - the host verified
  a chain, so it knows a member acted - and is the most it may say. A test
  asserts the presenter appears nowhere in a private room's audit trail,
  including in the Debug rendering.

  for_operation takes the AuthorizedAction rather than a presenter string,
  so a host cannot record an actor for an operation it did not authorize,
  and cannot record a different actor from the one it did.

  The record key is recorded on every tier. An opaque key identifies a
  record without describing it, which is exactly why the schema requires
  opacity on the sealed tiers - and why a host logging a descriptive key
  would be logging content.

  Both hosts reach the same decision and differ only in where the trail
  goes. A VTC writes to its hash-chained audit keyspace; room-host has no
  chain and no business growing one - it is a delivery service, and an
  HMAC key store plus a hash chain is most of a community service again -
  so it emits tracing, where an operator's own pipeline collects it. A
  host that logged the DID because its own logging happened to be simpler
  would have handed itself the membership by the back door.

  A failed audit write is logged and swallowed. Refusing an operation that
  already succeeded turns an audit outage into a room outage and tells the
  caller their write failed when it did not; the chain's own hash makes a
  gap visible to a verifier, which is the right place to notice it.

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



### Changed

- **rooms**: Move the group-key and sealing layers into vti-rooms ([#1241](https://github.com/yaroslava-kurash/verifiable-trust-infrastructure/pull/1241))

A VTA must not depend on a VTC client, and rooms/keys/open needs both
  layers inside vta-service - the VTA is what holds the principal's keys
  and opens a record on an agent's behalf. Today they live in vtc-client,
  so that task could not be written at all without a layering inversion.

  vti-rooms is already the shared home for the parts of a room that are not
  a service, and it is where the ciphertext is stored. Putting the AEAD
  binding beside the storage layer that binds to it closes the other half
  of the argument: the associated data commits to roomId | key | version |
  epoch, and until now the code that seals and the code that stores those
  four fields were in different crates. That is how a binding drifts.

  Both live behind an mls feature, off by default, so a host that only
  stores ciphertext still compiles no OpenMLS.

  SealedRoom no longer holds a RoomSession. It holds the room id and the
  group - and the separation is the honest shape rather than a concession
  to the move: the credentials a caller presents travel to the host on
  every request, and the keys never travel anywhere. Pairing them made a
  client the only place a room could be opened.

  The move surfaced a duplication that was invisible while it compiled.
  vtc-client defined its own Visibility, AuthorityPresentation,
  SealedContent, CleartextContent and three response types, plus all five
  Type URI constants - identical to vti-rooms' and with nothing checking
  they stayed identical. The schema-conformance suite added with the open
  tier validates vti-rooms' copies against the published schemas and could
  not see the client's at all, so those could have drifted freely. They are
  re-exports now, which makes the suite cover both.

  RoomKeyError replaces VtcError for this layer, deliberately not
  vti_common::AppError: a record that does not open is a legitimate outcome
  with a specific meaning, and folding it into Internal would say 'this
  service is broken' about the one case the design most wants to be loud -
  a host relocated a record.


