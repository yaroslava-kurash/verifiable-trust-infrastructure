# Todo: VTC MVP — Phase 2

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Spec: `docs/05-design-notes/vtc-mvp.md` §§5.4, 6.1–6.3, 7, 10.5, 14.2
Plan: `tasks/vtc-mvp/phase-2-plan.md`

Every code task also drafts the matching Trust Task spec
(`trust-tasks/.../spec.md` + `schema.json`) in the same PR — soft
gate per spec §9.4. Trust Task IDs per plan §D10.

Every PR must be DCO-signed (`git commit -s`) and pass
`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.

---

## M2.1 — `regorus` policy harness

### `[ ]` M2.1.1 — `vtc_service::policy` module

- **Acceptance**
  - `regorus` added to workspace dependencies.
  - New module `vtc_service::policy` with:
    - `Policy` struct (placeholder until M2.2).
    - `CompiledPolicy` wrapping a `regorus::Engine` + the
      source SHA-256 + the policy id.
    - `compile(rego_source: &str, id: Uuid) -> Result<CompiledPolicy,
      AppError>` — compiles, returns descriptive error on
      Rego syntax errors.
    - `evaluate(&CompiledPolicy, query: &str, input: JsonValue)
      -> Result<JsonValue, AppError>` — evaluates a Rego query
      under the given input.
  - 6 unit tests cover happy compile + parse error + evaluate
    with allow + evaluate with deny + missing-rule error +
    deterministic SHA across recompilations.
- **Verify** `cargo test --package vtc-service policy::` green.
- **Files**
  - `Cargo.toml` (workspace `regorus` dep)
  - `vtc-service/Cargo.toml`
  - `vtc-service/src/policy/mod.rs` (new)
  - `vtc-service/src/policy/engine.rs` (new — compile/evaluate)
- **Deps**: none
- **Pre-impl decision**: **D2** (regorus location).

---

## M2.2 — Policy model + `policies` keyspace

### `[ ]` M2.2.1 — `Policy` + storage CRUD

- **Acceptance**
  - `Policy { id, purpose, rego_source, sha256, activated_at:
    Option<DateTime>, author_did, created_at, version: u32 }`
    per spec §5.4.
  - `PolicyPurpose` enum: `Join`, `Removal`, `Personhood`,
    `Registry`, `Directory`, `RoleDefinitions`,
    `CrossCommunityRoles`, `CrossCommunityRelationships`,
    `Relationships` (spec §7.1).
  - `policies:<id>` keyspace stores `Policy` rows.
  - `active_policies:<purpose>` keyspace stores the active
    policy id per purpose (one row per purpose).
  - CRUD helpers: `store_policy`, `get_policy`,
    `list_policies_paginated`, `delete_policy`,
    `get_active_policy_id`, `set_active_policy_id`.
- **Verify** Round-trip every PolicyPurpose; paginated list;
  set + get active pointer.
- **Files**
  - `vtc-service/src/policy/model.rs` (new)
  - `vtc-service/src/policy/storage.rs` (new)
  - `vtc-service/src/server.rs` (AppState gains
    `policies_ks` + `active_policies_ks`)
- **Deps**: M2.1.1
- **Pre-impl decision**: **D3** (storage shape).

---

## M2.3 — Policy admin endpoints

### `[ ]` M2.3.1 — Upload + activate + test

- **Acceptance**
  - `POST /v1/policies` — admin-only. Body `{ purpose,
    rego_source }`. Compiles via M2.1.1; persists Policy row.
    Returns `{ id, sha256 }`. 400 with compiler error on Rego
    parse / type failures.
  - `POST /v1/policies/{id}/activate` — admin-only. Atomic
    swap of the active pointer (D8). Emits `PolicyActivated`
    audit envelope. 409 if already active.
  - `POST /v1/policies/{id}/test` — admin-only. Evaluates the
    candidate policy against a caller-supplied `input` JSON
    **without activating**. Returns the policy's output.
  - Trust Tasks: `policies/upload/1.0`,
    `policies/activate/1.0`, `policies/test/1.0`.
- **Verify** Integration tests cover happy upload + bad-Rego
  rejection + activate-after-upload swaps the active pointer +
  test-without-activate doesn't mutate state.
- **Files**
  - `vtc-service/src/routes/policies/mod.rs` (new)
  - `vtc-service/src/routes/policies/admin.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/policies/{upload,activate,test}/1.0/{spec.md,schema.json}`
- **Deps**: M2.2.1
- **Pre-impl decision**: **D8** (hot-swap atomicity).

---

## M2.4 — Policy read endpoints

### `[ ]` M2.4.1 — List + show

- **Acceptance**
  - `GET /v1/policies` — admin-only. Paginated; ?purpose=
    filter, ?status=active|archived.
  - `GET /v1/policies/{id}` — admin-only. Returns the full
    Policy row including Rego source.
  - Trust Tasks: `policies/list/1.0`, `policies/show/1.0`.
- **Files**
  - `vtc-service/src/routes/policies/read.rs` (new)
  - `trust-tasks/policies/{list,show}/1.0/{spec.md,schema.json}`
- **Deps**: M2.2.1

---

## M2.5 — Default policies

### `[ ]` M2.5.1 — Bundle deny-all / accept-all defaults

- **Acceptance**
  - 9 default Rego policies shipped under
    `vtc-service/policies/default/*.rego` per spec §7.1's table.
  - `policies::default::install_defaults()` writes each one as a
    Policy row + sets the active pointer at first boot. Idempotent.
  - `join.rego` default = allow-any-signed-VP (template
    `policies.open` per §7.1).
  - `personhood.rego` + cross-community defaults = deny-all.
  - `removal.rego` default = "any admin may remove any
    non-admin".
- **Verify** Compile each via M2.1.1 at unit-test time +
  round-trip each input contract → expected output for each
  default.
- **Files**
  - `vtc-service/policies/default/{join,removal,personhood,
    registry,directory,role_definitions,
    cross_community_roles,cross_community_relationships,
    relationships}.rego`
  - `vtc-service/src/policy/default.rs` (new)
  - `vtc-service/src/server.rs` (call `install_defaults` at
    init_auth time)
- **Deps**: M2.3.1

---

## M2.6 — Wire `join.rego` into submit

### `[ ]` M2.6.1 — Policy step at submit time

- **Acceptance**
  - `submit_inner` (existing) extracts `vp_claims` from the
    VP (D4) and evaluates the active `join` policy with input
    `{ applicant_did, vp_claims, action: "join", now }` per
    spec §7.3.
  - `allow` → row persisted with `JoinStatus::Pending` (current
    behaviour).
  - `deny` → row persisted with `JoinStatus::Rejected` +
    `policy_decision` populated with the policy's output JSON.
    Audit event `JoinRequestRejected` instead of
    `JoinRequestSubmitted`.
- **Files**
  - `vtc-service/src/routes/join_requests/submit.rs`
  - `vtc-service/src/policy/extract.rs` (new — VP → vp_claims
    extractor per D4)
- **Deps**: M2.5.1
- **Pre-impl decision**: **D4** (vp_claims extraction).

---

## M2.7 — Wire `removal.rego` into admin-remove

### `[ ]` M2.7.1 — Policy step at admin-remove time

- **Acceptance**
  - `routes::members::remove::admin_remove` evaluates the
    active `removal` policy with input `{ actor_did, target_did,
    target_role, reason, action: "remove", now }`.
  - `deny` → 403 `RemovalDeniedByPolicy` with the policy's
    rationale.
  - `min_disposition` output (Phase 1's plan §D6 placeholder)
    now reads from the policy when caller didn't override.
- **Files**
  - `vtc-service/src/routes/members/remove.rs`
- **Deps**: M2.5.1

---

## M2.8 — `personhood.rego` stub install

Folds into M2.5.1 — no separate milestone. The deny-all stub
ships; assert / revoke endpoints are Phase 4.

---

## M2.9 — VC builder + local signer

### `[ ]` M2.9.1 — `vtc_service::credentials` module

- **Acceptance**
  - `affinidi-vc` + `affinidi-data-integrity` added as
    direct deps.
  - `LocalSigner` wraps the `#key-0` Ed25519 private (read
    from the same `VtcKeyBundle` via the existing secret
    store) and signs data-integrity proofs.
  - `build_vmc(member_did, community_did, status_list_index,
    validity, personhood) -> VerifiableCredential` per spec
    §6.1's VMC shape.
  - `build_role_vec(member_did, role, community_did) ->
    VerifiableCredential` per the §6.1 VEC shape.
  - 8 unit tests covering: VMC happy path; VMC `validUntil`
    pinning; VEC with each `VtcRole`; signature verifies
    against the VTC's public key; tampering invalidates.
- **Files**
  - `vtc-service/src/credentials/mod.rs` (new)
  - `vtc-service/src/credentials/vmc.rs` (new)
  - `vtc-service/src/credentials/vec.rs` (new)
  - `vtc-service/src/credentials/signer.rs` (new)
- **Deps**: none (uses existing key material)
- **Pre-impl decision**: **D1** (local signer; spec §3-A
  amendment).

---

## M2.10 — Status-list infrastructure

### `[ ]` M2.10.1 — `status_lists` keyspace + reserved-index allocator

- **Acceptance**
  - `StatusListState { purpose, capacity, next_random_seed,
    occupied: BitSet, list_credential_id }` per spec §5.6.
  - Random-with-decoys allocator (`affinidi-status-list`'s
    privacy mode).
  - **Flipped indices retained** as occupied so reallocation
    can never reuse them.
  - `StatusListOccupancyWarning` telemetry event at 75%
    live + reserved (spec §6.2).
  - `BitstringStatusListCredential` builder using
    M2.9.1's signer.
- **Verify** Allocator never returns a flipped slot;
  occupancy warning fires at 75%; round-trip
  BitstringStatusList VC + verify.
- **Files**
  - `vtc-service/src/status_list/mod.rs` (new)
  - `vtc-service/src/status_list/storage.rs` (new)
  - `vtc-service/src/status_list/allocator.rs` (new)
  - `vtc-service/src/status_list/credential.rs` (new)
- **Deps**: M2.9.1
- **Pre-impl decision**: **D5** (status-list crypto).

---

## M2.11 — Status-list publication route

### `[ ]` M2.11.1 — `GET /v1/status-lists/{purpose}`

- **Acceptance**
  - Public, unauthenticated, Trust-Task-exempt (verifier-
    facing — same rationale as `/v1/{scid}/did.jsonl`).
  - Path param `purpose ∈ {revocation, suspension}`; other
    values → 404.
  - Returns the latest BitstringStatusList VC as JSON-LD.
  - `Cache-Control: no-store` (status list is live state).
- **Verify** Integration test: route serves the seeded
  status-list VC; unknown purpose 404s; route bypasses
  Trust-Task header check.
- **Files**
  - `vtc-service/src/routes/status_lists.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/status-lists/show/1.0/{spec.md,schema.json}`
- **Deps**: M2.10.1

---

## M2.12 — VMC + VEC issuance on approve

### `[ ]` M2.12.1 — Wire issuance into `decide::approve`

- **Acceptance**
  - On approve: allocate a status-list index (revocation
    purpose), mint VMC + role VEC via M2.9.1, seal-transfer
    to applicant DID via the existing sealed-transfer path
    (vta-sdk's `seal_payload`).
  - Member row gains `status_list_index` + `current_vmc_id` +
    `current_role_vec_id`.
  - Audit emits `VmcIssued` + `VecIssued` alongside the
    existing `JoinRequestApproved` + `MemberAdded`.
- **Files**
  - `vtc-service/src/routes/join_requests/decide.rs`
  - `vti-common/src/audit/event.rs` (`VmcIssued`,
    `VecIssued` variants)
- **Deps**: M2.10.1, M2.5.1

---

## M2.13 — Renewal

### `[ ]` M2.13.1 — `POST /v1/members/me/renew`

- **Acceptance**
  - Authenticated. Caller's DID is the renewal target.
  - Verifies the caller has an active ACL row (spec §6.3 —
    no expiry / grace window check).
  - Re-mints VMC + role VEC via M2.9.1 with `validFrom = now`
    + `validUntil = now + community.membership.validity`.
  - Re-evaluates `personhood.rego` per §6.3 step 3. Phase 2
    deny-all stub means `personhood: false` always.
  - Status-list index reused.
  - Audit emits `MembershipRenewed { personhood_changed }`.
  - Trust Task: `members/renew/1.0`.
- **Files**
  - `vtc-service/src/routes/members/renew.rs` (new)
  - `trust-tasks/members/renew/1.0/{spec.md,schema.json}`
- **Deps**: M2.12.1
- **Pre-impl decision**: **D6** (idempotency cache).

---

## M2.14 — Removal flips revocation bit

### `[ ]` M2.14.1 — Status-list flip on `MemberRemoved`

- **Acceptance**
  - `remove_inner` flips the member's status-list bit
    (revocation purpose) before deleting the ACL row.
  - Re-emits the BitstringStatusList VC (M2.10.1).
  - Audit emits `StatusListFlipped { purpose, index }`.
- **Files**
  - `vtc-service/src/routes/members/remove.rs`
- **Deps**: M2.10.1

---

## M2.15 — DID rotation

### `[ ]` M2.15.1 — `did:key` rotation (challenge + finish)

- **Acceptance**
  - `POST /v1/members/me/rotate/challenge` — auth: old DID's
    session. Returns single-use `rotation_id` + `expires_at`
    (10 min TTL).
  - `POST /v1/members/me/rotate` — auth: **new DID's session**.
    Body carries the rotation payload signed by both old and
    new keys, domain-tag-prefixed with `vtc-did-rotation/v1\0`.
    Atomic:
    - Verify both signatures.
    - Consume the `rotation_id`.
    - Update ACL DID → new.
    - Update Member DID → new.
    - Revoke all sessions / refresh tokens / idempotency
      cache rows keyed on old DID.
    - Re-issue VMC + role VEC to new DID (status-list index
      reused).
    - Audit `DidRotated { old_did, new_did, method: "did:key" }`.
  - Trust Tasks: `members/rotate-challenge/1.0`,
    `members/rotate/1.0`.
- **Files**
  - `vtc-service/src/routes/members/rotate.rs` (new)
  - `vti-common/src/audit/event.rs` (`DidRotated` variant)
- **Deps**: M2.12.1
- **Pre-impl decision**: **D7** (path split).

### `[ ]` M2.15.2 — `did:webvh` rotation

- **Acceptance**
  - `POST /v1/members/me/rotate` (same endpoint) detects
    new_did's method as `did:webvh`, resolves the new DID via
    `affinidi-did-resolver-cache-sdk`, walks the `did.jsonl`
    log, and verifies the prior-key signature on the latest
    log entry matches the old DID's key.
  - Same atomic effect as M2.15.1.
- **Risk** — see R4. May ship as a separate follow-up PR.
- **Deps**: M2.15.1

---

## M2.16 — Spec-deviation note

### `[ ]` M2.16.1 — Capture D1 + status-list URL outcomes

- **Acceptance** — `tasks/vtc-mvp/phase-2-plan.md` gains a
  "Phase 2 outcomes" header listing:
  - **D1 outcome**: VTC signs its own credentials locally.
    Spec §3-A "no key custody" amended.
  - **§14.2 outcome**: VTA-oracle timeout + breaker config
    knobs retained but only apply to non-VMC remote
    dependencies (trust-registry in Phase 3, did:webvh
    resolver in M2.15.2).
  - Any other deviations discovered during implementation.
- **Files**
  - `tasks/vtc-mvp/phase-2-plan.md`
  - `docs/05-design-notes/vtc-mvp.md` (§3-A + §14.2
    amendments)

---

## M2.17 — Audit variants

### `[ ]` M2.17.1 — Phase 2 audit vocabulary

- **Acceptance**
  - `AuditEvent` enum gains variants:
    `PolicyUploaded`, `PolicyActivated`, `VmcIssued`,
    `VecIssued`, `MembershipRenewed`, `StatusListFlipped`,
    `DidRotated`.
  - Each variant's data struct snapshot-tested.
- **Files**
  - `vti-common/src/audit/event.rs`
- **Deps**: every endpoint milestone (consumers wire after
  variants land)

---

## M2.18 — Trust Task drafts + index

### `[ ]` M2.18.1 — Spec + schema files for Phase 2 surface

- **Acceptance**
  - All 9 Phase 2 Trust Tasks from plan §D10 have `spec.md`
    + `schema.json` files.
  - `trust-tasks/index.json` extended with all 9 entries.
- **Files**
  - `trust-tasks/{policies,members,status-lists}/...`
  - `trust-tasks/index.json`
- **Deps**: M2.3, M2.4, M2.11, M2.13, M2.15

---

## M2.19 — Phase 2 gate

### `[ ]` M2.19.1 — Workspace gate green

- **Acceptance** (mirrors M0.12.3 + M1.15.1)
  - `cargo build --workspace` green.
  - `cargo test --workspace` green.
  - `cargo clippy --workspace --all-targets -- -D warnings`
    clean.
  - `cargo fmt --check` clean.
  - `trust-tasks/index.json` lists every Phase-2 Trust Task
    with matching on-disk files.
  - Memory entry `project_vtc_mvp.md` updated with the as-
    shipped outcomes for D1–D10.
  - Phase-2-todo milestones all flipped to `[x]`.
- **Verify** CI green on the merge commit.
- **Files**
  - `trust-tasks/index.json`
  - `/Users/glenngore/.claude/projects/-Users-glenngore-devel-fpp-verifiable-trust-infrastructure/memory/project_vtc_mvp.md`
- **Deps**: M2.17.1, M2.18.1

### Checkpoint — Phase 2 gate met

After M2.19.1: an applicant can submit → policy decides →
admin approves → VMC + VEC sealed-transferred → renewal works
→ removal flips the revocation bit → status list reflects
the flip → members can rotate their DIDs. Phase 3
(trust-registry + cross-community) can start.

---

## Open questions surfaced during planning

Defaults in `phase-2-plan.md` §§D1–D10. Listed here so
they're findable from the todo:

- **D1**: Signing surface — local Ed25519 (proposed).
  **Spec deviation**.
- **D2**: regorus location — `vtc_service::policy` (proposed).
- **D3**: Policy storage shape — `policies:<id>` rows +
  `active_policies:<purpose>` pointer (proposed).
- **D4**: VP → vp_claims extraction at submit time
  (proposed).
- **D5**: Status-list crypto — same `#key-0` signing,
  per-purpose endpoints (proposed).
- **D6**: Renewal idempotency — 24h non-destructive cache
  (proposed).
- **D7**: DID rotation — did:key first, did:webvh follows
  (proposed).
- **D8**: Policy hot-swap atomicity — Arc<CompiledPolicy>
  + RwLock + fjall row in same transaction (proposed).
- **D9**: Personhood policy stub in Phase 2; endpoints in
  Phase 4 (proposed).
- **D10**: Trust Task ID naming — see plan §D10.

Any decision that drifts from the default during
implementation should be recorded in `phase-2-plan.md`
under a "Phase 2 outcome" header.
