---
id: https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0
title: VTC Join Requests — Submit
status: Draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/join-requests
  - didcomm: https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0
---

# VTC Join Requests — Submit

Persist a `JoinRequest` in status `Pending`. Phase 1 manual-
approval flow: admin / moderator runs approve or reject later.

## Authentication

Unauthenticated. The VP / DIDComm envelope is the auth — see
spec §5.5.

### REST holder binding

Request body carries `applicantDid`, `vp`, optional
`registryConsent` + `extensions`, and a hex-encoded Ed25519
signature. Phase 1 supports `did:key` applicants only (the
pubkey is intrinsic to the DID).

The signing payload is the canonical JSON of the request body
(minus `signature`) prefixed with the domain tag
`vtc-join-request/v1\0`. Verification:

1. Decode `applicantDid` → Ed25519 pubkey.
2. Decode `signature` (hex).
3. Verify the signature against the prefixed payload.

### DIDComm

`applicantDid` comes from the DIDComm `from` field (the
authcrypt sender). No separate signature in the body — the
envelope IS the binding. The handler replies with a
`join-requests/submit-receipt/1.0` message carrying the
`requestId` + `status`.

## Errors

- `400 Bad Request` — malformed VP / signature / non-did:key
  applicant.
- `429 Too Many Requests` — rate-limited (per-IP for REST,
  per-sender-DID for DIDComm).

## Audit

`JoinRequestSubmitted { requestId, transport: "rest"|"didcomm" }`.
