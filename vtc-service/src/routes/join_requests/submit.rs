//! `POST /v1/join-requests` — REST submit (M1.8.1) + a shared
//! inner `submit_inner` the DIDComm handler (M1.8.2) calls into.
//!
//! ## Holder binding
//!
//! Phase 1 plan §D4 requires only the holder-binding proof: the
//! signature must verify against the applicant_did's intrinsic
//! Ed25519 public key (did:key only — did:webvh resolution lands
//! in Phase 2).
//!
//! Wire shape:
//!
//! ```text
//! {
//!   "applicantDid": "did:key:z…",
//!   "vp":               { … opaque JSON … },
//!   "registryConsent":  ? bool,
//!   "extensions":       ? object,
//!   "signature":        "<hex Ed25519 signature>"
//! }
//! ```
//!
//! Canonical signing payload:
//!
//! ```text
//! "vtc-join-request/v1\0" || canonical_json({
//!   "applicantDid":     applicant_did,
//!   "vp":               vp,
//!   "registryConsent":  registry_consent (default false),
//!   "extensions":       extensions (default null),
//! })
//! ```
//!
//! `canonical_json` is just `serde_json::to_vec` on a
//! key-ordered object — sufficient because both sides agree on
//! the field ordering via the typed struct.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{AuditEvent, JoinRequestData};
use vti_common::error::AppError;

use crate::join::{JoinRequest, JoinTransport, store_join_request};
use crate::server::AppState;

pub const JOIN_REQUEST_SUBMIT_DOMAIN_TAG: &[u8] = b"vtc-join-request/v1\0";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitRequestBody {
    pub applicant_did: String,
    pub vp: JsonValue,
    #[serde(default)]
    pub registry_consent: bool,
    #[serde(default)]
    pub extensions: JsonValue,
    /// Hex-encoded Ed25519 signature.
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitResponse {
    pub request_id: Uuid,
    pub status: String,
}

pub async fn submit(
    State(state): State<AppState>,
    Json(req): Json<SubmitRequestBody>,
) -> Result<(StatusCode, Json<SubmitResponse>), AppError> {
    let request = submit_inner(
        &state,
        req.applicant_did,
        req.vp,
        req.registry_consent,
        req.extensions,
        Some(&req.signature),
        JoinTransport::Rest,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(SubmitResponse {
            request_id: request.id,
            status: request.status.to_string(),
        }),
    ))
}

/// Shared inner implementation called by both REST and the
/// DIDComm handler. Returns the persisted `JoinRequest`.
///
/// `signature` is `Some` for REST (where the wire must carry an
/// explicit holder-binding signature) and `None` for DIDComm
/// (where the DIDComm envelope's authcrypt sender already
/// authenticates `applicant_did`).
pub async fn submit_inner(
    state: &AppState,
    applicant_did: String,
    vp: JsonValue,
    registry_consent: bool,
    extensions: JsonValue,
    signature_hex: Option<&str>,
    transport: JoinTransport,
) -> Result<JoinRequest, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // 1. Holder binding (REST only).
    if let Some(hex_sig) = signature_hex {
        verify_holder_signature(&applicant_did, &vp, registry_consent, &extensions, hex_sig)?;
    }

    // 2. Persist as Pending.
    let mut request = JoinRequest::new(applicant_did.clone(), vp);
    request.registry_consent = registry_consent;
    request.extensions = extensions;
    store_join_request(&state.join_requests_ks, &request).await?;

    // 3. Audit. Actor is the applicant — they're the principal.
    audit_writer
        .write(
            &applicant_did,
            None,
            AuditEvent::JoinRequestSubmitted(JoinRequestData {
                request_id: request.id.to_string(),
                transport: transport.as_str().to_string(),
            }),
        )
        .await?;

    info!(
        request_id = %request.id,
        applicant = %applicant_did,
        transport = transport.as_str(),
        "join request submitted"
    );
    Ok(request)
}

/// Verify the Ed25519 signature over the canonical signing
/// payload (see module docs).
fn verify_holder_signature(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
    signature_hex: &str,
) -> Result<(), AppError> {
    let pubkey_bytes =
        affinidi_crypto::did_key::did_key_to_ed25519_pub(applicant_did).map_err(|e| {
            AppError::Validation(format!("applicant_did is not a parseable did:key: {e}"))
        })?;
    let verifying = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
        AppError::Validation(format!(
            "applicant_did decodes to an invalid Ed25519 pubkey: {e}"
        ))
    })?;

    let payload = canonical_payload(applicant_did, vp, registry_consent, extensions)?;
    let signing_bytes = signing_bytes(&payload);

    let raw_sig = hex::decode(signature_hex)
        .map_err(|e| AppError::Validation(format!("signature is not hex: {e}")))?;
    let signature = Signature::from_slice(&raw_sig).map_err(|e| {
        AppError::Validation(format!("signature is not a 64-byte Ed25519 value: {e}"))
    })?;

    verifying
        .verify(&signing_bytes, &signature)
        .map_err(|e| AppError::Validation(format!("holder-binding signature failed: {e}")))?;
    Ok(())
}

/// Canonical signing payload — a typed struct serialised via
/// `serde_json::to_vec` with the field order pinned by the
/// derive. Both sides build this identically by going through the
/// same struct.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    applicant_did: &'a str,
    vp: &'a JsonValue,
    registry_consent: bool,
    extensions: &'a JsonValue,
}

fn canonical_payload(
    applicant_did: &str,
    vp: &JsonValue,
    registry_consent: bool,
    extensions: &JsonValue,
) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&CanonicalPayload {
        applicant_did,
        vp,
        registry_consent,
        extensions,
    })
    .map_err(|e| AppError::Internal(format!("canonical payload serialize: {e}")))
}

/// Domain-tag prefixed bytes the signer hashes over.
fn signing_bytes(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(JOIN_REQUEST_SUBMIT_DOMAIN_TAG.len() + payload.len());
    buf.extend_from_slice(JOIN_REQUEST_SUBMIT_DOMAIN_TAG);
    buf.extend_from_slice(payload);
    buf
}

// ---------------------------------------------------------------------------
// Tests — signing primitive + sign-then-verify round trip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn pair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0xAB; 32]);
        let pub_bytes = sk.verifying_key().to_bytes();
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        (sk, did)
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"placeholder"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        verify_holder_signature(&did, &vp, false, &JsonValue::Null, &sig_hex).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let (_a_sk, a_did) = pair();
        let other = SigningKey::from_bytes(&[0xCD; 32]);
        let vp = serde_json::json!({});
        let payload = canonical_payload(&a_did, &vp, false, &JsonValue::Null).unwrap();
        let sig = other.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        let err = verify_holder_signature(&a_did, &vp, false, &JsonValue::Null, &sig_hex)
            .expect_err("wrong signer must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, did) = pair();
        let vp = serde_json::json!({"vp":"original"});
        let payload = canonical_payload(&did, &vp, false, &JsonValue::Null).unwrap();
        let sig = sk.sign(&signing_bytes(&payload));
        let sig_hex = hex::encode(sig.to_bytes());

        // Same signature, different VP body.
        let tampered = serde_json::json!({"vp":"changed"});
        let err = verify_holder_signature(&did, &tampered, false, &JsonValue::Null, &sig_hex)
            .expect_err("tampered VP must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_garbage_signature() {
        let (_sk, did) = pair();
        let err =
            verify_holder_signature(&did, &JsonValue::Null, false, &JsonValue::Null, "not-hex")
                .expect_err("garbage sig must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn verify_rejects_non_did_key_applicant() {
        let err = verify_holder_signature(
            "did:web:example.com",
            &JsonValue::Null,
            false,
            &JsonValue::Null,
            "00",
        )
        .expect_err("non-did:key must fail");
        assert!(matches!(err, AppError::Validation(_)));
    }
}
