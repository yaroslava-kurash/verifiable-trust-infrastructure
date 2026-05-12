//! DIDComm wire types for VTC join-request submission.
//!
//! The corresponding REST endpoint is `POST /v1/join-requests`;
//! over DIDComm the message `type` field IS the Trust Task URL
//! (workspace convention) and the DIDComm authcrypt sender
//! authenticates the applicant DID — no separate holder-binding
//! signature is needed (the envelope already binds the sender).

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// DIDComm message `type` for a join-request submission.
pub const JOIN_REQUEST_SUBMIT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0";

/// DIDComm message `type` for the VTC's reply (the submission
/// receipt). Carried as a `thid` reply to the submit message id.
pub const JOIN_REQUEST_SUBMIT_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/submit-receipt/1.0";

/// Body of the submit message. Applicant_did comes from the
/// DIDComm `from` field, not the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSubmitBody {
    pub vp: JsonValue,
    #[serde(default)]
    pub registry_consent: bool,
    #[serde(default)]
    pub extensions: JsonValue,
}

/// Body of the receipt message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSubmitReceiptBody {
    pub request_id: Uuid,
    /// Status string. Always `"pending"` for a successful submit;
    /// future protocol versions may add `"deferred"` etc.
    pub status: String,
}
