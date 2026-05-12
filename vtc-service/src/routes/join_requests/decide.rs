//! `POST /v1/join-requests/{id}/approve` + `/reject` — admin
//! decision endpoints (M1.10.1).
//!
//! Approve atomically writes the ACL row (`VtcRole::Member`),
//! the Member record, and the audit envelopes
//! (`JoinRequestApproved` + `MemberAdded`). The applicant_did is
//! already validated at submit time so the only failure modes
//! here are auth + duplicate-membership.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{AuditEvent, JoinRequestData, JoinRequestRejectedData, MemberAddedData};
use vti_common::error::AppError;

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::join::{JoinStatus, get_join_request, store_join_request};
use crate::members::{Member, store_member};
use crate::server::AppState;

const REJECT_REASON_MAX: usize = 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideResponse {
    pub request_id: Uuid,
    pub status: String,
}

// ---------------------------------------------------------------------------
// Approve
// ---------------------------------------------------------------------------

pub async fn approve(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<DecideResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let mut req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.status != JoinStatus::Pending {
        return Err(AppError::Conflict(format!(
            "join request {id} is {:?}, not Pending",
            req.status
        )));
    }
    if get_acl_entry(&state.acl_ks, &req.applicant_did)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "{} already has an ACL row; refusing to approve a duplicate membership",
            req.applicant_did
        )));
    }

    // Write ACL first (auth-gating truth), then Member, then flip
    // the JoinRequest status. A crash between ACL + Member would
    // leave the auth path working but the metadata missing — the
    // safer direction (Phase 2 reconcile / next admin action can
    // patch the gap).
    let now = now_epoch();
    let acl = VtcAclEntry {
        did: req.applicant_did.clone(),
        role: VtcRole::Member,
        label: None,
        allowed_contexts: vec![],
        created_at: now,
        created_by: admin.0.did.clone(),
        expires_at: None,
    };
    store_acl_entry(&state.acl_ks, &acl).await?;

    let member = Member::fresh(&req.applicant_did);
    store_member(&state.members_ks, &member).await?;

    req.status = JoinStatus::Approved;
    store_join_request(&state.join_requests_ks, &req).await?;

    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::JoinRequestApproved(JoinRequestData {
                request_id: id.to_string(),
                transport: "rest".to_string(),
            }),
        )
        .await?;
    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::MemberAdded(MemberAddedData {
                role: VtcRole::Member.to_string(),
                via_join_request_id: Some(id.to_string()),
            }),
        )
        .await?;

    info!(
        request_id = %id,
        applicant = %req.applicant_did,
        admin = %admin.0.did,
        "join request approved"
    );

    Ok((
        StatusCode::OK,
        Json(DecideResponse {
            request_id: id,
            status: req.status.to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Reject
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RejectBody {
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn reject(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<RejectBody>,
) -> Result<(StatusCode, Json<DecideResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let reason = body.reason.unwrap_or_default();
    if reason.len() > REJECT_REASON_MAX {
        return Err(AppError::Validation(format!(
            "reject reason exceeds {REJECT_REASON_MAX} chars (got {})",
            reason.len(),
        )));
    }

    let mut req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.status != JoinStatus::Pending {
        return Err(AppError::Conflict(format!(
            "join request {id} is {:?}, not Pending",
            req.status
        )));
    }

    req.status = JoinStatus::Rejected;
    store_join_request(&state.join_requests_ks, &req).await?;

    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::JoinRequestRejected(JoinRequestRejectedData {
                request_id: id.to_string(),
                reason: reason.clone(),
            }),
        )
        .await?;

    info!(
        request_id = %id,
        applicant = %req.applicant_did,
        admin = %admin.0.did,
        reason_present = !reason.is_empty(),
        "join request rejected"
    );

    Ok((
        StatusCode::OK,
        Json(DecideResponse {
            request_id: id,
            status: req.status.to_string(),
        }),
    ))
}
