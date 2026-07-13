//! Mediator ACL setup for DIDComm clients.
//!
//! After a client successfully connects to a mediator, it configures its own per-DID
//! ACL to accept all messages despite potentially restrictive global ACL defaults.
//! This allows the client to receive messages while maintaining the flexibility to set
//! more restrictive ACLs on specific contexts or integrations if needed.
//!
//! Used by both VTA (server startup) and PNM (on DIDComm connect).
//! Gated on the `acl-setup` feature which requires `session` + `trust-tasks-rs`.

use std::sync::Arc;

use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::ATM;
use sha2::{Digest, Sha256};
use trust_tasks_rs::specs::messaging::acl;
use tracing::{debug, info, warn};

/// Set a client's own ACL on the mediator to accept all messages.
///
/// Call this immediately after a DIDComm connection to the mediator succeeds.
/// The client sets its per-DID ACL to allow all message types, which overrides any
/// restrictive global ACL settings on the mediator while still respecting per-context
/// ACLs configured for integrations.
///
/// # Behavior
/// - If ATM or required DIDs are not available, this is a no-op (graceful degradation)
/// - If ACL setting fails, a warning is logged but startup continues (fire-and-forget)
pub async fn set_client_acl_on_connection(
    atm: &ATM,
    client_did: &str,
    mediator_did: &str,
    channel: &str,
    client_name: &str,
) {
    if let Err(e) = set_client_acl_internal(atm, client_did, mediator_did, channel, client_name).await {
        warn!(
            channel,
            error = %e,
            client = client_name,
            "failed to set client ACL on mediator (startup continues)"
        );
    }
}

/// Internal implementation of ACL setup.
async fn set_client_acl_internal(
    atm: &ATM,
    client_did: &str,
    mediator_did: &str,
    channel: &str,
    client_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build an ATM profile for the client with the mediator as the peer.
    let atm_profile = ATMProfile::new(atm, None, client_did.to_string(), Some(mediator_did.to_string()))
        .await
        .map_err(|e| format!("failed to create ATM profile: {e}"))?;

    // Hash the client's DID for the mediator's ACL record (self-reference)
    // SHA-256 to match the TDK's acl_set convention
    let mut hasher = Sha256::new();
    hasher.update(client_did);
    let hash_bytes = hasher.finalize();
    let client_did_hash = hash_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Build an "allow all" ACL that accepts every message type.
    // This is a partial update: only the flags we set matter; the rest left unchanged.
    let acl = build_allow_all_acl();

    // Apply the ACL to the client's own DID via the mediator's trust-tasks protocol.
    // Send the request without waiting for response, because receiving the response
    // requires receive_forwarded permission which we don't have until the ACL is
    // applied. The mediator will process the request asynchronously anyway.
    let client_did_copy = client_did.to_string();
    let client_name_copy = client_name.to_string();
    let atm_profile_arc = Arc::new(atm_profile);
    let atm_clone = atm.clone();

    // Spawn a background task to send the ACL request fire-and-forget.
    // Errors are logged at debug level since the mediator may still process it.
    tokio::spawn(async move {
        match atm_clone
            .trust_tasks()
            .acl_set(&atm_profile_arc, client_did_hash, acl)
            .await
        {
            Ok(_) => {
                info!(
                    client_did = %client_did_copy,
                    client = client_name_copy,
                    "client ACL configured on mediator"
                );
            }
            Err(e) => {
                debug!(
                    client_did = %client_did_copy,
                    error = %e,
                    client = client_name_copy,
                    "client ACL request error (mediator may still process asynchronously)"
                );
            }
        }
    });

    info!(
        channel,
        client_did = %client_did,
        client = client_name,
        "client ACL configuration request sent to mediator"
    );

    Ok(())
}

/// Build a wire-format ACL that allows all message types.
///
/// This creates a `MediatorAcl` wire format (compatible with the trust-tasks
/// `acl/set/0.1` endpoint) that permits sending, receiving, forwarding, and
/// anonymous messages. The access-list mode is set to ExplicitDeny (denylist
/// semantics), allowing all except explicitly denied entries.
fn build_allow_all_acl() -> acl::set::v0_1::MediatorAcl {
    acl::set::v0_1::MediatorAcl {
        blocked: Some(false),
        local: Some(true),
        send_messages: Some(true),
        receive_messages: Some(true),
        send_forwarded: Some(true),
        receive_forwarded: Some(true),
        create_invites: Some(true),
        anon_receive: Some(true),
        access_list_mode: Some(acl::set::v0_1::MediatorAclAccessListMode::ExplicitDeny),
        // Don't set self-manage flags — let the mediator's defaults apply
        ..Default::default()
    }
}
