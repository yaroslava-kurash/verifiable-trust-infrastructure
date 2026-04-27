//! Shared VTA request / reply types for the online provisioning workflow.
//!
//! Two intents are supported:
//!
//! - [`VtaIntent::FullSetup`] — the VTA mints the integration's DID via a
//!   template render, rolls over an admin DID, and returns a
//!   [`super::result::ProvisionResult`] with keys, `did.jsonl`,
//!   authorization VC, and VTA trust bundle.
//! - [`VtaIntent::AdminOnly`] — the integration brings its own DID; the
//!   VTA only issues an admin credential and an ACL row. The reply carries
//!   an admin DID + matching private key.
//!
//! Each intent produces a [`VtaReply`] that downstream consumers handle
//! uniformly. The runners in this module produce these replies; the
//! consumer's UI / persistence layer consumes them.
//!
//! Offline / sealed-handoff variants are out of scope for this module —
//! see the workspace `vta bootstrap` CLI for that flow.

use super::result::ProvisionResult;

/// What the operator wants the VTA to do during setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtaIntent {
    /// VTA mints the integration's DID via a template render, rolls over
    /// an admin DID, and returns a [`ProvisionResult`].
    FullSetup,
    /// The integration brings its own DID (out of band); the VTA only
    /// issues an admin credential and an ACL row. The reply carries an
    /// admin DID + matching private key.
    AdminOnly,
}

/// Unified reply from the online runners.
///
/// Downstream consumers switch on the variant instead of branching on
/// intent separately. `Full` is boxed so the enum's stack footprint
/// stays uniform regardless of which variant is in play (the underlying
/// `ProvisionResult` is ~528 bytes vs `AdminCredentialReply`'s ~48).
#[derive(Clone, Debug)]
pub enum VtaReply {
    /// Full template-bootstrap reply. The VTA minted the integration's
    /// DID, (optionally) rolled over an admin DID, and returned the
    /// complete trust bundle.
    Full(Box<ProvisionResult>),
    /// Admin-credential-only reply. The integration keeps its own DID;
    /// the VTA supplied an admin identity it authenticates as against
    /// the VTA's admin APIs.
    AdminOnly(AdminCredentialReply),
}

/// Payload of [`VtaReply::AdminOnly`] — an admin DID and its private key.
#[derive(Clone, Debug)]
pub struct AdminCredentialReply {
    /// Admin DID the integration authenticates as.
    pub admin_did: String,
    /// Private key (multibase) paired with `admin_did`.
    pub admin_private_key_mb: String,
}
