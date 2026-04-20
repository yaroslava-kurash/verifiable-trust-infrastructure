//! Wire types for `POST /bootstrap/provision-integration`.
//!
//! Mirrors the shape of
//! `vta-service::routes::bootstrap::provision::*` on the client side,
//! so `VtaClient::provision_integration` consumers don't need to
//! depend on vta-service.

use serde::{Deserialize, Serialize};

use super::BootstrapRequest;

/// Request body.
#[derive(Debug, Serialize)]
pub struct ProvisionIntegrationRequest {
    /// The integration's VP-framed bootstrap request (signed by its
    /// ephemeral `client_did`). The caller sends it unverified — the
    /// server verifies on intake.
    pub request: BootstrapRequest,
    /// VTA context to provision into.
    pub context: String,
    /// Optional — default `did-signed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<AssertionMode>,
    /// Optional override for the VC's validity window (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vc_validity_seconds: Option<i64>,
}

/// Producer assertion mode on the returned sealed bundle. Mirrors the
/// server's `AssertionMode`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionMode {
    #[default]
    DidSigned,
    PinnedOnly,
}

/// Response body.
#[derive(Debug, Deserialize)]
pub struct ProvisionIntegrationResponse {
    /// Armored sealed bundle.
    pub bundle: String,
    /// SHA-256 digest of the sealed ciphertext (lowercase hex).
    pub digest: String,
    pub summary: ProvisionSummary,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProvisionSummary {
    pub client_did: String,
    pub integration_did: String,
    pub template_name: String,
    pub template_kind: String,
    pub bundle_id_hex: String,
    pub secret_count: usize,
    pub output_count: usize,
}
