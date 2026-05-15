//! Install token state machine + claim-secret helpers.
//!
//! Implements **M0.4** of the VTC MVP Phase 0 plan. The install
//! token is the one-time bearer credential an operator clicks to
//! claim a passkey for an admin DID — first-time setup via
//! `vtc setup`, and ongoing admin invites via `vtc admin invite`
//! or `POST /v1/admin/invites`. This module owns:
//!
//! - **[`token`]** — `InstallToken` claims + the EdDSA JWT
//!   signer/verifier derived from the VTC's master seed via HKDF.
//! - **[`state_machine`]** — the `install` keyspace state machine
//!   gating each invite (`Issued` → `Consumed`), with the
//!   **claim-window** pattern adopted from
//!   `webvh-common::server::passkey::store` (plan D12). A failed
//!   WebAuthn ceremony doesn't burn the token — only a successful
//!   `finish_claim` does.
//! - **[`claim_secret`]** — Argon2id-hashed out-of-band code each
//!   invite carries. Defense in depth: a leaked install URL alone
//!   is insufficient to claim the passkey; the invitee also needs
//!   the code, which travels through a separate channel.
//! - **[`INSTALL_TOKEN_LOCK`]** — a single process-wide async
//!   mutex guarding the state-machine transitions so two concurrent
//!   `start_claim` calls on the same token can't both pass the
//!   "claimed_at not set within the window" check.
//!
//! See spec §4.1 / §4.2 for the consumer-facing flow.

pub mod claim_secret;
pub mod state_machine;
pub mod token;

pub use state_machine::{
    InstallTokenState, InstallTokenStore, PendingEmergencyBootstrap, StartClaimOutcome,
};
pub use token::{
    INSTALL_AUDIENCE, INSTALL_SESSION_AUDIENCE, INSTALL_SESSION_DEFAULT_TTL_SECS, INSTALL_SUBJECT,
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallSessionClaims, InstallTokenClaims, InstallTokenSigner,
    mint_install_session_token, mint_install_token, parse_install_token,
};

use tokio::sync::Mutex;

/// Process-wide async mutex serialising every install-token state
/// machine transition. Mirrors VTA's `MODE_B_LOCK` invariant — the
/// claim-check then claim-set sequence must be atomic across
/// concurrent Axum tasks. Cheap when idle.
pub static INSTALL_TOKEN_LOCK: Mutex<()> = Mutex::const_new(());

// Backwards-compatible alias. The old name leaked the abandoned
// "carve-out" model into call sites; new code should use
// `INSTALL_TOKEN_LOCK` directly. Remove once internal callers
// migrate.
#[doc(hidden)]
pub use INSTALL_TOKEN_LOCK as INSTALL_CARVEOUT_LOCK;
