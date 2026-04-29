//! `pnm mediator …` command implementations.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 4 lands `migrate` and the `rollback` alias. `drain cancel`
//! and `report` arrive in P4.3 / P4.4.

use vta_sdk::client::VtaClient;
use vta_sdk::protocol::MigrateMediatorRequest;

/// `pnm mediator migrate --to <did> --drain-ttl <secs> [--force]
///                       [--handshake-timeout <secs>]`.
pub async fn cmd_mediator_migrate(
    client: &VtaClient,
    new_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_migrate(
        client,
        new_mediator_did,
        drain_ttl_secs,
        force,
        handshake_timeout_secs,
        /* rollback = */ false,
    )
    .await
}

/// `pnm mediator rollback --to <did> --drain-ttl <secs>`.
///
/// Mechanically identical to `migrate` but tagged in telemetry as
/// a rollback so reports can distinguish forward and reverse moves.
/// Spec criterion #6 (rollback equivalence): the resulting DID doc
/// matches the pre-migrate state byte-for-byte in `service[]`,
/// modulo `versionId` and the rotated WebVH control keys.
pub async fn cmd_mediator_rollback(
    client: &VtaClient,
    target_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_migrate(
        client,
        target_mediator_did,
        drain_ttl_secs,
        force,
        handshake_timeout_secs,
        /* rollback = */ true,
    )
    .await
}

async fn run_migrate(
    client: &VtaClient,
    new_mediator_did: String,
    drain_ttl_secs: u64,
    force: bool,
    handshake_timeout_secs: Option<u64>,
    rollback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = MigrateMediatorRequest::new(&new_mediator_did, drain_ttl_secs);
    req.force = force;
    req.handshake_timeout_secs = handshake_timeout_secs;
    req.rollback = rollback;

    let resp = client
        .migrate_mediator(req)
        .await
        .map_err(|e| format!("{e}"))?;

    let verb = if rollback { "rolled back" } else { "migrated" };
    println!("Mediator {verb}.");
    println!("  Prior mediator:  {}", resp.prior_mediator_did);
    println!("  Active mediator: {}", resp.active_mediator_did);
    if !resp.active_mediator_endpoint.is_empty() {
        println!("  Active endpoint: {}", resp.active_mediator_endpoint);
    }
    println!("  New version ID:  {}", resp.new_version_id);
    println!(
        "  Drain deadline:  {} (prior listener stays up until then)",
        resp.drains_until
    );
    if force {
        println!();
        println!("  Note: --force was set; mediator handshake steps 2-5 were bypassed.");
    }
    Ok(())
}
