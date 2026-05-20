//! Fjall-backed storage for in-flight backup bundles.
//!
//! See `docs/05-design-notes/backup-descriptor-pattern.md` for the
//! full state machine. Brief recap: every `initiate-export` /
//! `initiate-import` mints a [`BundleRecord`], the bytes live
//! separately on disk under `${data_dir}/backups/{bundle_id}.vtabak`,
//! and a background sweeper transitions expired records to
//! `Expired` (terminal) and deletes the on-disk bytes.
//!
//! Tokens are stored as `SHA-256(token_b64)` so a leaked database
//! does not yield usable bearer credentials. Validation in the blob
//! endpoint uses constant-time comparison via `subtle::ConstantTimeEq`.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Bundle kind — export bytes flow VTA → operator, import bytes flow
/// operator → VTA. Encoded on the record so the same keyspace can
/// hold both directions without separate prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    Export,
    Import,
}

/// Per-bundle state machine. Transitions are recorded in
/// `docs/05-design-notes/backup-descriptor-pattern.md` §"State machine".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleState {
    /// Export: bytes are minted and waiting for download.
    ExportReady,
    /// Export: bytes have been downloaded once. Terminal —
    /// blob endpoint refuses further reads (one-shot).
    ExportDownloaded,
    /// Export: optional `complete-export` ack received.
    ExportAcked,
    /// Import: upload slot minted; awaiting blob POST.
    ImportPending,
    /// Import: bytes received; awaiting `finalize-import`.
    ImportReceived,
    /// Import: `finalize-import` ran in preview mode. Bundle stays
    /// open so the operator can re-finalize in commit mode.
    ImportPreviewed,
    /// Import: `finalize-import` committed. Terminal.
    ImportCommitted,
    /// Operator-requested cancel. Terminal.
    Aborted,
    /// Sweeper-driven garbage collection. Terminal.
    Expired,
}

impl BundleState {
    /// True when the state is terminal — the sweeper may free the
    /// bytes and the dispatcher refuses further mutations except
    /// retention-driven record deletion.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ExportDownloaded
                | Self::ExportAcked
                | Self::ImportCommitted
                | Self::Aborted
                | Self::Expired
        )
    }
}

/// Persistent record for an in-flight backup bundle. The
/// `token_hash` is `SHA-256(token_b64_url)` — the plaintext token
/// is returned to the client exactly once at mint time and never
/// stored.
///
/// `Zeroize` is not derived: every field is either a public
/// identifier (`bundle_id`, `created_by`, `kind`, …) or a hash.
/// The token plaintext lives only in the mint helper's stack frame
/// and is dropped immediately after the descriptor is built.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRecord {
    pub bundle_id: Uuid,
    pub kind: BundleKind,
    pub state: BundleState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// DID of the super-admin who initiated the bundle. Every
    /// non-`initiate-*` mutation checks `auth.did == created_by`.
    pub created_by: String,
    /// Transport algorithm. v1 only stores `"stream"`.
    pub algorithm: String,
    pub expected_sha256: String,
    pub expected_size_bytes: u64,
    /// `SHA-256(token_b64)`. Constant-time compared on every
    /// blob-endpoint request.
    pub token_hash: [u8; 32],
    /// On-disk path to the `.vtabak` bytes. Populated:
    ///   - for export: at descriptor mint time (bytes pre-staged)
    ///   - for import: after a successful POST to the blob endpoint
    pub blob_path: Option<PathBuf>,
}

/// Plaintext token returned to the client at descriptor mint time.
/// Zeroized on drop so it doesn't linger in memory after the
/// descriptor is built.
///
/// Wrapped in a newtype rather than `String` so a careless
/// `tracing::info!(?token, …)` redacts via the `Debug` impl below.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct BundleToken(pub String);

impl std::fmt::Debug for BundleToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BundleToken").field(&"<redacted>").finish()
    }
}

impl BundleToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn bundle_key(id: &Uuid) -> String {
    format!("bundle:{id}")
}

/// Fetch a bundle record by id.
pub async fn get_bundle(ks: &KeyspaceHandle, id: &Uuid) -> Result<Option<BundleRecord>, AppError> {
    ks.get(bundle_key(id)).await
}

/// Insert or replace a bundle record. Called at every state
/// transition (mint, blob-endpoint hit, finalize, sweeper expiry).
pub async fn store_bundle(ks: &KeyspaceHandle, record: &BundleRecord) -> Result<(), AppError> {
    ks.insert(bundle_key(&record.bundle_id), record).await
}

/// Remove a bundle record. Called by the sweeper after a terminal
/// state ages out of the 24h audit retention window.
pub async fn delete_bundle(ks: &KeyspaceHandle, id: &Uuid) -> Result<(), AppError> {
    ks.remove(bundle_key(id)).await
}

/// Enumerate every persisted bundle. The sweeper iterates this to
/// find candidates for TTL expiry and post-terminal cleanup.
/// Operator audit tooling can also consult it to inspect open
/// transfers.
pub async fn list_bundles(ks: &KeyspaceHandle) -> Result<Vec<BundleRecord>, AppError> {
    let raw = ks.prefix_iter_raw("bundle:").await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_, v) in raw {
        let record: BundleRecord = serde_json::from_slice(&v)
            .map_err(|e| AppError::Internal(format!("bundle record decode: {e}")))?;
        out.push(record);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    async fn setup_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace("backup_bundles_test").unwrap();
        (dir, ks)
    }

    #[tokio::test]
    async fn bundle_round_trips_through_keyspace() {
        let (_dir, ks) = setup_ks().await;
        let id = Uuid::new_v4();
        let record = BundleRecord {
            bundle_id: id,
            kind: BundleKind::Export,
            state: BundleState::ExportReady,
            created_at: Utc::now(),
            expires_at: Utc::now(),
            created_by: "did:example:admin".into(),
            algorithm: "stream".into(),
            expected_sha256: "deadbeef".into(),
            expected_size_bytes: 42,
            token_hash: [7u8; 32],
            blob_path: Some(PathBuf::from("/var/lib/vta/backups/a.vtabak")),
        };
        store_bundle(&ks, &record).await.unwrap();
        let restored = get_bundle(&ks, &id).await.unwrap().unwrap();
        assert_eq!(restored.bundle_id, id);
        assert_eq!(restored.state, BundleState::ExportReady);
        assert_eq!(restored.token_hash, [7u8; 32]);
    }

    #[tokio::test]
    async fn delete_removes_record() {
        let (_dir, ks) = setup_ks().await;
        let id = Uuid::new_v4();
        let record = BundleRecord {
            bundle_id: id,
            kind: BundleKind::Import,
            state: BundleState::ImportPending,
            created_at: Utc::now(),
            expires_at: Utc::now(),
            created_by: "did:example:admin".into(),
            algorithm: "stream".into(),
            expected_sha256: "feedface".into(),
            expected_size_bytes: 0,
            token_hash: [0u8; 32],
            blob_path: None,
        };
        store_bundle(&ks, &record).await.unwrap();
        delete_bundle(&ks, &id).await.unwrap();
        assert!(get_bundle(&ks, &id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_returns_all_bundles_via_prefix_scan() {
        let (_dir, ks) = setup_ks().await;
        let make = |kind: BundleKind, state: BundleState| BundleRecord {
            bundle_id: Uuid::new_v4(),
            kind,
            state,
            created_at: Utc::now(),
            expires_at: Utc::now(),
            created_by: "did:example:admin".into(),
            algorithm: "stream".into(),
            expected_sha256: "0".into(),
            expected_size_bytes: 0,
            token_hash: [0u8; 32],
            blob_path: None,
        };
        let a = make(BundleKind::Export, BundleState::ExportReady);
        let b = make(BundleKind::Import, BundleState::ImportPending);
        store_bundle(&ks, &a).await.unwrap();
        store_bundle(&ks, &b).await.unwrap();
        let all = list_bundles(&ks).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn is_terminal_pins_the_state_machine_taxonomy() {
        // Live states: blob endpoint accepts requests, sweeper
        // candidates only by TTL.
        assert!(!BundleState::ExportReady.is_terminal());
        assert!(!BundleState::ImportPending.is_terminal());
        assert!(!BundleState::ImportReceived.is_terminal());
        assert!(!BundleState::ImportPreviewed.is_terminal());

        // Terminal states: any further mutation is refused.
        assert!(BundleState::ExportDownloaded.is_terminal());
        assert!(BundleState::ExportAcked.is_terminal());
        assert!(BundleState::ImportCommitted.is_terminal());
        assert!(BundleState::Aborted.is_terminal());
        assert!(BundleState::Expired.is_terminal());
    }

    #[test]
    fn bundle_token_debug_redacts_secret() {
        let token = BundleToken("super-secret-token-AAA".into());
        let dbg = format!("{token:?}");
        assert!(
            dbg.contains("<redacted>"),
            "BundleToken debug must redact secret material: {dbg}"
        );
        assert!(!dbg.contains("super-secret-token"));
    }
}
