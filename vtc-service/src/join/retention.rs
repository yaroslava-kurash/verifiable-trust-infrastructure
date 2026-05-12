//! 30-day retention sweeper for `Rejected` + `Withdrawn` join
//! requests (spec §5.5).
//!
//! VP contents may include PII; the sole control on inadvertent
//! PII retention is this sweeper. Runs on a daemon-wide tokio
//! task spawned at startup; default cadence is hourly.

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::{delete_join_request, list_join_requests};

/// Operator-controllable retention window for terminal join
/// requests (Rejected + Withdrawn).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestsConfig {
    /// Retention window in days. After this many days from
    /// `submitted_at`, terminal-state rows are purged on the next
    /// sweep. Default 30.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// How often the sweeper runs, in seconds. Default 3600 (1
    /// hour). Lower in tests via the config knob if needed.
    #[serde(default = "default_sweep_interval_secs")]
    pub sweep_interval_secs: u64,
}

pub fn default_retention_days() -> u32 {
    30
}

fn default_sweep_interval_secs() -> u64 {
    3600
}

impl Default for JoinRequestsConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
            sweep_interval_secs: default_sweep_interval_secs(),
        }
    }
}

/// Owns the sweeper background task.
pub struct RetentionSweeper;

impl RetentionSweeper {
    /// Spawn the sweeper. Returns immediately; the task runs
    /// until the daemon's shutdown watcher fires.
    pub fn spawn(
        ks: KeyspaceHandle,
        config: JoinRequestsConfig,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = Duration::from_secs(config.sweep_interval_secs.max(60));
            info!(
                retention_days = config.retention_days,
                interval_secs = interval.as_secs(),
                "join-request retention sweeper started"
            );
            // Sweep once on startup so a freshly-restarted daemon
            // catches up on rows that aged out while it was down.
            if let Err(e) = sweep_once(&ks, config.retention_days).await {
                warn!(error = %e, "initial join-request sweep failed");
            }
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        info!("join-request retention sweeper shutting down");
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {
                        if let Err(e) = sweep_once(&ks, config.retention_days).await {
                            warn!(error = %e, "join-request sweep failed");
                        }
                    }
                }
            }
        })
    }
}

/// One pass: scan every row, delete those whose status is
/// `Rejected` / `Withdrawn` AND `submitted_at` is older than the
/// retention window.
async fn sweep_once(ks: &KeyspaceHandle, retention_days: u32) -> Result<(), AppError> {
    let cutoff = Utc::now() - ChronoDuration::days(retention_days as i64);
    let rows = list_join_requests(ks).await?;
    let mut purged = 0usize;
    for row in rows {
        if row.status.is_terminal_retainable() && row.submitted_at < cutoff {
            delete_join_request(ks, row.id).await?;
            purged += 1;
        }
    }
    if purged > 0 {
        info!(
            purged,
            retention_days, "join-request retention sweep complete"
        );
    } else {
        debug!(
            retention_days,
            "join-request retention sweep: nothing to purge"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join::storage::store_join_request;
    use crate::join::{JoinRequest, JoinStatus};
    use chrono::{Duration as ChronoDuration, Utc};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("join_requests").unwrap();
        (ks, dir)
    }

    fn at(submitted_at: chrono::DateTime<Utc>, status: JoinStatus) -> JoinRequest {
        JoinRequest {
            submitted_at,
            status,
            ..JoinRequest::new("did:key:z", serde_json::json!({}))
        }
    }

    #[tokio::test]
    async fn sweep_purges_old_rejected_rows() {
        let (ks, _dir) = temp_ks().await;
        let old = at(Utc::now() - ChronoDuration::days(31), JoinStatus::Rejected);
        let recent = at(Utc::now() - ChronoDuration::days(7), JoinStatus::Rejected);
        let pending_old = at(Utc::now() - ChronoDuration::days(60), JoinStatus::Pending);
        for r in [&old, &recent, &pending_old] {
            store_join_request(&ks, r).await.unwrap();
        }

        sweep_once(&ks, 30).await.unwrap();

        let remaining = list_join_requests(&ks).await.unwrap();
        let dids: Vec<_> = remaining.iter().map(|r| r.id).collect();
        assert!(!dids.contains(&old.id), "old Rejected row must be purged");
        assert!(
            dids.contains(&recent.id),
            "recent Rejected row must be retained"
        );
        assert!(
            dids.contains(&pending_old.id),
            "Pending rows must never be swept"
        );
    }

    #[tokio::test]
    async fn sweep_purges_old_withdrawn_rows() {
        let (ks, _dir) = temp_ks().await;
        let old = at(Utc::now() - ChronoDuration::days(45), JoinStatus::Withdrawn);
        store_join_request(&ks, &old).await.unwrap();
        sweep_once(&ks, 30).await.unwrap();
        assert!(
            list_join_requests(&ks).await.unwrap().is_empty(),
            "old Withdrawn rows must be purged"
        );
    }

    #[tokio::test]
    async fn sweep_does_not_purge_approved_rows() {
        let (ks, _dir) = temp_ks().await;
        let approved = at(Utc::now() - ChronoDuration::days(365), JoinStatus::Approved);
        store_join_request(&ks, &approved).await.unwrap();
        sweep_once(&ks, 30).await.unwrap();
        assert_eq!(list_join_requests(&ks).await.unwrap().len(), 1);
    }
}
