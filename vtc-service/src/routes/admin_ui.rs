//! Admin UX route surface (§12.2, Phase 5 M5.7).
//!
//! Two handlers:
//!
//! - **Catch-all** (`GET /admin/*`) → serves the baked SPA from
//!   [`crate::admin_ui`]. SPA history-mode fallback: paths that
//!   don't match a baked file fall back to `index.html` so
//!   client-side routing works.
//! - **Build-info** (`GET /admin/build-info.json`) → returns the
//!   embedded directory's SHA-256 + file count + mode. Unauth —
//!   the daemon's release metadata is public.

#![cfg(feature = "admin-ui")]

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use serde::Serialize;

use crate::admin_ui::AdminUiInfo;
use crate::server::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    pub version: String,
    pub index_sha256: String,
    pub file_count: u32,
    pub mode: String,
}

/// `GET /admin/build-info.json` — unauth, surfaces what's baked.
pub async fn build_info(State(state): State<AppState>) -> Json<BuildInfo> {
    let mode = state.config.read().await.admin_ui.mode.clone();
    let info = AdminUiInfo::from_embedded(&mode);
    Json(BuildInfo {
        // The admin SPA carries its own internal version, but
        // the embedded build's SHA-256 is what an operator
        // actually pins against.
        version: env!("CARGO_PKG_VERSION").to_string(),
        index_sha256: (*info.index_sha256).clone(),
        file_count: info.file_count,
        mode: (*info.mode).clone(),
    })
}

/// `GET /admin/*` — serve the baked SPA. When
/// `admin_ui.mode = "external"` this handler is skipped at route
/// attach time and `/admin/*` returns 404.
pub async fn serve_spa(req: Request<Body>) -> Response {
    crate::admin_ui::serve(req).await
}

/// Manifest entry the admin SPA's plugin loader iterates over to
/// dynamically `import()` each third-party plugin's entry module.
///
/// Mirrors the shape of `PluginManifest` in the admin SPA's
/// `plugin-api.ts` for the fields a third-party plugin needs to
/// register itself: `id`, `label`, `path`, `entry`, plus optional
/// `icon` + `scopes`. The plugin's entry JS calls
/// `window.VtcPluginApi.registerPlugin({...})` to wire its UI into
/// the shell's router and nav.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifestEntry {
    pub id: String,
    pub label: String,
    pub path: String,
    /// Absolute URL the shell `import()`s. Daemon-served plugins
    /// resolve to `/admin/plugins/<id>/<file>`.
    pub entry: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginsManifestResponse {
    pub plugins: Vec<PluginManifestEntry>,
}

/// `GET /admin/plugins.json` — third-party plugin manifest.
///
/// Today: returns an empty list. The endpoint exists so the shell's
/// plugin loader is well-defined (fetch the manifest at boot,
/// `import()` each entry) and so operators can layer in plugins via
/// a future config knob (`admin_ui.plugin_dir`) that this handler
/// reads. Until that knob lands, all operator-facing plugins are
/// the built-ins baked into the SPA bundle.
///
/// Unauth on purpose: knowing which plugins are installed is not
/// sensitive, and the shell fetches before login.
pub async fn plugins_manifest(State(_state): State<AppState>) -> Json<PluginsManifestResponse> {
    // TODO: when `admin_ui.plugin_dir` lands, walk that directory
    // and read each `<plugin_id>/manifest.json`. Validate the id
    // against a `^[a-z][a-z0-9-]*$` allow-list before serving.
    Json(PluginsManifestResponse { plugins: vec![] })
}
