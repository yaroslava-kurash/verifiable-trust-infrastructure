//! Public, unauthenticated serving of the VTA's **own** self-hosted
//! `did:webvh` log at the canonical resolver paths.
//!
//! These endpoints only return content when the VTA hosts its own DID
//! (serverless mode — `record.server_id == "serverless"`). A server-managed
//! VTA publishes its log to an external did-hosting backplane, so here it
//! returns 404. Self-hosting is therefore a *runtime* distinction (the
//! serverless→server-managed promotion is a runtime operation — see the
//! workspace `CLAUDE.md` "Promote a serverless DID to a server-managed one"),
//! which is why it rides the existing `webvh` feature like the rest of the
//! method rather than a separate compile flag. When other self-hosted DID
//! methods (e.g. `did:web`) arrive, their public-serving handlers belong
//! here alongside these.
//!
//! ## Security model
//!
//! World-readable by design (the `did:webvh` log model is public) and
//! rate-limited via the unauth governor at the router. Two deliberate
//! properties:
//!
//! - **The request path is never used as a store key or filesystem path.** It
//!   is only ever compared for *equality* against the path derived from the
//!   *configured* VTA DID; the log bytes are read from the store keyed by that
//!   configured DID. A crafted request path can therefore neither traverse the
//!   store nor select a different DID's log.
//! - **Failure modes are opaque.** Every "not self-hosting / not found" reason
//!   collapses to a bare 404 with no body — byte-identical to axum's default
//!   fallback — so an unauthenticated prober cannot fingerprint the VTA's DID
//!   configuration (has-a-DID? is-webvh? root vs pathful?). Only a genuine
//!   storage error surfaces as 500, for operational visibility.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use didwebvh_rs::url::WebVHURL;

use crate::server::AppState;

/// Media type the did:webvh v1.0 spec SHOULDs for the log file
/// (DID-to-HTTPS Transformation §6).
const JSONL_CONTENT_TYPE: &str = "text/jsonl";

/// `GET /.well-known/did.jsonl` — public, unauthenticated.
///
/// Serves the VTA's own `did:webvh` log at the standard resolver path for a
/// *root-style* DID (`did:webvh:SCID:domain`, no path segments). Returns an
/// opaque 404 for every other case — including a pathful VTA DID, whose log is
/// served by [`get_vta_canonical_did_log_handler`] instead.
#[utoipa::path(
    get, path = "/.well-known/did.jsonl", tag = "did-webvh",
    responses(
        (status = 200, description = "VTA did.jsonl log", content_type = "text/jsonl"),
        (status = 404, description = "VTA has no self-hosted did:webvh identity at this path"),
    ),
)]
pub async fn get_vta_well_known_did_log_handler(State(state): State<AppState>) -> Response {
    serve_canonical(&state, "/.well-known/did.jsonl").await
}

/// `GET /{*did_log_path}` — public, unauthenticated catch-all.
///
/// Serves the VTA's own `did:webvh` log when the configured VTA DID is
/// *pathful* (`did:webvh:SCID:domain:tenant:vta` → `/tenant/vta/did.jsonl`).
/// Every non-matching request returns a bare 404 (empty body), so mounting
/// this as the unauth catch-all does not change the response shape of
/// unrelated unknown GETs.
///
/// INVARIANT: this must remain the *only* root-level wildcard route in the
/// router. A second `/{*...}` or an overlapping `nest()` at the root would
/// conflict in axum's matcher. See the module docs for why the request path is
/// never used as a store key.
pub async fn get_vta_canonical_did_log_handler(
    State(state): State<AppState>,
    Path(did_log_path): Path<String>,
) -> Response {
    let request_path = format!("/{}", did_log_path.trim_start_matches('/'));
    // Cheap pre-filter: reject anything that can't be a did.jsonl request
    // before taking the config lock, so the bulk of catch-all traffic
    // (unrelated unknown GETs) stays as cheap as axum's default 404.
    if !request_path.ends_with("/did.jsonl") {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_canonical(&state, &request_path).await
}

/// Serve the VTA's self-hosted `did.jsonl` iff `request_path` is exactly the
/// canonical resolver path of the configured VTA DID. See the module-level
/// security model for the equality-not-lookup and opaque-404 guarantees.
async fn serve_canonical(state: &AppState, request_path: &str) -> Response {
    let Some((vta_did, expected_path)) = configured_canonical_path(state).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if request_path != expected_path {
        return StatusCode::NOT_FOUND.into_response();
    }
    match crate::webvh_store::get_did_log(&state.webvh_ks, &vta_did).await {
        Ok(Some(log)) => jsonl_response(log),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            // Genuine storage failure: keep it visible in logs but return an
            // opaque 500 (no internal detail in the body).
            tracing::warn!(error = %e, "failed to read VTA did.jsonl from store");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `(vta_did, canonical_request_path)` for the configured VTA DID, or `None`
/// if the VTA has no self-hosted `did:webvh` identity (no DID configured, the
/// DID isn't `did:webvh`, or it can't be parsed into a webvh URL). Collapses
/// every "not self-hosting" reason into `None` so callers emit a single opaque
/// 404.
async fn configured_canonical_path(state: &AppState) -> Option<(String, String)> {
    let vta_did = state.config.read().await.vta_did.clone()?;
    if !vta_did.starts_with("did:webvh:") {
        return None;
    }
    let parsed = WebVHURL::parse_did_url(&vta_did).ok()?;
    let path = parsed.path.trim_end_matches('/');
    Some((vta_did, format!("{path}/did.jsonl")))
}

/// Build the 200 response with the spec content type and `nosniff`. Built
/// explicitly (rather than via a `String` body) so there is exactly one
/// `content-type` header — these endpoints sit at the router root, outside any
/// website-router security-headers middleware, so a browser must not be able
/// to content-sniff the jsonl into something executable. Mirrors the VTC's
/// `did_log` route.
fn jsonl_response(log: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", JSONL_CONTENT_TYPE)
        .header("x-content-type-options", "nosniff")
        .body(Body::from(log))
        .expect("static headers + owned body always build a valid response")
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// GET `uri` against a freshly-built app configured with `vta_did` and an
    /// optional seeded `(did, log)` entry. Returns (status, content-type, body).
    async fn get(
        uri: &str,
        vta_did: Option<&str>,
        seed: Option<(&str, &str)>,
    ) -> (StatusCode, Option<String>, Vec<u8>) {
        let (app, ctx) = crate::test_support::build_test_app().await;
        ctx.config.write().await.vta_did = vta_did.map(str::to_string);
        if let Some((did, log)) = seed {
            crate::webvh_store::store_did_log(&ctx.webvh_ks, did, log)
                .await
                .expect("seed did log");
        }
        let req = Request::builder()
            .uri(uri)
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string());
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, content_type, body)
    }

    #[tokio::test]
    async fn well_known_serves_root_webvh_log_with_spec_headers() {
        let did = "did:webvh:QmSCID:example.com";
        let log = r#"{"versionId":"1-abc","versionTime":"2025-01-01T00:00:00Z"}"#;
        let (status, ct, body) = get("/.well-known/did.jsonl", Some(did), Some((did, log))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct.as_deref(), Some("text/jsonl"));
        assert_eq!(body, log.as_bytes());
    }

    #[tokio::test]
    async fn well_known_404_for_pathful_did() {
        let did = "did:webvh:QmSCID:example.com:tenant:vta";
        let (status, _, body) = get("/.well-known/did.jsonl", Some(did), Some((did, "{}\n"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "404 must be opaque (empty body)");
    }

    #[tokio::test]
    async fn canonical_path_serves_pathful_log() {
        let did = "did:webvh:QmSCID:example.com:tenant:vta";
        let log = "{\"versionId\":\"1-abc\"}\n";
        let (status, ct, body) = get("/tenant/vta/did.jsonl", Some(did), Some((did, log))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct.as_deref(), Some("text/jsonl"));
        assert_eq!(body, log.as_bytes());
    }

    #[tokio::test]
    async fn catch_all_404_for_non_canonical_did_jsonl_path() {
        let did = "did:webvh:QmSCID:example.com:tenant:vta";
        let (status, _, body) = get("/wrong/path/did.jsonl", Some(did), Some((did, "{}\n"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "non-canonical path must be opaque");
    }

    #[tokio::test]
    async fn catch_all_unknown_path_is_bare_404() {
        // An unrelated unknown GET must look exactly like axum's default 404
        // (empty body) — the catch-all must not change the 404 surface.
        let did = "did:webvh:QmSCID:example.com";
        let (status, _, body) = get("/totally/unknown/resource", Some(did), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn well_known_404_when_no_vta_did() {
        let (status, _, body) = get("/.well-known/did.jsonl", None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "must not reveal that no DID is configured");
    }

    #[tokio::test]
    async fn well_known_404_for_non_webvh_did() {
        // A did:key VTA must 404 opaquely — no fingerprinting the method.
        let (status, _, body) = get("/.well-known/did.jsonl", Some("did:key:z6Mkabc"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn catch_all_does_not_shadow_authed_route() {
        // GET /keys is a real authed route. Without a bearer it must be
        // rejected by its auth extractor (not swallowed into the catch-all's
        // 404), proving static routes keep precedence over the wildcard.
        let (app, _ctx) = crate::test_support::build_test_app().await;
        let req = Request::builder()
            .uri("/keys")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "real route must not be shadowed by the did.jsonl catch-all"
        );
    }
}
