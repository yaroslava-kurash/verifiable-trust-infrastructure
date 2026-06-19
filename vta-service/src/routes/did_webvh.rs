use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use vta_sdk::protocols::did_management::{
    create::{CreateDidWebvhBody, CreateDidWebvhResultBody},
    list::ListDidsWebvhResultBody,
    servers::{
        AddWebvhServerResultBody, ListWebvhServersResultBody, RegisterDidWithServerBody,
        RegisterDidWithServerResultBody, UpdateWebvhServerResultBody,
    },
};
use vta_sdk::webvh::WebvhDidRecord;

use crate::auth::{AdminAuth, AuthClaims, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::operations::did_webvh::{
    RegisterDidWithServerError, RegisterDidWithServerParams, RotateDidWebvhKeysOptions,
    UpdateDidWebvhOptions, UpdateDidWebvhResult, register_did_with_server,
};
use crate::server::AppState;
use didwebvh_rs::url::WebVHURL;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddServerRequest {
    pub id: String,
    pub did: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListDidsQuery {
    pub context_id: Option<String>,
    pub server_id: Option<String>,
}

// -- Server routes --

/// POST /webvh/servers — register a webvh hosting server. Auth: super-admin.
#[utoipa::path(
    post, path = "/webvh/servers", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    request_body = AddServerRequest,
    responses(
        (status = 201, description = "Server registered", body = AddWebvhServerResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
    ),
)]
pub async fn add_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<AddServerRequest>,
) -> Result<(StatusCode, Json<AddWebvhServerResultBody>), AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let result = operations::did_webvh::add_webvh_server(
        &state.webvh_ks,
        &auth.0,
        &req.id,
        &req.did,
        req.label,
        did_resolver,
        "rest",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /webvh/servers — list registered webvh hosting servers. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/servers", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Registered servers", body = ListWebvhServersResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn list_servers_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ListWebvhServersResultBody>, AppError> {
    let result = operations::did_webvh::list_webvh_servers(&state.webvh_ks, &auth, "rest").await?;
    Ok(Json(result))
}

/// `GET /webvh/servers/:id/domains` — relay the registered hosting
/// server's `/api/me/domains` view to the caller. Used by
/// `pnm did-mgmt list-domains` and by the interactive `--domain`
/// prompt in `pnm did-mgmt dids create` / `register`. Authentication
/// to the hosting server uses the VTA's own credentials.
#[utoipa::path(
    get, path = "/webvh/servers/{id}/domains", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Server identifier")),
    responses(
        (status = 200, description = "Caller-scoped hosting domains", body = vta_sdk::protocols::did_management::servers::ListWebvhServerDomainsResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "Server not found"),
    ),
)]
pub async fn list_server_domains_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<
    Json<vta_sdk::protocols::did_management::servers::ListWebvhServerDomainsResultBody>,
    AppError,
> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let config = state.config.read().await;
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = operations::did_webvh::list_webvh_server_domains(
        &deps,
        &auth,
        config.vta_did.as_deref(),
        &id,
    )
    .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateServerRequest {
    pub label: Option<String>,
}

/// PATCH /webvh/servers/{id} — update a registered server's metadata. Auth: super-admin.
#[utoipa::path(
    patch, path = "/webvh/servers/{id}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Server identifier")),
    request_body = UpdateServerRequest,
    responses(
        (status = 200, description = "Server updated", body = UpdateWebvhServerResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "Server not found"),
    ),
)]
pub async fn update_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateServerRequest>,
) -> Result<Json<UpdateWebvhServerResultBody>, AppError> {
    let result = operations::did_webvh::update_webvh_server(
        &state.webvh_ks,
        &auth.0,
        &id,
        req.label,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// DELETE /webvh/servers/{id} — remove a registered server. Auth: super-admin.
#[utoipa::path(
    delete, path = "/webvh/servers/{id}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Server identifier")),
    responses(
        (status = 204, description = "Server removed"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "Server not found"),
    ),
)]
pub async fn remove_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    operations::did_webvh::remove_webvh_server(&state.webvh_ks, &auth.0, &id, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}

// -- DID routes --

/// POST /webvh/dids — create a new webvh DID. Auth: admin.
#[utoipa::path(
    post, path = "/webvh/dids", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    request_body = CreateDidWebvhBody,
    responses(
        (status = 201, description = "DID created", body = CreateDidWebvhResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn create_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<CreateDidWebvhBody>,
) -> Result<(StatusCode, Json<CreateDidWebvhResultBody>), AppError> {
    let config = state.config.read().await;
    let params = body.into();
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let deps =
        operations::did_webvh::CreateDidWebvhDeps::from_app_state(&state, &config, did_resolver);
    let result = operations::did_webvh::create_did_webvh(&deps, &auth.0, params, "rest").await?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /webvh/dids — list webvh DIDs with optional filters. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/dids", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(ListDidsQuery),
    responses(
        (status = 200, description = "DID records", body = ListDidsWebvhResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn list_dids_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListDidsQuery>,
) -> Result<Json<ListDidsWebvhResultBody>, AppError> {
    let result = operations::did_webvh::list_dids_webvh(
        &state.webvh_ks,
        &auth,
        query.context_id.as_deref(),
        query.server_id.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// GET /webvh/dids/{did} — retrieve a single webvh DID record. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/dids/{did}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 200, description = "DID record", body = WebvhDidRecord),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn get_did_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<WebvhDidRecord>, AppError> {
    let result = operations::did_webvh::get_did_webvh(&state.webvh_ks, &auth, &did, "rest").await?;
    Ok(Json(result))
}

/// GET /webvh/dids/{did}/log — retrieve the did.jsonl log for a DID. Auth: any authenticated user.
#[utoipa::path(
    get, path = "/webvh/dids/{did}/log", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 200, description = "DID log", body = operations::did_webvh::GetDidWebvhLogResult),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn get_did_log_handler(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<operations::did_webvh::GetDidWebvhLogResult>, AppError> {
    let result =
        operations::did_webvh::get_did_webvh_log(&state.webvh_ks, &auth, &did, "rest").await?;
    Ok(Json(result))
}

/// `GET /did/{did}/log` — public, unauthenticated.
///
/// Returns the raw `did.jsonl` bytes for a DID the VTA knows. 404 if
/// unknown. Matches webvh's native design: DID logs are world-readable
/// (security is cryptographic via signatures + SCID anchoring, not
/// access-gated). Rate-limited via the `unauth_layer` at the router.
///
/// This is a snapshot of the log at provisioning time — once the
/// integration boots and publishes on its own webvh host, that copy
/// becomes the live source of truth. Use this endpoint for audit,
/// debugging, or republication fallback; not as a general DID
/// resolver. See `docs/02-vta/provision-integration.md` §"did.jsonl
/// retrieval" for the full semantics.
#[utoipa::path(
    get, path = "/did/{did}/log", tag = "did-webvh",
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 200, description = "did.jsonl log", content_type = "application/jsonl"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn get_did_log_public_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<
    (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        String,
    ),
    AppError,
> {
    use axum::http::StatusCode;
    let log = crate::webvh_store::get_did_log(&state.webvh_ks, &did).await?;
    let log = log.ok_or_else(|| AppError::NotFound(format!("webvh DID log not found: {did}")))?;
    Ok((StatusCode::OK, [("content-type", "application/jsonl")], log))
}

/// `GET /.well-known/did.jsonl` — public, unauthenticated.
///
/// Serves the VTA's own `did:webvh` log at the standard resolver path. A
/// resolver reconstructing the fetch URL from `did:webvh:SCID:domain`
/// derives `https://domain/.well-known/did.jsonl` — this endpoint answers
/// that request. Only meaningful when the VTA was set up with
/// `[vta_did] kind = "create_webvh"` and `url = "https://domain"` (no
/// subpath); returns 404 if the VTA has no webvh identity or no log stored.
/// Rate-limited via `unauth_layer` at the router.
#[utoipa::path(
    get, path = "/.well-known/did.jsonl", tag = "did-webvh",
    responses(
        (status = 200, description = "VTA did.jsonl log", content_type = "application/jsonl"),
        (status = 404, description = "VTA has no self-hosted did:webvh identity or log not found"),
    ),
)]
pub async fn get_vta_well_known_did_log_handler(
    State(state): State<AppState>,
) -> Result<
    (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        String,
    ),
    AppError,
> {
    use axum::http::StatusCode;
    let vta_did = configured_vta_webvh_did(&state).await?;
    let expected_path = canonical_did_log_path(&vta_did)?;
    if expected_path != "/.well-known/did.jsonl" {
        return Err(AppError::NotFound(
            "VTA DID resolves to a pathful did.jsonl endpoint, not /.well-known/did.jsonl".into(),
        ));
    }
    let log = load_vta_did_log(&state, &vta_did).await?;
    Ok((StatusCode::OK, [("content-type", "application/jsonl")], log))
}

/// `GET /{*did_log_path}` — public, unauthenticated.
///
/// Catch-all route used only for canonical `did:webvh` retrieval when the
/// configured VTA DID has path segments (for example `/tenant/vta/did.jsonl`).
/// Returns 404 for every non-canonical path so it is safe to mount as a
/// fallback on the unauth branch.
pub async fn get_vta_canonical_did_log_handler(
    State(state): State<AppState>,
    Path(did_log_path): Path<String>,
) -> Result<
    (
        axum::http::StatusCode,
        [(&'static str, &'static str); 1],
        String,
    ),
    AppError,
> {
    use axum::http::StatusCode;

    let request_path = format!("/{}", did_log_path.trim_start_matches('/'));
    if !request_path.ends_with("/did.jsonl") {
        return Err(AppError::NotFound("Not Found".into()));
    }

    let vta_did = configured_vta_webvh_did(&state).await?;
    let expected_path = canonical_did_log_path(&vta_did)?;
    if request_path != expected_path {
        return Err(AppError::NotFound("Not Found".into()));
    }

    let log = load_vta_did_log(&state, &vta_did).await?;
    Ok((StatusCode::OK, [("content-type", "application/jsonl")], log))
}

async fn configured_vta_webvh_did(state: &AppState) -> Result<String, AppError> {
    let vta_did = state
        .config
        .read()
        .await
        .vta_did
        .clone()
        .ok_or_else(|| AppError::NotFound("VTA has no configured DID".into()))?;
    if !vta_did.starts_with("did:webvh:") {
        return Err(AppError::NotFound(
            "VTA DID is not a did:webvh identity".into(),
        ));
    }
    Ok(vta_did)
}

fn canonical_did_log_path(vta_did: &str) -> Result<String, AppError> {
    let parsed = WebVHURL::parse_did_url(vta_did).map_err(|e| {
        AppError::NotFound(format!("VTA DID cannot be transformed into a webvh URL: {e}"))
    })?;
    let path = parsed.path.trim_end_matches('/');
    Ok(format!("{path}/did.jsonl"))
}

async fn load_vta_did_log(state: &AppState, vta_did: &str) -> Result<String, AppError> {
    let log = crate::webvh_store::get_did_log(&state.webvh_ks, vta_did).await?;
    log.ok_or_else(|| AppError::NotFound(format!("did.jsonl log not found for VTA DID: {vta_did}")))
}

/// DELETE /webvh/dids/{did} — delete a webvh DID. Auth: admin.
#[utoipa::path(
    delete, path = "/webvh/dids/{did}", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 204, description = "DID deleted"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn delete_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    operations::did_webvh::delete_did_webvh(&deps, &auth.0, &did, vta_did.as_deref(), "rest")
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /contexts/{ctx_id}/dids/{scid}/update` — apply a generic
/// update to an existing webvh DID. The `ctx_id` path component is
/// validated against the DID's context inside the operation; mismatches
/// surface as 404 to avoid cross-context existence leaks.
#[utoipa::path(
    post, path = "/contexts/{ctx_id}/dids/{scid}/update", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(
        ("ctx_id" = String, Path, description = "Context identifier"),
        ("scid" = String, Path, description = "DID SCID"),
    ),
    request_body = UpdateDidWebvhOptions,
    responses(
        (status = 200, description = "DID updated", body = UpdateDidWebvhResult),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn update_did_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((_ctx_id, scid)): Path<(String, String)>,
    Json(body): Json<UpdateDidWebvhOptions>,
) -> Result<Json<UpdateDidWebvhResult>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = operations::did_webvh::update_did_webvh(
        &deps,
        &auth.0,
        &scid,
        body,
        vta_did.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// `POST /contexts/{ctx_id}/dids/{scid}/rotate-keys` — rotate every
/// verificationMethod's keys + drive an update. Mirrors
/// [`update_did_handler`].
#[utoipa::path(
    post, path = "/contexts/{ctx_id}/dids/{scid}/rotate-keys", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(
        ("ctx_id" = String, Path, description = "Context identifier"),
        ("scid" = String, Path, description = "DID SCID"),
    ),
    request_body = RotateDidWebvhKeysOptions,
    responses(
        (status = 200, description = "Keys rotated", body = UpdateDidWebvhResult),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn rotate_did_keys_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((_ctx_id, scid)): Path<(String, String)>,
    Json(body): Json<RotateDidWebvhKeysOptions>,
) -> Result<Json<UpdateDidWebvhResult>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = operations::did_webvh::rotate_did_webvh_keys(
        &deps,
        &auth.0,
        &scid,
        body,
        vta_did.as_deref(),
        "rest",
    )
    .await?;
    Ok(Json(result))
}

/// `POST /webvh/dids/{did}/register-server` — promote a serverless
/// DID to a server-managed one. Auth: super-admin. The DID in the
/// path must match the body's `did` field; the body's `server_id`
/// must be a previously-registered server.
#[utoipa::path(
    post, path = "/webvh/dids/{did}/register-server", tag = "did-webvh",
    security(("bearer_jwt" = [])),
    params(("did" = String, Path, description = "DID identifier")),
    request_body = RegisterDidWithServerBody,
    responses(
        (status = 200, description = "DID registered with server", body = RegisterDidWithServerResultBody),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a super-admin"),
        (status = 404, description = "DID or server not found"),
    ),
)]
pub async fn register_did_with_server_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(body): Json<RegisterDidWithServerBody>,
) -> Result<Json<RegisterDidWithServerResultBody>, AppError> {
    if did != body.did {
        return Err(AppError::Validation(format!(
            "DID in path (`{did}`) does not match body `did` (`{}`)",
            body.did
        )));
    }
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let deps = operations::did_webvh::WebvhDeps::from_app_state(&state, did_resolver);
    let result = register_did_with_server(
        &deps,
        &auth.0,
        RegisterDidWithServerParams {
            did: body.did,
            server_id: body.server_id,
            force: body.force,
            domain: body.domain,
        },
        vta_did.as_deref(),
        "rest",
    )
    .await
    .map_err(map_register_err)?;
    Ok(Json(RegisterDidWithServerResultBody {
        did: result.did,
        server_id: result.server_id,
        log_entry_count: result.log_entry_count,
    }))
}

/// Map `RegisterDidWithServerError` onto `AppError` so the
/// existing route-error machinery surfaces an appropriate status
/// (404 for missing DID/server/log, 409 for already-server-managed,
/// 400 for malformed DID URLs, 500 otherwise).
fn map_register_err(e: RegisterDidWithServerError) -> AppError {
    use RegisterDidWithServerError as E;
    match e {
        E::Auth(msg) => AppError::Forbidden(msg),
        E::DidNotFound(msg) | E::ServerNotFound(msg) | E::LogMissing(msg) => {
            AppError::NotFound(msg)
        }
        E::AlreadyServerManaged { .. } | E::Conflict(_) => AppError::Conflict(e.to_string()),
        E::Transport(msg) | E::Publish(msg) => AppError::Internal(format!("publish: {msg}")),
        E::DidUrlParse { .. } => AppError::Validation(e.to_string()),
        E::Storage(msg) => AppError::Internal(msg),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[cfg(feature = "webvh")]
    async fn seed_log(ctx: &crate::test_support::TestAppContext, did: &str, log: &str) {
        crate::webvh_store::store_did_log(&ctx.webvh_ks, did, log)
            .await
            .expect("seed did log");
    }

    async fn set_vta_did(ctx: &crate::test_support::TestAppContext, did: Option<String>) {
        ctx.config.write().await.vta_did = did;
    }

    #[tokio::test]
    #[cfg(feature = "webvh")]
    async fn well_known_returns_log_for_root_webvh_vta_did() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let webvh_did = "did:webvh:QmSCID:example.com";
        let log_content = r#"{"versionId":"1-abc","versionTime":"2025-01-01T00:00:00Z"}"#;

        set_vta_did(&ctx, Some(webvh_did.to_string())).await;
        seed_log(&ctx, webvh_did, log_content).await;

        let req = Request::builder()
            .uri("/.well-known/did.jsonl")
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), log_content.as_bytes());
    }

    #[tokio::test]
    #[cfg(feature = "webvh")]
    async fn well_known_returns_404_for_pathful_webvh_vta_did() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let webvh_did = "did:webvh:QmSCID:example.com:tenant:vta";
        set_vta_did(&ctx, Some(webvh_did.to_string())).await;
        seed_log(&ctx, webvh_did, "{}\n").await;

        let req = Request::builder()
            .uri("/.well-known/did.jsonl")
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[cfg(feature = "webvh")]
    async fn canonical_path_returns_log_for_pathful_webvh_vta_did() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let webvh_did = "did:webvh:QmSCID:example.com:tenant:vta";
        let log_content = "{\"versionId\":\"1-abc\"}\n";
        set_vta_did(&ctx, Some(webvh_did.to_string())).await;
        seed_log(&ctx, webvh_did, log_content).await;

        let req = Request::builder()
            .uri("/tenant/vta/did.jsonl")
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), log_content.as_bytes());
    }
}
