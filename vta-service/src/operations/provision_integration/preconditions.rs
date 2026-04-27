//! Authorization + request-shape checks that run before the VTA
//! mutates any state. Failing here leaves the store untouched — a typo
//! in a template name or a missing context is surfaced with a concrete
//! operator remediation before we mint keys or write ACL rows.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::auth::AuthClaims;
use crate::error::AppError;
use vta_sdk::provision_integration::{BootstrapAsk, DidTemplateRef, VerifiedBootstrapRequest};

use super::ProvisionIntegrationDeps;

pub(super) async fn preconditions(
    state: &ProvisionIntegrationDeps,
    auth: &AuthClaims,
    context: &str,
    request: &VerifiedBootstrapRequest,
) -> Result<(), AppError> {
    auth.require_admin()?;
    auth.require_context(context)?;

    // Context must exist.
    if crate::contexts::get_context(&state.contexts_ks, context)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "context '{context}' is not registered on this VTA — create it first via \
             'vta context create --id {context}' (offline) or 'pnm contexts create' (online), \
             or pass '--create-context' to provision it inline"
        )));
    }

    // If the request carries a context hint, it must agree with the
    // chosen context. Silently normalizing hides operator bugs.
    if let BootstrapAsk::TemplateBootstrap(ask) = request.ask()
        && let Some(ref hint) = ask.context_hint
        && hint != context
    {
        return Err(AppError::Validation(format!(
            "request contextHint '{hint}' does not match provisioning context '{context}'"
        )));
    }

    // Template must be registered. Resolve order matches template-render:
    // context scope → global → built-in. Built-ins always resolve via the
    // SDK's embedded loader; only operator-uploaded templates need a
    // stored record.
    let (template_name, admin_template_name) = match request.ask() {
        BootstrapAsk::TemplateBootstrap(ask) => (
            ask.template.name.clone(),
            ask.admin_template.as_ref().map(|t| t.name.clone()),
        ),
    };
    let template_registered = crate::did_templates::get_context_template(
        &state.did_templates_ks,
        context,
        &template_name,
    )
    .await?
    .is_some()
        || crate::did_templates::get_global_template(&state.did_templates_ks, &template_name)
            .await?
            .is_some()
        || vta_sdk::did_templates::load_embedded(&template_name).is_ok();
    if !template_registered {
        return Err(AppError::Validation(format!(
            "template '{template_name}' is not registered on this VTA. Register it via \
             'pnm did-templates upload {template_name} --file <path>' then retry"
        )));
    }

    // Same check for the admin template, when present. Built-ins
    // (`vta-admin`) always resolve via the SDK's embedded loader; only
    // operator-uploaded templates need a stored record.
    if let Some(name) = admin_template_name {
        let registered =
            crate::did_templates::get_context_template(&state.did_templates_ks, context, &name)
                .await?
                .is_some()
                || crate::did_templates::get_global_template(&state.did_templates_ks, &name)
                    .await?
                    .is_some()
                || vta_sdk::did_templates::load_embedded(&name).is_ok();
        if !registered {
            return Err(AppError::Validation(format!(
                "admin template '{name}' is not registered on this VTA. Register it via \
                 'pnm did-templates upload {name} --file <path>' then retry, or use the \
                 built-in 'vta-admin' template."
            )));
        }
    }

    Ok(())
}

/// Extract the primary template name + variables from an `ask`.
pub(super) fn extract_template(
    ask: &BootstrapAsk,
) -> Result<(String, BTreeMap<String, Value>), AppError> {
    let BootstrapAsk::TemplateBootstrap(ask) = ask;
    Ok((ask.template.name.clone(), ask.template.vars.clone()))
}

/// Extract the optional admin-rollover template reference from an `ask`.
pub(super) fn extract_admin_template(ask: &BootstrapAsk) -> Option<DidTemplateRef> {
    let BootstrapAsk::TemplateBootstrap(ask) = ask;
    ask.admin_template.clone()
}
