//! Convenience re-exports for the most commonly used VTA SDK types.
//!
//! ```ignore
//! use vta_sdk::prelude::*;
//! ```

// Error
pub use crate::error::VtaError;

// Keys
pub use crate::keys::{KeyRecord, KeyStatus, KeyType};

// Contexts
pub use crate::contexts::ContextRecord;

// Credentials
pub use crate::credentials::CredentialBundle;

// DID secrets
pub use crate::did_secrets::{DidSecretsBundle, SecretEntry};

// Client (feature-gated)
#[cfg(feature = "client")]
pub use crate::client::{
    AclEntryResponse, AclListResponse, ConfigResponse, ContextListResponse, ContextResponse,
    CreateAclRequest, CreateContextRequest, CreateDidWebvhResponse, CreateKeyRequest,
    CreateKeyResponse, DeleteContextPreviewResponse, DeleteContextResponse, DidTemplate,
    DidTemplateError, DidTemplateRecord, DidTemplateScope, GetKeySecretResponse, HealthResponse,
    ImportKeyRequest, ImportKeyResponse, InvalidateKeyResponse, ListDidsWebvhResponse,
    ListKeysResponse, ListWebvhServersResponse, RenameKeyResponse, SignResponse, TemplateVars,
    UpdateAclRequest, UpdateConfigRequest, UpdateContextDidRequest, VtaClient, WrappingKeyResponse,
};

// DID key utilities
pub use crate::did_key::{decode_private_key_multibase, ed25519_multibase_pubkey};

#[cfg(feature = "client")]
pub use crate::did_key::secret_from_key_response;

// Integration (feature-gated)
#[cfg(feature = "integration")]
pub use crate::integration::{
    SecretCache, SecretSource, StartupResult, VtaIntegrationError, VtaServiceConfig, authenticate,
    startup,
};

// Protocols — commonly used request/response bodies
pub use crate::protocols::audit_management::list::ListAuditLogsBody;
