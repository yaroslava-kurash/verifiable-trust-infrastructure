//! Structured error type for VTA SDK operations.

/// Errors returned by VTA SDK client operations.
#[derive(Debug, thiserror::Error)]
pub enum VtaError {
    /// Network-level error (connection refused, timeout, DNS failure).
    #[cfg(feature = "client")]
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Authentication failed (401) or token expired.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Resource not found (404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Request validation error (400).
    #[error("validation error: {0}")]
    Validation(String),

    /// Permission denied (403).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Conflict (409) — e.g. duplicate key ID.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Gone (410) — the resource existed but is now permanently unavailable.
    /// Most often emitted by the bootstrap carve-out endpoint after it has
    /// been consumed; the CLI surfaces this with a "did you mean to run
    /// `… provision-request`" hint instead of a flat string.
    #[error("gone: {0}")]
    Gone(String),

    /// Server error (5xx).
    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    /// The operation does not support the transport the client is
    /// configured for (e.g. calling a REST-only helper on a client built
    /// with DIDComm-only transport, or vice versa).
    #[error("unsupported transport: {0}")]
    UnsupportedTransport(String),

    /// DIDComm transport failure (pack/send/pickup). Network-ish —
    /// caller may want to retry. Distinct from [`Self::Network`] which
    /// is REST-specific and carries a `reqwest::Error`.
    #[error("didcomm transport error: {0}")]
    DidcommTransport(String),

    /// Remote endpoint returned an error message over DIDComm. The VTA
    /// (or the peer) encoded a specific status; prefer matching on
    /// this variant before falling back to [`Self::Protocol`].
    #[error("didcomm remote error ({code}): {comment}")]
    DidcommRemote { code: String, comment: String },

    /// Catch-all for protocol-level errors that don't map to a typed
    /// variant above. Prefer a typed variant when adding new call
    /// sites — this exists so legacy dispatch paths still compile.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

impl VtaError {
    /// Create from an HTTP response status and error body.
    #[cfg(feature = "client")]
    pub(crate) fn from_http(status: reqwest::StatusCode, body: String) -> Self {
        match status.as_u16() {
            401 => Self::Auth(body),
            403 => Self::Forbidden(body),
            404 => Self::NotFound(body),
            400 | 422 => Self::Validation(body),
            409 => Self::Conflict(body),
            410 => Self::Gone(body),
            s if s >= 500 => Self::Server { status: s, body },
            s => Self::Other(format!("{s}: {body}")),
        }
    }

    /// Returns true if the resource was permanently consumed/gone (410).
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Gone(_))
    }

    /// Returns true if a create/insert collided with an existing entry (409).
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
    }

    /// Returns true if this is an authentication/authorization error.
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Auth(_) | Self::Forbidden(_))
    }

    /// Returns true if this is a network-level error (retryable).
    pub fn is_network(&self) -> bool {
        #[cfg(feature = "client")]
        if matches!(self, Self::Network(_)) {
            return true;
        }
        false
    }

    /// Returns true if the resource was not found.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

impl From<String> for VtaError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<&str> for VtaError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

// Backward-compat conversion from `Box<dyn Error>` (legacy CLI handler
// return type) into a typed `VtaError`.
//
// Tries `Box::downcast::<VtaError>` first — many shared-CLI handlers
// return `Box<dyn Error>` whose inner is in fact a `VtaError` carried
// from the SDK call. If we collapsed unconditionally to `Other(String)`,
// the typed dispatch on `VtaError::Conflict` / `Gone` / `Forbidden` that
// `print_cli_error` and the per-command "did you mean …" hints rely on
// would silently fail.
//
// For new integrations, return a `VtaError` directly or add a typed
// variant with `#[from]` on the underlying cause so the source chain is
// preserved. The legacy collapse to `Other(String)` is the fallback
// only for non-VtaError errors.
impl From<Box<dyn std::error::Error>> for VtaError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        match e.downcast::<VtaError>() {
            Ok(typed) => *typed,
            Err(other) => Self::Other(other.to_string()),
        }
    }
}

impl From<crate::did_key::DidKeyError> for VtaError {
    fn from(e: crate::did_key::DidKeyError) -> Self {
        Self::Other(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boxed_vta_error_preserves_typed_variant_through_conversion() {
        // Regression: shared CLI handlers return Box<dyn Error> whose inner
        // is a VtaError. The From impl must downcast first so per-command
        // hints can still match on Conflict / Gone / etc.
        let original = VtaError::Conflict("context already exists".into());
        let boxed: Box<dyn std::error::Error> = Box::new(original);
        let recovered: VtaError = boxed.into();
        assert!(
            matches!(recovered, VtaError::Conflict(_)),
            "From<Box<dyn Error>> must preserve the typed variant when the inner is \
             a VtaError — got {recovered:?}"
        );
    }

    #[test]
    fn boxed_non_vta_error_falls_back_to_other() {
        // Strings, io errors, etc. flow through Other(String) as before.
        let boxed: Box<dyn std::error::Error> = "plain string error".into();
        let recovered: VtaError = boxed.into();
        assert!(matches!(recovered, VtaError::Other(_)));
    }

    #[test]
    fn from_http_410_maps_to_gone() {
        #[cfg(feature = "client")]
        {
            let err = VtaError::from_http(reqwest::StatusCode::GONE, "carve-out closed".into());
            assert!(err.is_gone(), "410 must map to VtaError::Gone, got {err:?}");
        }
    }
}
