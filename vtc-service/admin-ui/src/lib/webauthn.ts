// WebAuthn helpers used by the install ceremony, login, and any
// step-up reauth flow.
//
// The base64url ↔ ArrayBuffer conversions are unavoidable because
// the daemon serialises ArrayBuffer fields as base64url strings
// (webauthn-rs default JSON shape) and `navigator.credentials.*`
// wants real `BufferSource`. We do the conversion once at the
// seam.

export function base64urlToBuffer(b64: string): ArrayBuffer {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Serialise a `PublicKeyCredential` (registration) for JSON
 * transport to the daemon. Mirrors webauthn-rs's expected
 * `RegisterPublicKeyCredential` shape.
 */
export function serializeRegistration(
  credential: PublicKeyCredential,
): unknown {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  };
}

/**
 * Serialise a `PublicKeyCredential` (assertion / authentication)
 * for JSON transport. Used by passkey login and every step-up UV
 * ceremony.
 */
export function serializeAssertion(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle
        ? bufferToBase64url(response.userHandle)
        : null,
    },
  };
}

/**
 * Server-shape of the `publicKey` field webauthn-rs returns at the
 * `/start` endpoint of both registration and assertion flows.
 *
 * `webauthn-rs` serialises `ArrayBuffer`-typed fields as
 * base64url-encoded strings; we walk the known shapes below and
 * convert each in-place into a real `BufferSource` so the browser
 * `navigator.credentials.{create,get}` calls accept them.
 *
 * Typed as a narrow shape rather than `any` so a future drift in
 * the server payload trips the compiler instead of silently
 * skipping a field. Anything we don't recognise stays untouched.
 */
export interface JsonPublicKeyOptions {
  challenge: string | ArrayBuffer;
  user?: {
    id: string | ArrayBuffer;
    [key: string]: unknown;
  };
  excludeCredentials?: Array<{ id: string | ArrayBuffer; [key: string]: unknown }>;
  allowCredentials?: Array<{ id: string | ArrayBuffer; [key: string]: unknown }>;
  // Everything else (rp, pubKeyCredParams, timeout, attestation,
  // authenticatorSelection, …) passes through unchanged.
  [key: string]: unknown;
}

/**
 * Decode the `publicKey` field of a server-issued creation/request
 * challenge: convert the base64url-encoded `challenge`, `user.id`,
 * `excludeCredentials[].id`, and `allowCredentials[].id` to real
 * `ArrayBuffer`s so the browser WebAuthn API accepts them.
 *
 * Returns a **new** object (shallow clone of the top level + each
 * touched nested field) so the original server response can be
 * retried by the caller if the WebAuthn ceremony fails. The
 * previous in-place mutation forced callers to refetch on every
 * retry, which raced the install token's claim-window.
 */
export function decodePublicKeyOptions(
  publicKey: JsonPublicKeyOptions,
): PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions {
  const out: Record<string, unknown> = { ...publicKey };
  if (typeof publicKey.challenge === "string") {
    out.challenge = base64urlToBuffer(publicKey.challenge);
  }
  if (publicKey.user && typeof publicKey.user.id === "string") {
    out.user = { ...publicKey.user, id: base64urlToBuffer(publicKey.user.id) };
  }
  if (Array.isArray(publicKey.excludeCredentials)) {
    out.excludeCredentials = publicKey.excludeCredentials.map((c) =>
      typeof c.id === "string" ? { ...c, id: base64urlToBuffer(c.id) } : c,
    );
  }
  if (Array.isArray(publicKey.allowCredentials)) {
    out.allowCredentials = publicKey.allowCredentials.map((c) =>
      typeof c.id === "string" ? { ...c, id: base64urlToBuffer(c.id) } : c,
    );
  }
  // The webauthn-rs shape matches the browser type once the
  // base64-encoded fields are buffers; the union return type
  // covers both create (`Creation`) and get (`Request`) ceremonies
  // from a single helper. Cast via `unknown` because the
  // intersection of our open `Record<string, unknown>` with the
  // closed browser DOM types isn't structurally provable.
  return out as unknown as
    | PublicKeyCredentialCreationOptions
    | PublicKeyCredentialRequestOptions;
}
