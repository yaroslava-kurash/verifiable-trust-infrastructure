// Passkey login page.
//
// Operator clicks "Sign in with passkey" → POST to
// `/v1/auth/passkey-login/start` → run `navigator.credentials.get`
// → POST to `/finish` → daemon sets the `vtc_admin_session` cookie
// (HttpOnly) and the `csrf` cookie (JS-readable). The shell then
// reloads its sign-in probe and renders the authenticated UI.

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { postJson } from "@/lib/api";

const TRUST_TASK_START =
  "https://trusttasks.org/openvtc/vtc/auth/passkey-login/start/1.0";
const TRUST_TASK_FINISH =
  "https://trusttasks.org/openvtc/vtc/auth/passkey-login/finish/1.0";

type Phase =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "error"; message: string; hint?: string };

function base64urlToBuffer(b64: string): ArrayBuffer {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64url(buf: ArrayBuffer): string {
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

export function Login() {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const queryClient = useQueryClient();

  const signIn = async () => {
    setPhase({ kind: "running" });
    try {
      // ── /passkey-login/start ──
      const start = await postJson<{
        authId: string;
        options: { publicKey: PublicKeyCredentialRequestOptionsJSON };
      }>("/v1/auth/passkey-login/start", undefined, {
        trustTask: TRUST_TASK_START,
      });

      const publicKey = start.options.publicKey;
      const requestOptions: PublicKeyCredentialRequestOptions = {
        ...publicKey,
        challenge: base64urlToBuffer(publicKey.challenge as unknown as string),
        allowCredentials: (publicKey.allowCredentials ?? []).map((c) => ({
          ...c,
          id: base64urlToBuffer(c.id as unknown as string),
        })),
      } as unknown as PublicKeyCredentialRequestOptions;

      // ── navigator.credentials.get ──
      const credential = (await navigator.credentials.get({
        publicKey: requestOptions,
      })) as PublicKeyCredential | null;
      if (!credential) {
        setPhase({
          kind: "error",
          message: "Passkey ceremony returned no credential.",
          hint: "Retry, or use a different authenticator.",
        });
        return;
      }
      const response =
        credential.response as AuthenticatorAssertionResponse;

      // ── /passkey-login/finish ──
      await postJson<unknown>(
        "/v1/auth/passkey-login/finish",
        {
          auth_id: start.authId,
          credential: {
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
          },
        },
        { trustTask: TRUST_TASK_FINISH },
      );

      // Success — the daemon set the cookies. Invalidate the
      // session probe so the shell re-renders the authenticated
      // tree.
      await queryClient.invalidateQueries({ queryKey: ["session-probe"] });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      let hint: string | undefined;
      if (e.status === 401) {
        hint =
          "Your passkey isn't recognised, or the ACL revoked your admin role. " +
          "Ask another admin to issue a fresh `vtc admin invite --did <your-did>`.";
      } else if (e.status === 404) {
        hint = "No passkeys are registered yet — claim the install URL first.";
      } else if (
        err instanceof DOMException &&
        err.name === "NotAllowedError"
      ) {
        hint = "Passkey prompt cancelled or denied by the browser.";
      }
      setPhase({
        kind: "error",
        message: e.message ?? String(err),
        hint,
      });
    }
  };

  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>VTC Admin</h2>
        <p className="lead">Sign in with the passkey you registered at install.</p>
        <button
          type="button"
          className="primary"
          onClick={signIn}
          disabled={phase.kind === "running"}
        >
          {phase.kind === "running"
            ? "Waiting for passkey…"
            : "Sign in with passkey"}
        </button>
        {phase.kind === "error" && (
          <section className="card error">
            <h3>Sign-in failed</h3>
            <p>{phase.message}</p>
            {phase.hint && <p className="lead">{phase.hint}</p>}
          </section>
        )}
        <footer>
          <p className="lead">
            No passkey yet? Open the install URL the daemon operator
            shared, or ask them to mint a fresh one via{" "}
            <code>vtc admin invite</code>.
          </p>
        </footer>
      </div>
    </section>
  );
}

interface PublicKeyCredentialRequestOptionsJSON {
  challenge: BufferSource;
  allowCredentials?: ReadonlyArray<
    { id: BufferSource } & Record<string, unknown>
  >;
  [k: string]: unknown;
}
