// Tiny inline copy-to-clipboard button.
//
// Renders a 24×24 ghost-styled button with a lucide Clipboard icon
// that flips to a Check + green border for ~1.6s on a successful
// copy. Falls back to a hidden-textarea + `execCommand("copy")` for
// non-secure contexts (http:// during local dev) where
// `navigator.clipboard` is unavailable.
//
// Used inline next to any monospace identifier the operator might
// want to copy — DIDs, JTIs, session IDs, etc. Keep it close to the
// value (not in a separate "actions" column) so the affordance is
// obvious without scanning.

import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";

import { useToast } from "@/lib/toast";

const FEEDBACK_MS = 1600;

interface CopyButtonProps {
  /** The text to copy. When falsy or empty, the button is disabled. */
  value: string | null | undefined;
  /** Accessible label + tooltip. Defaults to "Copy". */
  label?: string;
  /** Optional toast on success. When omitted, only the icon flash fires. */
  successMessage?: string;
}

export function CopyButton({
  value,
  label = "Copy",
  successMessage,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<number | null>(null);
  const toast = useToast();
  const empty = !value;

  useEffect(
    () => () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    },
    [],
  );

  const onClick = async () => {
    if (!value) return;
    try {
      await copyText(value);
      setCopied(true);
      if (successMessage) toast.push("success", successMessage);
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      timerRef.current = window.setTimeout(() => {
        setCopied(false);
        timerRef.current = null;
      }, FEEDBACK_MS);
    } catch (err) {
      toast.pushFromError(err, "Copy failed");
    }
  };

  return (
    <button
      type="button"
      className={`copy-icon-btn${copied ? " copied" : ""}`}
      onClick={onClick}
      disabled={empty}
      aria-label={copied ? "Copied" : label}
      title={empty ? "Nothing to copy" : copied ? "Copied" : label}
    >
      {copied ? (
        <Check size={14} strokeWidth={2} aria-hidden="true" />
      ) : (
        <Copy size={14} strokeWidth={1.75} aria-hidden="true" />
      )}
    </button>
  );
}

async function copyText(text: string) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
  } finally {
    document.body.removeChild(ta);
  }
}
