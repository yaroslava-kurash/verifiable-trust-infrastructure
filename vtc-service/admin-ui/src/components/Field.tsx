import type { ReactNode } from "react";

// A labelled form-field wrapper used across every plugin. Renders
// the same `<label class="field"><span class="field-label">...</span>
// {children}</label>` shape the design language locked at phase 2.
// Pulled out so the four plugins that previously inlined a private
// `Field` helper (acl, members, policies, profile) share a single
// canonical implementation.
export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}
