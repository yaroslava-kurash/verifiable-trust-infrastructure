// Shared formatting helpers used across plugins.
//
// Each helper was previously duplicated in 3–5 plugin files with
// minor variations (some `formatIso`, some `formatEpoch`, some hand-
// rolled `shortDid`). Consolidating here keeps the on-screen
// presentation consistent and gives reviewers one place to change
// when the formatting needs to evolve.

/**
 * Truncate a long opaque identifier (DID, session id, JTI, hash) so
 * it fits in a table cell while still letting an operator visually
 * compare two values. Keeps the first `head` and last `tail`
 * characters and joins with `…`. Returns the input unchanged when
 * it's shorter than the would-be truncation overhead.
 */
export function shorten(value: string, head = 8, tail = 4): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/**
 * Format an RFC3339 / ISO-8601 timestamp into the operator's
 * locale-string. Used for `joinedAt`, `created_at`, `activated_at`,
 * audit envelope timestamps, etc. Falls back to the raw input on
 * parse failure so the cell never goes blank.
 */
export function formatIso(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

/**
 * Format a Unix-seconds epoch (i.e. `seconds since 1970-01-01 UTC`)
 * into the operator's locale-string. Used by session / ACL rows
 * that carry epochs rather than ISO strings.
 */
export function formatEpoch(epoch: number): string {
  try {
    return new Date(epoch * 1000).toLocaleString();
  } catch {
    return String(epoch);
  }
}
