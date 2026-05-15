// Audit trail viewer.
//
// Wraps `GET /v1/audit`. Super-admin only — the endpoint is gated
// server-side, and a non-super-admin caller gets a 403 rendered as
// a toast.
//
// Pagination is forward-only ("Show older" button). The page shows
// timestamp + event-kind + actor/target DIDs + a collapsible JSON
// detail panel per row. Auto-refreshes when the operator clicks
// Refresh — we deliberately don't poll, because the audit log can
// grow large and a poll would refetch the whole page each tick.

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { getJson } from "@/lib/api";
import { useToast } from "@/lib/toast";

const TRUST_TASK = "https://trusttasks.org/openvtc/vtc/audit/list/1.0";

interface AuditEnvelope {
  event_id: string;
  event_version: number;
  schema_version: number;
  timestamp: string;
  audit_key_id: string;
  actor_did_hash: string;
  actor_did_plain: string | null;
  target_did_hash: string | null;
  target_did_plain: string | null;
  event: Record<string, unknown> | string;
}

interface Paginated<T> {
  items: T[];
  next_cursor?: string | null;
  total_estimate?: number | null;
}

async function fetchAuditPage(
  cursor: string | null,
  limit: number,
): Promise<Paginated<AuditEnvelope>> {
  const q = new URLSearchParams();
  if (cursor) q.set("cursor", cursor);
  q.set("limit", String(limit));
  return getJson<Paginated<AuditEnvelope>>(`/v1/audit?${q}`, {
    trustTask: TRUST_TASK,
  });
}

export function Audit() {
  const [cursor, setCursor] = useState<string | null>(null);
  const [items, setItems] = useState<AuditEnvelope[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const toast = useToast();

  const query = useQuery({
    queryKey: ["audit", cursor],
    queryFn: () => fetchAuditPage(cursor, 50),
    staleTime: 0,
  });

  // Accumulate pages: first page replaces, subsequent appends. We
  // could let TanStack manage this with `useInfiniteQuery` instead,
  // but the read-once pattern keeps it simpler.
  useEffect(() => {
    if (!query.data) return;
    if (cursor === null) {
      setItems(query.data.items);
    } else {
      setItems((prev) => [...prev, ...query.data!.items]);
    }
    setNextCursor(query.data.next_cursor ?? null);
  }, [query.data, cursor]);

  useEffect(() => {
    if (query.error) toast.pushFromError(query.error, "Failed to load audit");
  }, [query.error, toast]);

  return (
    <section className="page">
      <h2>Audit trail</h2>
      <p className="lead">
        Tamper-evident operations log. Newest first. Super-admin only —
        envelopes carry plaintext actor / target DIDs until an RTBF
        redaction nulls them.
      </p>

      <section className="card">
        <div className="toolbar">
          <button
            type="button"
            className="primary"
            disabled={query.isFetching && cursor === null}
            aria-busy={query.isFetching && cursor === null}
            onClick={() => {
              setCursor(null);
              setItems([]);
              setNextCursor(null);
              void query.refetch();
            }}
          >
            {query.isFetching && cursor === null ? "Refreshing…" : "Refresh"}
          </button>
          <span className="muted">
            {items.length} entr{items.length === 1 ? "y" : "ies"}
            {nextCursor ? " (more available)" : ""}
          </span>
        </div>
      </section>

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event</th>
              <th>Actor</th>
              <th>Target</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && !query.isPending && (
              <tr>
                <td colSpan={5}>No audit entries.</td>
              </tr>
            )}
            {query.isPending && cursor === null && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {items.map((env) => (
              <AuditRow key={env.event_id} env={env} />
            ))}
          </tbody>
        </table>
        {nextCursor && (
          <div className="pagination">
            <button
              type="button"
              className="secondary"
              disabled={query.isFetching}
              aria-busy={query.isFetching && cursor !== null}
              onClick={() => setCursor(nextCursor)}
            >
              {query.isFetching && cursor !== null ? "Loading…" : "Show older"}
            </button>
          </div>
        )}
      </section>
    </section>
  );
}

function AuditRow({ env }: { env: AuditEnvelope }) {
  const [open, setOpen] = useState(false);
  const kind = eventKind(env.event);
  return (
    <>
      <tr>
        <td title={env.timestamp}>{formatIso(env.timestamp)}</td>
        <td>
          <code>{kind}</code>
        </td>
        <td>
          {env.actor_did_plain ? (
            <code className="truncate" title={env.actor_did_plain}>
              {env.actor_did_plain}
            </code>
          ) : (
            <span className="muted" title="Redacted by RTBF">
              redacted
            </span>
          )}
        </td>
        <td>
          {env.target_did_plain ? (
            <code className="truncate" title={env.target_did_plain}>
              {env.target_did_plain}
            </code>
          ) : env.target_did_hash ? (
            <span className="muted" title="Redacted by RTBF">
              redacted
            </span>
          ) : (
            <span className="muted">—</span>
          )}
        </td>
        <td>
          <button
            type="button"
            className="link"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Hide" : "Details"}
          </button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5}>
            <pre className="audit-detail">{formatEvent(env)}</pre>
          </td>
        </tr>
      )}
    </>
  );
}

function eventKind(event: AuditEnvelope["event"]): string {
  // The event field is serde-tagged: `{ kind: "MemberAdded", … }`
  // or `"MemberAdded"` for unit variants. Surface the tag for the
  // table column; the JSON detail row shows the full payload.
  if (typeof event === "string") return event;
  if (event && typeof event === "object") {
    const obj = event as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      return key;
    }
  }
  return "Unknown";
}

function formatEvent(env: AuditEnvelope): string {
  try {
    return JSON.stringify(env, null, 2);
  } catch {
    return String(env);
  }
}

function formatIso(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
