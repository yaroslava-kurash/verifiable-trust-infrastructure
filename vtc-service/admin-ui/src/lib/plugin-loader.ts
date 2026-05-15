// Third-party plugin loader.
//
// At shell boot, fetches `/admin/plugins.json` from the daemon to
// discover which plugins the operator has installed. Each manifest
// entry carries an `entry` URL; the loader dynamically `import()`s
// it. The plugin's module body is expected to call
// `window.VtcPluginApi.registerPlugin({...})` at the top level,
// which mutates the shared registry that the React shell renders
// from.
//
// Plugins are loaded sequentially so registration order is
// deterministic (nav ordering follows registration order). If one
// plugin fails to load — bad URL, syntax error, registerPlugin
// rejected — the loader logs and continues; one broken plugin
// shouldn't take down the rest of the console.
//
// `reloadThirdPartyPlugins()` is the live-reload entry point: it
// refetches the manifest, imports any IDs that aren't already
// registered, and returns the IDs it added. Existing plugins are
// left untouched — re-importing them would either no-op (browser
// module cache) or throw on the duplicate `registerPlugin` call.
// True hot-reload of a *modified* plugin's JS still requires a page
// refresh; that's an acceptable v1 limitation.

import { getPluginIds } from "@/plugin-api";

interface ManifestEntry {
  id: string;
  label: string;
  path: string;
  entry: string;
  icon?: string;
  scopes?: string[];
}

interface ManifestResponse {
  plugins: ManifestEntry[];
}

async function fetchManifest(): Promise<ManifestResponse | null> {
  try {
    const res = await fetch("/admin/plugins.json", {
      credentials: "include",
      cache: "no-store",
    });
    if (!res.ok) {
      console.warn(
        `[plugin-loader] /admin/plugins.json returned ${res.status} — no third-party plugins loaded`,
      );
      return null;
    }
    return (await res.json()) as ManifestResponse;
  } catch (err) {
    console.warn("[plugin-loader] failed to fetch plugin manifest:", err);
    return null;
  }
}

async function importEntries(entries: ManifestEntry[]): Promise<string[]> {
  const added: string[] = [];
  for (const entry of entries) {
    if (!isValidEntry(entry)) {
      console.warn(`[plugin-loader] skipping malformed manifest entry:`, entry);
      continue;
    }
    try {
      // Dynamic import — the URL is resolved by the browser. The
      // imported module's top-level code calls registerPlugin().
      // We don't inspect or `await` anything from the module
      // itself; the side effect (registry mutation) is what
      // matters.
      await import(/* @vite-ignore */ entry.entry);
      added.push(entry.id);
    } catch (err) {
      console.error(
        `[plugin-loader] plugin '${entry.id}' failed to load from ${entry.entry}:`,
        err,
      );
    }
  }
  return added;
}

export async function loadThirdPartyPlugins(): Promise<void> {
  const manifest = await fetchManifest();
  if (!manifest?.plugins?.length) return;
  await importEntries(manifest.plugins);
}

/**
 * Refetch the manifest and import any plugins that aren't already
 * registered. Returns the list of newly-imported plugin IDs (empty
 * if nothing changed). Safe to call on a timer or on focus —
 * already-loaded plugins are skipped, so cost on the steady-state
 * path is just one manifest fetch.
 */
export async function reloadThirdPartyPlugins(): Promise<string[]> {
  const manifest = await fetchManifest();
  if (!manifest?.plugins?.length) return [];
  const known = getPluginIds();
  const fresh = manifest.plugins.filter((e) => !known.has(e.id));
  if (fresh.length === 0) return [];
  return importEntries(fresh);
}

function isValidEntry(entry: unknown): entry is ManifestEntry {
  if (!entry || typeof entry !== "object") return false;
  const e = entry as Record<string, unknown>;
  return (
    typeof e.id === "string" &&
    typeof e.label === "string" &&
    typeof e.path === "string" &&
    typeof e.entry === "string"
  );
}
