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

export async function loadThirdPartyPlugins(): Promise<void> {
  let manifest: ManifestResponse;
  try {
    const res = await fetch("/admin/plugins.json", { credentials: "include" });
    if (!res.ok) {
      console.warn(
        `[plugin-loader] /admin/plugins.json returned ${res.status} — no third-party plugins loaded`,
      );
      return;
    }
    manifest = (await res.json()) as ManifestResponse;
  } catch (err) {
    console.warn("[plugin-loader] failed to fetch plugin manifest:", err);
    return;
  }

  if (!Array.isArray(manifest.plugins) || manifest.plugins.length === 0) {
    return;
  }

  for (const entry of manifest.plugins) {
    if (!isValidEntry(entry)) {
      console.warn(
        `[plugin-loader] skipping malformed manifest entry:`,
        entry,
      );
      continue;
    }
    try {
      // Dynamic import — the URL is resolved by the browser. The
      // imported module's top-level code calls registerPlugin().
      // We don't inspect or `await` anything from the module
      // itself; the side effect (registry mutation) is what
      // matters.
      await import(/* @vite-ignore */ entry.entry);
    } catch (err) {
      console.error(
        `[plugin-loader] plugin '${entry.id}' failed to load from ${entry.entry}:`,
        err,
      );
    }
  }
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
