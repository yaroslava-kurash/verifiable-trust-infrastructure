// Theme strategy: the CSS uses `light-dark()` so the default mode
// follows the OS via `color-scheme: light dark`. Operators who want
// to pin a specific mode flip `data-theme` on <html>, which sets
// `color-scheme` to a single value and lets the cascade resolve.
//
// Preference persists in localStorage under `vtc-admin-theme`. The
// values are intentionally narrow ("auto" / "light" / "dark") so we
// can switch on them without normalisation.

export type ThemePreference = "auto" | "light" | "dark";

const STORAGE_KEY = "vtc-admin-theme";
type Listener = (pref: ThemePreference) => void;
const listeners = new Set<Listener>();

function isPref(v: unknown): v is ThemePreference {
  return v === "auto" || v === "light" || v === "dark";
}

export function getStoredTheme(): ThemePreference {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    return isPref(v) ? v : "auto";
  } catch {
    return "auto";
  }
}

export function applyStoredTheme(): void {
  if (typeof document === "undefined") return;
  apply(getStoredTheme());
}

export function setTheme(pref: ThemePreference): void {
  try {
    if (pref === "auto") window.localStorage.removeItem(STORAGE_KEY);
    else window.localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    /* fall through — preference still applies for this session */
  }
  apply(pref);
  for (const l of listeners) l(pref);
}

export function subscribeTheme(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function apply(pref: ThemePreference): void {
  const root = document.documentElement;
  if (pref === "auto") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", pref);
  }
}
