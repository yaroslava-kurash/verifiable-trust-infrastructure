// Segmented Auto / Light / Dark switcher. Lives in the nav header
// next to the session badge. Persists via @/lib/theme.

import { useEffect, useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";

import {
  getStoredTheme,
  setTheme,
  subscribeTheme,
  type ThemePreference,
} from "@/lib/theme";

const options: { value: ThemePreference; icon: typeof Sun; label: string }[] = [
  { value: "auto", icon: Monitor, label: "Match system" },
  { value: "light", icon: Sun, label: "Light" },
  { value: "dark", icon: Moon, label: "Dark" },
];

export function ThemeSwitcher() {
  const [pref, setPref] = useState<ThemePreference>(() => getStoredTheme());

  useEffect(() => subscribeTheme(setPref), []);

  return (
    <div
      className="theme-switcher"
      role="group"
      aria-label="Colour theme"
    >
      {options.map((opt) => {
        const Icon = opt.icon;
        const active = pref === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            aria-pressed={active}
            aria-label={opt.label}
            title={opt.label}
            onClick={() => setTheme(opt.value)}
          >
            <Icon aria-hidden="true" />
          </button>
        );
      })}
    </div>
  );
}
