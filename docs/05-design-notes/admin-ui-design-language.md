# Admin UX design language

Design system for the VTC admin SPA (`/admin/*`), locked at the
end of phase 1 of the design review. This document is the source
of truth for tokens + component-level decisions; phase 2 of the
review refactors the existing CSS / JSX to honour it.

## 1. Reference frame

Target: **world-class application UI**, not marketing-site gloss.

- **Vercel Dashboard** — monochrome base, crisp 1px borders, tight
  type, restrained color, dark-mode-first instincts.
- **Stripe Dashboard** — deliberate single brand accent, soft
  elevation on data surfaces, dense tables that stay readable,
  refined empty states.

Out of scope: bouncy springs, gradients on UI chrome, "AI app"
tropes (glassmorphism, neon, orbs).

## 2. Type system

```css
--font-sans:
  "Inter Variable", "Inter", ui-sans-serif, system-ui, -apple-system,
  "Segoe UI", Roboto, sans-serif;
--font-mono:
  "JetBrains Mono", ui-monospace, SFMono-Regular, "SF Mono",
  Menlo, Consolas, monospace;

/* 14px base — Stripe Dashboard / Linear scale, not 16px web-default */
--text-xs:   11px / 16px;   /* metadata, chip text */
--text-sm:   12px / 18px;   /* table cells, secondary labels */
--text-base: 14px / 20px;   /* default UI text */
--text-md:   15px / 22px;   /* form inputs */
--text-lg:   17px / 24px;   /* page H2 */
--text-xl:   22px / 28px;   /* page H1, login card */
--text-2xl:  28px / 34px;   /* hero numbers on dashboard */

/* Tracking */
--tracking-tight:   -0.011em;   /* default body */
--tracking-tighter: -0.022em;   /* headings */
--tracking-wide:     0.02em;    /* uppercase labels */
```

**Locked decisions:**

- Self-host Inter Variable via `@fontsource-variable/inter`. No FOUT.
- `font-variant-numeric: tabular-nums` on every numeric surface —
  table columns, timestamps, counts.
- Headings use `font-weight: 600`, not 700.

## 3. Color tokens

Single brand accent (locked: **indigo #5B5BD6**) + semantic ramp.
No gradients on chrome.

```css
/* Neutral ramp — 12 stops, cool-gray hue */
--gray-50:  #fafafa;
--gray-100: #f4f4f5;
--gray-200: #e4e4e7;
--gray-300: #d4d4d8;
--gray-400: #a1a1aa;
--gray-500: #71717a;
--gray-600: #52525b;
--gray-700: #3f3f46;
--gray-800: #27272a;
--gray-900: #18181b;
--gray-950: #09090b;

/* Brand: indigo (locked) */
--brand-500: #5b5bd6;
--brand-600: #4a4ac4;  /* hover */
--brand-400: #7c7ce8;  /* dark-mode primary */
--brand-50:  #efeffe;  /* subtle backgrounds */

/* Semantic — used sparingly, only on state indicators */
--success-500: #16a34a;
--warning-500: #d97706;
--danger-500:  #dc2626;
```

**Theme strategy** (locked: both modes equally polished, follow OS):

Map every visible surface through `light-dark(...)` against the
gray ramp above. Author dark and light side-by-side; don't tune
one and let the other rot.

## 4. Spacing & radius

```css
/* 4px grid. Restrict yourself to these values. */
--space-1:  4px;
--space-2:  8px;
--space-3:  12px;
--space-4:  16px;
--space-5:  20px;
--space-6:  24px;
--space-8:  32px;
--space-10: 40px;
--space-12: 48px;
--space-16: 64px;

/* Radius */
--radius-sm: 4px;   /* chips, tight controls */
--radius-md: 6px;   /* buttons, inputs, table cells */
--radius-lg: 8px;   /* cards */
--radius-xl: 12px;  /* modals, login card */
```

## 5. Elevation

1px border as the primary affordance (Vercel), with a faint
shadow layered for floating surfaces (Stripe).

```css
--elev-0: none;
--elev-1:
  0 0 0 1px var(--border),
  0 1px 2px 0 rgb(0 0 0 / 0.04);              /* default cards */
--elev-2:
  0 0 0 1px var(--border),
  0 4px 12px 0 rgb(0 0 0 / 0.08);             /* dropdowns */
--elev-3:
  0 0 0 1px var(--border),
  0 12px 32px -4px rgb(0 0 0 / 0.20);         /* modals */
```

## 6. Motion

```css
--motion-fast:    120ms cubic-bezier(0.16, 1, 0.3, 1);
--motion-medium:  180ms cubic-bezier(0.16, 1, 0.3, 1);
--motion-slow:    260ms cubic-bezier(0.16, 1, 0.3, 1);
```

Expo-out curve (Vercel / Linear idiom). No bouncy springs.

- **Animates:** focus rings (fast), hover state colors (fast),
  drawer open/close (medium), modal scrim (medium).
- **Does not animate:** tables, page transitions, content.

## 7. Iconography

**Locked: lucide-react, 16px outlined.**

- Install `lucide-react` (~5kb gzipped for the set we use).
- Replace every emoji nav icon. Emojis read as MVP-ish and render
  differently per OS, breaking the visual system.
- Icon size = 16px in nav and inline; 20px in empty states; 14px
  in chips. Stroke width 1.75 (lucide default 2 is slightly
  heavier than the type wants).

## 8. Component-level decisions

| Surface | Decision |
|---|---|
| **Button** | 32px (sm) / 36px (default) / 40px (primary CTA). Primary = solid brand-500. Secondary = transparent + 1px border. Destructive = transparent + red-tinted border, solid red on hover. No "filled secondary." |
| **Input** | 36px height, 1px border, 2px focus ring with **1px inset offset** (inside the border, not outside — Vercel idiom). |
| **Table** | 40px row height, hover row tint, sticky header on scroll, monospace for IDs/DIDs, tabular-nums for timestamps + counts, action buttons reveal on row hover (reduce always-visible noise). |
| **Card** | 1px border, 8px radius, no shadow by default. Optional faint shadow (elev-1) only when floating on a colored backdrop (e.g. login card). |
| **Chip** | Pill (full radius), 4px / 8px padding, 11px text, monochrome by default. State chips use semantic color on text + 1px border, not background fill. |
| **Toast** | Keep current 4px left-border state indicator; retune to new tokens. |
| **Empty states** | Centered 20px icon + 1-line heading + 1-paragraph explanation + single CTA. |

## 9. Page-level moves

Specific redesigns that carry most of the visible improvement:

1. **Login** — single centered card on a subtly textured backdrop.
   No big VTC logo lock-up; just `VTC Admin` in `--text-xl` and
   the passkey button.
2. **Dashboard** — replace the current key-value `<dl>` blocks
   with **stat tiles**: large tabular number (`--text-2xl`),
   label below in `--text-xs --tracking-wide` uppercase, optional
   sparkline/trend. 4 tiles in a row, wrap on narrow viewports.
3. **Tables (Members, ACL, Audit, Sessions, …)** — introduce a
   `<Toolbar>` row: search input on the left, filter chips in the
   middle, primary action on the right. Sticky header on scroll;
   row actions reveal on hover.
4. **Nav** — narrow to 220px. Drop emoji icons; use lucide
   16px outlined. Active route uses indigo accent on the left
   border + bolder weight on the label.

## 10. Out of scope

- Not a Tailwind migration. Existing CSS architecture stays; add
  tokens and refactor against them.
- Not a component library swap. Reach for Radix only on Dialog +
  DropdownMenu where the a11y is hard. Everything else stays
  hand-built.
- Not a brand exercise. Accent color is the only "brand"
  decision; everything else is structural.

## Locked decisions summary

| Decision | Value |
|---|---|
| Brand accent | `#5B5BD6` indigo |
| Theme target | Both light + dark equally polished, follow OS |
| Icon set | lucide-react, 16px outlined, stroke 1.75 |
| Type family | Inter Variable, self-hosted |
| Base size | 14px |
| Grid | 4px |
| Default card radius | 8px |
| Default focus ring | 2px, 1px inset offset, brand-500 |
| Motion curve | `cubic-bezier(0.16, 1, 0.3, 1)` |
