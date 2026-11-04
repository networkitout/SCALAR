# SCALAR design system

Authoritative reference for the dashboard's visual decisions (`src/scalar/web/static/`). When this
document and the code disagree, fix whichever is wrong and update the other. The tokens live in
the `:root` blocks at the top of `style.css`; component code uses tokens, never raw values.

Derived from the KEVLAR design system (same owner, same operators). What carries over is the
structure, palette, density and rules. The KEVLAR brand mark, KEV-specific components and its
orange-era history do not.

## 1. Principles

1. **A monitoring tool for power users.** Operators scan, compare and pattern-match for hours.
   Density is a feature; sparse layouts need a reason. Aim for a professional instrument, not a
   consumer app.
2. **Colour is semantic, not decorative.** Accent blue means SCALAR (primary action, active
   navigation, selection). Link blue means informational or secondary. Severity colours mean
   severity and appear nowhere else. Success green means a verified good outcome. Neutrals do
   almost all the work.
3. **Data first, chrome recedes.** Identifiers and values use the brightest text tier; labels and
   metadata are muted; backgrounds and borders stay quiet.
4. **Restraint with accents, confidence with structure.** If half the UI is accent blue none of
   it is emphasized.
5. **Flat.** No shadows on cards, no gradients, no glow (except the small halo on status dots), no
   pills on functional elements, no decorative animation. Hover transitions are 150 ms.
6. **Dark first.** Dark is the default and the design target. The light theme is derived (see
   section 8) and opt-in through the toggle.

## 2. Colour tokens

### Surfaces and borders (dark)

| Token | Value | Use |
|---|---|---|
| `--bg-page` | `#0E1218` | Page background, inputs, code blocks |
| `--bg-surface` | `#161B24` | Sidebar, top bar |
| `--bg-card` | `#1C222D` | Cards, panels, dialogs |
| `--bg-card-hover` | `#232A37` | Row and card hover |
| `--bg-tablehead` | `#1F2631` | Table and panel headers |
| `--border-subtle` | `#2A3240` | Default edge |
| `--border-row` | `#2E3643` | Table row separators |
| `--border-emphasis` | `#3A4556` | Hover and secondary-button borders |

Cards must stay clearly lighter than the page; never pull the canvas toward the card value (cards
turn "smoky"). Never use pure black.

### Text

| Token | Value | Use |
|---|---|---|
| `--text-data` | `#F5F7FA` | Numbers, hostnames, IDs, KPI values |
| `--text-primary` | `#E8ECF2` | Body text, headings |
| `--text-secondary` | `#A0A8B5` | Supporting text, inactive nav, table body |
| `--text-tertiary` | `#6B7280` | Metadata, captions, section labels |

No intermediate levels: use weight 500 instead. No pure white text.

### Brand, severity, status

| Token | Value | Use |
|---|---|---|
| `--accent` / `--accent-hover` | `#2F80ED` / `#4A93F2` | Primary button, active nav, selection |
| `--accent-soft` / `--accent-border` | 12% / 40% tint | Active nav background, selected rows |
| `--link` / `--link-hover` | `#2496ED` / `#3AA5F0` | Links, informational states |
| `--critical` | `#E24B4A` | Severity: critical (bg 15%, border 30% tints) |
| `--high` | `#D85820` | Severity: high |
| `--medium` | `#EF9F27` | Severity: medium; also degraded or warning status |
| `--low` | `#5FA3C7` | Severity: low (steel blue, only inside bordered badges) |
| `--success` | `#4FAE7D` | Healthy, delivered, verified outcome |

Rules: severity colours only in severity (and the matching warning) contexts; never rely on colour
alone (badges carry text, status dots carry a label); do not put accent blue and low-severity blue
next to each other. New colours need a justification, not a hex code.

## 3. Typography

```
--font-sans:  -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif;
--font-mono:  "JetBrains Mono", "SF Mono", Consolas, monospace;
--font-brand: "Montserrat", var(--font-sans);   /* wordmark only */
```

No web fonts are bundled, so the dashboard makes no font requests and renders in the platform's
own faces. The wordmark is `SCALAR`, uppercase, weight 800, `letter-spacing: .04em`; without a
bundled Montserrat it falls back to the system sans at 800. To ship Montserrat, add a Basic Latin
WOFF2 subset (SIL OFL 1.1, include the licence file) under `static/` and an `@font-face`.

Scale (13 px base): 26/600 metric values, 20/500 page title, 15/500 section headings, 13/500
panel titles and navigation, 13/400 body, 12/400 table body, 11/500 uppercase labels, 10/500
uppercase table heads and badges. Weights are 400, 500 and 600 only (800 for the wordmark).
Sentence case everywhere; uppercase only for small structural labels, always with 0.05 to 0.08em
letter spacing. No italics. Monospace is for technical data: hostnames, IPs, CVE IDs, versions,
timestamps, hashes, paths and metric values; set `tnum` on tabular numbers.

## 4. Spacing, radius, layout

Spacing is a 4 px scale (4, 8, 12, 16, 20, 24, 32, 40). Density targets: card padding 14/16,
table cells 9/14, top bar 48 px, sidebar 210 px, 12 px between cards, 20 px between sections,
20 px content padding. Radii: 2 px badges, 3 px buttons, 4 px cards, panels and inputs.

Structure: top bar, sidebar, a row of four metric cards, then a 2fr/1fr content grid. Every page
uses that frame; a page that needs something else documents why. The layout collapses to a drawer
sidebar below 800 px and to two and one metric columns below 800 and 340 px.

## 5. Components

- **Sidebar item**: `8px 18px`, 13 px secondary text, 15 px icon at 85% opacity, 2 px transparent
  left border reserved. Active: accent-soft background, accent border and icon, primary text.
- **Metric card**: uppercase 11 px label with a 13 px icon, 26/600 mono value in `--text-data`,
  11 px tertiary note. Notes may be coloured good, attention or alert. Keep to one headline
  metric per row if one is emphasized; otherwise none.
- **Panel / table wrap**: card background, subtle border, 4 px radius, clipped overflow. Header on
  `--bg-tablehead`.
- **Tables**: head 10 px uppercase tertiary on `--bg-tablehead`; rows `9px 14px`, 12 px, row
  separators, hover to `--bg-card-hover`. Text left, numbers right, badges left. More than ten
  rows paginate. An empty result shows a message, never bare headers.
- **Badges**: 10 px, 600, uppercase, `2px 8px`, 2 px radius, severity tint plus border, always the
  full word (CRITICAL, not CRIT). Status badges: online and delivered use success; pending and
  unmonitored use the warning tint; info uses link blue.
- **Buttons**: primary is accent fill with white text, `6px 14px`, 12/500, 3 px radius; secondary
  is transparent with an emphasis border; text buttons are 11 px uppercase link blue. One primary
  action per view.
- **Inputs**: 32 px, `--bg-page` fill, subtle border (emphasis on hover), accent focus ring.
  Labels sit above the field; a placeholder is never the label.
- **Dialogs**: card background, emphasis border, no shadow, header on `--bg-tablehead`, scrim at
  70% (dark).
- **Status dot**: 8 px, with a 3 px halo of the same colour at low opacity, followed by text.

## 6. Icons

Lucide only (vendored, `static/lucide.min.js`). Sizes: 13 px in metric labels, 15 px in the
sidebar, 16 px elsewhere; never below 13 px. Icons inherit `currentColor`; only the active nav icon
takes the accent. No emoji, no second icon set. The brand mark is currently the Lucide `radar`
glyph, a placeholder until SCALAR has its own mark.

## 7. Rules and anti-patterns

- Use tokens, not raw values. Do not introduce new sizes, weights or colours casually.
- No shadows on cards, no surface gradients, no left-border accent cards, no decorative colour,
  no fade-ins or pulsing, no tooltips carrying critical information.
- Format numbers with thousands separators unless they are identifiers.
- When in doubt: use a neutral, use the smaller size, add nothing. Consistency beats local
  optimality; return to section 1 as the tiebreaker.
- Changing a token means auditing every surface that uses it; adding one needs a use case the
  existing tokens cannot serve. Update this file in the same change.

## 8. Deviations from the KEVLAR system

1. **Light theme exists.** KEVLAR defines dark only. SCALAR keeps a light theme (existing
   feature), derived by darkening accent and severity text so they hold 4.5:1 on white, and by
   lightening the surfaces. Treat the light values in `style.css` as provisional.
2. **Accent contrast.** White on `#2F80ED` is about 3.9:1. The system specifies it for dark mode and
   it is kept, but the 12 px button text is below WCAG AA; the light theme uses a darker accent
   that passes. Revisit if the dark accent is ever adjusted.
3. **Metric values in monospace**, to keep digit columns aligned and identifiers visually distinct.
4. **No KEVLAR components.** The KEV KPIs, MTTK bar and activity feed are not used; SCALAR's
   equivalents are the metric cards, severity bars (`progress`) and the findings table.
5. **Responsive layout is implemented**, where KEVLAR defers it.

## Changelog

- **2026-11-03**: Initial SCALAR design system, ported from KEVLAR. Dashboard restyled to dark-first
  tokens; IBM Plex Sans removed in favour of the system stack.
