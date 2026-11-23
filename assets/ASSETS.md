# Assets

The asset ledger. One row per slot (`A-###`). The user is the sole authority on what already exists and where.
`Status` is `Done` when the file is on disk and `Pending` until then.

| Slot | File | Family / Variant | Status |
|---|---|---|---|
| A-001 | `apps/console/public/favicon.svg` | brandmark / app-icon | Done |
| A-002 | `assets/brand/brandmark.svg` | brandmark / mark-master | Done |
| A-003 | `assets/brand/logo-horizontal.svg` | brandmark / horizontal-lockup | Done |
| A-004 | `assets/brand/wordmark.svg` | brandmark / wordmark-only | Pending |
| A-005 | `assets/brand/brandmark-monochrome.svg` | brandmark / one-colour | Pending |
| A-006 | `assets/brand/logo-horizontal-knockout.svg` | brandmark / knockout-on-dark | Pending |

## Family blocks

### Family: brandmark

**Medium:** Scalable Vector Graphics (SVG), authored as exact geometry and set type; not raster image generation.

**Palette:**
- Primary Blue `#3B82F6` — outer hexagon stroke, node fill, and protocol vector lines
- Light Facet Blue `#93C5FD` — inner hexagon stroke (the lit facet)
- Bastion Dark `#0B0F19` — mark field fill, and the dark surface a knockout sits on
- Inner Slate `#1E293B` — inner hexagon fill
- Wordmark Text `#0F172A` — "Aegis" letterform ink on light surfaces
- Badge Container `#E2E8F0` fill, `#CBD5E1` stroke — the "MCP" outlined container
- Monospace Text `#172554` — "MCP" letters inside the badge
- Reversed Ink `#F8FAFC` — the single tone for monochrome and knockout forms

**Invariants:** Hexagonal node geometry with 6 converging protocol vector lines, central 3px circle node; sharp vertex tracking on "Aegis" sans-serif; "MCP" in JetBrains Mono inside outlined container; 12px gap between mark and wordmark. The mark is legible at 16x16px as a clean closed silhouette without losing interior structure, reads in a single tone, and reverses cleanly on dark. The mark is never placed on a busy photographic background and never carries a multi-colour novelty gradient.

**Prompt:**
```text
A sharp, geometric hexagonal node anchored by converging data flow lines: incoming protocol vectors meet at a central hexagonal bastion that deflects unauthorized paths while channeling verified traffic through a clean axial conduit. Technical, monolithic, solid.
```

**Settings:** 32x32 viewBox for the mark (A-001, A-002, A-005); 160x36 viewBox for the horizontal lockup (A-003, A-006); 36px total height for the wordmark-only form (A-004); stroke-width 2.0 on the outer hexagon and protocol vectors, 1.5 on the inner hexagon; "Aegis" set in Inter 700 at 20px with -0.04em tracking; "MCP" set in JetBrains Mono 600 at 11px inside a 44x20 outlined container with 4px corner radius. Type is always set from the font, never traced.

**Variants:**

| Variant | Target | Execution Delta |
|---|---|---|
| app-icon | `apps/console/public/favicon.svg` | Mark only, 32x32 viewBox, no wordmark, detail stripped to what survives 16px |
| mark-master | `assets/brand/brandmark.svg` | Mark only, 32x32 viewBox, full interior structure, canonical palette |
| horizontal-lockup | `assets/brand/logo-horizontal.svg` | Mark plus "Aegis" wordmark plus "MCP" badge, 12px gap after the mark, 160x36 viewBox, light-surface ink `#0F172A` |
| wordmark-only | `assets/brand/wordmark.svg` | Mark removed; "Aegis" wordmark and "MCP" badge only, cropped tight, light-surface ink `#0F172A` |
| one-colour | `assets/brand/brandmark-monochrome.svg` | Mark only; every stroke and fill collapsed to the single tone `#F8FAFC`, facet distinction carried by the outlines alone |
| knockout-on-dark | `assets/brand/logo-horizontal-knockout.svg` | Horizontal lockup reversed for terminal and dark surfaces: field `#0B0F19`, all ink `#F8FAFC`, badge container stroked `#E2E8F0` with no fill |
