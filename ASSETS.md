# Assets

The asset ledger. One row per slot. The user is the sole authority on what already exists and where.

| Slot | File | Family / Variant | Status |
|---|---|---|---|
| A-001 | `apps/console/public/favicon.svg` | brandmark / standalone-icon | Done |
| A-002 | `assets/brand/brandmark.svg` | brandmark / master-vector | Done |
| A-003 | `assets/brand/logo-horizontal.svg` | brandmark / horizontal-lockup | Done |

`Slot` is a stable `A-###` id. `Status` is `Done` when the file is on disk and `Pending` until then.

## Family blocks

Store one block per asset family with its specifications, palette, prompt/source, and variants:

### Family: brandmark
Medium: Scalable Vector Graphics (SVG)
Palette: Primary Blue (`#3B82F6`), Light Facet Blue (`#93C5FD`), Bastion Dark (`#0B0F19`), Inner Slate (`#1E293B`), Wordmark Text (`#0F172A`), Badge Container (`#E2E8F0`, `#CBD5E1`), Monospace Text (`#172554`)
Invariants: Hexagonal node geometry with 6 converging protocol vector lines, central 3px circle node; sharp vertex tracking on "Aegis" sans-serif; "MCP" in JetBrains Mono inside outlined container; 12px gap between mark and wordmark.
Prompt: A sharp, geometric hexagonal node anchored by converging data flow lines: incoming protocol vectors meet at a central hexagonal bastion that deflects unauthorized paths while channeling verified traffic through a clean axial conduit. Technical, monolithic, solid.
Settings: 32x32 viewBox for mark; 160x36 viewBox for horizontal lockup; stroke-width 2.0 (outer) / 1.5 (inner).
Variants:
- `standalone-icon`: Mark only (favicon, browser tab, CLI badge) at `apps/console/public/favicon.svg` and `assets/brand/brandmark.svg`
- `horizontal-lockup`: Mark + wordmark + monospace badge at `assets/brand/logo-horizontal.svg`
