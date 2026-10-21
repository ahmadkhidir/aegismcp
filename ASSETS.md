# Assets

The asset ledger. One row per slot. The user is the sole authority on what already exists and where.

| Slot | File | Family / Variant | Status |
|---|---|---|---|

`Slot` is a stable `A-###` id. `Status` is `Done` when the file is on disk and `Pending` until then.

## Family blocks

Store one block per asset family with its specifications, palette, prompt/source, and variants:

```text
### Family: <name>
Medium:
Palette:
Invariants:
Prompt:
Settings:
Variants:
```
