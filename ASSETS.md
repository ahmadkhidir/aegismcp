# Assets

The asset ledger. One row per slot. The user is the sole authority on what already exists and where.

| Slot | File | Family / Variant | Status |
|---|---|---|---|

`Slot` is a stable `A-###` id. `Status` is `Done` when the file is on disk and `Pending` until then.

## Family blocks

Store one block per family, verbatim from `generating-asset-prompts`:

```text
### Family: <name>
Medium:
Palette:
Invariants:
Prompt:
Settings:
Variants:
```
