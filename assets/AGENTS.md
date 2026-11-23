# assets

This file is authoritative for work in this directory and its subdirectories. Root
`AGENTS.md` is the coordinator's manual: read it for repository-wide workflow, dispatch,
and verification gates.

## Scope

The canonical source for every visual asset the product ships. Files here are generated from
`ASSETS.md`, and the application copies or imports them from here; no path in this directory is served
directly.

## Structure

- `AGENTS.md` — this manual.
- `ASSETS.md` — the ledger: one row per slot (`A-###`), plus one family block per family. The family
  block carries the prompt, the settings, and the per-variant deltas that produce the files.
- `<family>/<variant>.<ext>` — generated output, written at the exact path its slot's `File` column
  names.

## Task rules

- Work only inside the issue's `Own` paths; everything outside `Own` is read-only.
- Code tasks never write under `docs/`. A doc gap becomes a `doc-gap` issue.
- Commit only your owned paths. Conventional Commits linking spec and issue (e.g. `Implements: FEAT-###`, `Fixes #<n>`). Never `git add -A`.
- Branch from `main` with `<class>/<issue-number>-<slug>` (e.g. `implement/12-feat-001-auth`), open a PR, never push to `main`.
- In code and tests, cite permanent spec anchors (`FEAT-###`, `NFR-###`, `EVT-###`, or `C-###`). Commits and PRs link the spec and the GitHub issue.
- Implement all states, schemas, and events assigned to your area; never leave stubbed states or skip declared non-happy paths.
- Never log or commit secrets, tokens, or unmasked identity; credentials live in the secret store.
- Document code inline with docstrings and comments on non-obvious logic; skip trivial comments. Never create ad-hoc markdown documentation files.
- Write lean unit tests for the behavior your issue names.
- If a contract is wrong or incomplete, report a change request; never deviate.
- Execute strictly against the assigned issue contract. Never modify files outside your owned paths. If feedback or findings uncover defects outside your scope, report back to the coordinator for triage rather than performing out-of-scope edits.
- Do not reinvent the wheel: prefer established, battle-tested ecosystem packages over bespoke implementations. Research standard libraries and agree with the user before adding or changing external dependencies.
- Packages and dependencies belong strictly in this area's manifest (build.gradle.kts), never in `AGENTS.md`.
- If blocked, state the assumption or ask for clarification before proceeding.
- When a fact resists you, verify it with evidence before falling back on recall.
- User-facing copy reads as human-written.

## Generating an asset

1. Read the slot's row in `ASSETS.md`, then the family block it belongs to. The row gives the file
   path; the block gives everything else.
2. Take the prompt from the family block. Compile or confirm it with the installed prompt skill
   (`generating-asset-prompts` where available); the block's text is the source, and a rewrite belongs
   in the ledger, not in a one-off session.
3. Render with the installed generator that fits the family's medium — image generation for raster
   art, vector authoring for marks, logos, and icons. The block's settings must match the generator's
   options; when they cannot be reconciled, stop and report rather than improvising.
4. Write the file to the slot's `File` path, at the extension the generator produced.
5. Flip that slot's `Status` from `Pending` to `Done`, and change nothing else in `ASSETS.md`.

## Discipline

- **The ledger is the specification; the file is output.** Never invent a palette, composition, or
  variant the family block does not carry.
- **One slot, one file.** Do not add variants, families, or directories; a new asset is a new slot,
  authored upstream in the specification.
- **Never edit a family block to match a render.** If the prompt cannot be satisfied, report it; the
  block changes only through the specification.
- **No application code.** SVG components, markup, and styles belong to the app area that renders them.
- **Regeneration is a design change.** Overwriting a file marked `Done` changes the product's
  appearance; confirm before replacing it.
- **Respect the brand.** The mark and its forms come from the branding document through the ledger;
  never redesign them here.

## Definition of Done

- Every touched slot's file exists at its recorded path.
- The slot reads `Done`; untouched slots are unchanged.
- No placeholder tokens remain in `ASSETS.md`.
