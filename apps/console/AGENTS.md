# apps/console

This file is authoritative for work in this directory and its subdirectories. Root
`AGENTS.md` is the coordinator's manual: read it for repository-wide workflow, dispatch,
and verification gates.

## Scope

This directory and its subdirectories. The issue's `Own` paths are binding; everything outside `Own` is read-only.

## Structure

- Single-page Vite app rooted at `apps/console`. `src/main.tsx` mounts the React tree; `src/App.tsx`
  owns the authenticated application shell, the login gate, screen switching, and global overlays.
  There is no router package: routes are the shell's screen identifiers.
- `src/screens/` is the code root for routed views. One file per screen. A screen owns its data
  fetching, its filter/buffer state, and its rendering of loading, empty, error/offline,
  submitting/disabled, and success. Screen-private subcomponents, helpers, and state stay in that
  screen file until a second screen needs them.
- `src/components/` holds presentational components shared by two or more screens or by the shell:
  navigation, status pills, empty/error states, payload viewers, modals, banners. Components receive
  data and callbacks as props; they do not fetch, read global auth, or hide transport fallbacks.
- `src/context/` holds React providers and their hooks. Session and identity state live here; screens
  consume them through the exported hook rather than reading storage directly.
- `src/services/` is the only place that speaks to the network. `api.ts` is the contract adapter for
  the gateway REST and SSE surface; `oidc.ts` is the identity client. Screens and components never
  call `fetch` or construct stream clients themselves.
- `src/types/` mirrors the frozen contract and identity shapes. Gateway payload types belong in the
  local `contracts.ts` module; session, token, and role types belong in `auth.ts`. Do not redeclare a
  contract shape inside a screen or service.
- `src/test/` holds all automated tests plus `setup.ts` for the jsdom environment. Test files are
  named after the unit under test (for example, `DashboardScreen.test.tsx` or
  `KillSwitchModal.test.tsx`). Tests are never written next to source files and never placed in a
  second test folder.
- `src/index.css` declares the design tokens as CSS custom properties; `tailwind.config.js` maps
  those properties to utility names. Both are shared infrastructure, not a place for screen styles.
- `public/` holds static brand and favicon assets referenced from `index.html`. Build configuration
  (`vite.config.ts`, `tsconfig.json`, `postcss.config.js`, `tailwind.config.js`) stays at the app root.
- Placement rule: a new view is a file in `src/screens/` wired into the shell's screen map; a reusable
  visual primitive is a file in `src/components/`; a new endpoint belongs as a method on the existing
  service for its contract; a new payload shape belongs in `src/types/`. Do not introduce a new
  top-level folder under `src/` without coordinating the change and updating this section.

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
- Packages and dependencies belong strictly in this area's manifest (package.json), never in `AGENTS.md`.
- If blocked, state the assumption or ask for clarification before proceeding.
- When a fact resists you, verify it with evidence before falling back on recall.
- User-facing copy reads as human-written.

## Discipline

- **No silent mock fallback in production.** Fixture data may exist only behind an explicit
  development or test mode that is off in a production build. A failed request, a non-2xx response,
  or a dropped stream surfaces the error and offline state to the operator; the console never
  substitutes invented tickets, metrics, policies, audit blocks, verdicts, or tokens for a live
  contract. Test fixtures belong in test setup or a mode-gated module, not in the shipped request
  path.
- **Contract wiring is literal.** Bind every screen to the frozen `C-###` request, response, and
  error shapes in `contracts/`, including HTTP status handling and field names; map identity and
  role claims per the identity contract. The live inspector consumes the `C-002` event stream with
  reconnect and exponential backoff, reports connecting, connected, reconnecting, and disconnected
  states, and re-fetches the pending approval queue (`C-003`) after every reconnect so no approval is
  orphaned. Release every stream, timer, and listener on unmount and on route change.
- **Token-only styling.** Consume the theme tokens wired through `tailwind.config.js`; never hardcode
  a hex value, spacing, radius, shadow, font size, or motion duration at a call site. A value absent
  from the token set is a reported gap, not an arbitrary bracket value. Apply the declared device
  classes from the specification instead of collapsing them, and honour the platform kit's focus,
  contrast, motion-reduction, and touch-target behaviour before writing custom interaction.
- **Complete state coverage.** Every screen and every mutation implements loading, empty,
  error/offline, submitting/disabled, and success, plus the screen's declared screen-specific states.
  Mutations disable while in flight and surface contract errors in place. Each declared state has a
  test that asserts what the operator sees; a compiling component with unhandled states is not done.
  Treat connectivity loss as a first-class state: banner, retry path, and preserved in-progress work.
- **Real identity boundary.** The mock IdP is a development-only provider, selectable only when
  development mode is explicit. A production build authenticates through the configured OIDC
  provider, validates session expiry and role claims, and never fabricates a token, assumes a
  persona, or auto-signs-in. Missing identity configuration in production is a startup error shown
  to the operator, not a silent mock session. Tokens stay in the session store and out of logs,
  telemetry, rendered payloads, and error text.
- **Configuration, not constants.** The gateway base URL and identity settings come from environment
  or runtime configuration. Local development reaches the gateway through the Vite dev-server proxy;
  source contains no hardcoded localhost, staging, or production origin. A new required setting is
  added to the documented environment example and the typed environment declaration in the same
  change, and a missing required setting fails visibly.

## Checks

- Install exactly from the lockfile: `cd apps/console && npm ci`
- Unit and component tests: `cd apps/console && npm test`
- Type-check and production build: `cd apps/console && npm run build`
- Run the console locally: `cd apps/console && npm run dev` (view each rendered state before
  calling the work done)

## Definition of Done

- All unit and component tests in this directory pass.
- Every screen and mutation state named by the issue has a passing test.
- Contract conformance holds against the frozen `C-###` shapes and error responses.
- No design value is hardcoded and no fixture can reach a production request path.
- The production build passes with no type errors, and the dev server was exercised across the
  affected states.
- Checks run cleanly with no unresolved stubs, placeholder states, or TODOs.
- Missing tokens, contract fields, or configuration are reported as gaps rather than improvised.

## Report

Task and feature IDs; files changed; screens and states covered; unit-test results; build result;
missing tokens, contract fields, assets, or configuration; shared-module or shell changes; blockers
or assumptions; commands run. Report contract conformance against the frozen shapes and name any
behavior that still relies on a mock path.
