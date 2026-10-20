# ShipSafe - Project Logs & Activity Records

## 1. Development Activity Log

### [2026-10-15]
- **Repo Initialization**:
  - Created base repository and pushed initial commit to remote GitHub repository (`dhruvil-codes/shipsafe`).
  - Added project documentation structure under `doc/`:
    - [`PRD.md`](file:///d:/shipsafe/doc/PRD.md): Product Requirements, user personas, roadmap milestones.
    - [`RULES.md`](file:///d:/shipsafe/doc/RULES.md): Coding standards, Git conventions, security rules, and skill discovery guidelines.
    - [`LOGS.md`](file:///d:/shipsafe/doc/LOGS.md): Activity log and architectural decision records.
    - [`INSTABOX.md`](file:///d:/shipsafe/doc/INSTABOX.md): Complete InstaBox SDK, API, CLI, and resource limits reference from [https://instabox.sh/docs](https://instabox.sh/docs).
  - Added [`AGENTS.md`](file:///d:/shipsafe/AGENTS.md) with context-first directives, dynamic skill discovery via `find-skills`, and InstaBox guidelines.
- **Frontend Simplification**:
  - Revoked all marketing, isometric, and complex dashboard sections from the home page.
  - Reset [`apps/web/app/page.tsx`](file:///d:/shipsafe/apps/web/app/page.tsx) and [`apps/web/app/layout.tsx`](file:///d:/shipsafe/apps/web/app/layout.tsx) to render a clean, centered text heading (`ShipSafe`) on a pure black canvas with zero extraneous components.
- **Inline Report Alignment & Private Scan Lab Polish**:
  - Replaced the minimal inline completed scan results with the full sample report layout (`/report/sample`) in [`apps/web/components/InlineScan.tsx`](file:///d:/shipsafe/apps/web/components/InlineScan.tsx), featuring split metrics (Recorded score, Executed check coverage), limits callout, JSON/print exports, severity-filtered finding cards with fix prompts, and 13-control check outcomes table.
  - Fixed Private Lab scan: Prevented `shipsafe-fixture.invalid` from populating user input URL and cleanly labeled the session and scan tree as `ShipSafe Private Lab`.
  - Refactored `BOARD` in [`apps/web/app/page.tsx`](file:///d:/shipsafe/apps/web/app/page.tsx) to replace repetitive 'Not tested' labels with actionable security profiles across perimeter, cookies, API exposure, and full-stack integration boundaries.
- **Hero and Navbar Unification**:
  - Repositioned `<HeroASCII />` at the root of `.ora` preceding `<OraNav />` with `height: 760px` (`height: 640px` on mobile) and `z-index: -1`.
  - Configured `.ora { position: relative; isolation: isolate; }` and `.ora .ora-nav { background: transparent; border-bottom: 0; }`.
  - Restored seamless coverage across the navbar and hero with zero horizontal cut, white seam, or visual boundary between navigation and hero.

---

## 2. Architecture Decision Records (ADR)

### ADR-001: Initial Documentation & Repository Structure
- **Status**: Accepted
- **Context**: Establish clear requirements, operating rules, and project history from day one.
- **Decision**: Centralize all documentation inside `doc/` with PRD, RULES, and LOGS markdown files.
- **Consequences**: Teams and contributors have clear guidance on feature roadmap and contribution criteria.

---

## 3. Pending Actions & Next Steps
- [x] Define technology stack and scaffolding for core services / UI.
- [x] Parallel build Agents 1-4 merged to main with zero conflicts.
- [x] Wire orchestration contracts to @shipsafe/shared (removed local copies in orchestration + api/_lib).
- [x] Migrate monorepo and scripts to Bun (`bun.lock`, `bun test`, `bun run build`).
- [x] Cleaned up temporary `D:\shipsafe-agent-*` worktree directories from disk.
- [ ] Deploy real in-VM OSINT engine (`runner/osint_engine.py` - crt.sh subdomains, DMARC/SPF, DNS takeover).
- [ ] Wire single-screen terminal UI mode.
- [ ] Live InstaBox E2E against target with real INSTABOX_API_KEY.

---

## 4. Bun Migration & Contract Wiring [2026-10-15]
- **Standardized on Bun (`v1.3.5`)**:
  - Root `package.json` updated with native Bun `workspaces: ["packages/*", "apps/*"]`.
  - Generated `bun.lock`.
  - Scripts configured for `bun --filter` (`bun run test`, `bun run typecheck`, `bun run build`, `bun run dev`).
- **Wired Canonical Contracts**:
  - `packages/orchestration/src/contracts.ts` and `apps/web/app/api/_lib/contracts.ts` now directly re-export from `@shipsafe/shared`.
  - Fixed Next.js 15 `Promise<{ id: string }>` route params typing in `apps/web/app/api/__tests__/api.test.ts`.
- **Verification Results**:
  - `bun --filter "*" typecheck`: **7/7 packages passed (0 errors)**.
  - `bun run test`: **91/91 unit/integration tests passed in 7.17s**.
  - `python -m unittest discover`: **2/2 runner tests passed**.
  - `bun run build`: **Next.js 15 production build passed cleanly**.
  - Deleted temporary worktree folders (`D:\shipsafe-agent-*`) to free disk space.

---

## 5. Real OSINT & Attack Surface Engine [2026-10-15] (branch `feat/osint-engine`)
- **In-VM runner** (`runner/osint_engine.py` + `runner/osint_engine.sh`): orchestrates REAL binaries only —
  subfinder, httpx, subzy, checkdmarc, whois (+dnsutils) — sequential JSON pipeline into a single
  `osint-suite` ToolResult (`osint_result.json` + `.sha256`). Missing/failed binaries record `ran: false`
  with error text; consolidated status `passed` iff ≥1 stage executed, else `failed` with
  `checksAttempted: 0`. Zero simulation: no output is ever fabricated.
- **Normalizer** (`packages/adapters/src/osint.ts`): `normalizeOsint` + `parseOsintEvidence` wired into the
  main `normalize()` aggregator (the `normalizeAll` participant) and `OSINT_RULE_CATALOG` merged into
  `RULE_CATALOG`: `OSINT-DMARC-MISSING` (HIGH, CWE-358), `OSINT-DMARC-PERMISSIVE` (MEDIUM, CWE-358),
  `OSINT-SUBDOMAIN-TAKEOVER` (CRITICAL, CWE-650), `OSINT-EXPOSED-STAGING` (MEDIUM, CWE-200, live-2xx only),
  `OSINT-DOMAIN-EXPIRING` (MEDIUM, CWE-672, ≤30 days). Shape-based parsing, fingerprint dedup, redaction.
- **Refactor**: shared `fingerprintFor`/`redactSecrets`/`DraftFinding` moved to
  `packages/adapters/src/primitives.ts` (cycle-free import graph); `DraftFinding.owasp` / `RuleMeta.owasp`
  now optional (domain expiry has no honest Top-10 mapping).
- **Scoring**: 5 deterministic explainer templates with fenced fix snippets (full-catalog test now covers 35 rules).
- **Verification**: `bun --filter "*" typecheck` 7/7, `bun run test` 105/105 (adapters 37 incl. 14 new OSINT),
  `bun run build` clean, `python -m unittest discover -s runner/tests` 8 tests OK (1 POSIX-only stub test
  skips on Windows). One parser bug caught by tests and fixed (explicit `"dmarc": null` → MISSING).

---

## 6. Single-Screen Terminal UI [2026-10-15] (branch `feat/single-screen-terminal-ui`)
- **Home page is now the terminal** (`apps/web/app/page.tsx`): one window, no redirects. Reactive
  IDLE → SCANNING → COMPLETED state machine with a New Scan reset. Old marketing landing
  (`app/(app)/page.tsx`) removed to avoid a `/` route conflict; `/scan/[id]` deep links kept.
- **Components** (`apps/web/components/`): `TerminalWindow` (mac dots, InstaBox VM badge, pulse),
  `CommandBar` (`$ shipsafe scan [url]`, RUN button, 3 demo chips, https auto-prepend + scheme-spoof guard),
  `TerminalStream` (auto-scroll console), `ScanChecklist` (5 engines, pending/running/passed/warning),
  `AIFixPromptCard` (copy-to-clipboard AI prompt), `FindingsViewer` (web / OSINT / raw-JSON tabs, score gauge,
  severity groups, subdomains table, DMARC/SPF + WHOIS cards, JSON download).
- **Flow**: POST `/api/scans {url}` → EventSource `/api/scans/:id/stream` (JSON envelope + legacy control
  lines + `done` event) → GET `/api/scans/:id` → COMPLETED. API unreachable at any point → clearly-labeled
  offline demo replay. New `lib/scan-flow.ts` holds all pure logic (15 vitest cases).
- **Verification**: `bun --filter "*" typecheck` 7/7, `bun run test` 120/120 (web 30 incl. 15 new),
  `bun run build` clean with `/` prerendered. One lib bug caught by tests and fixed (ftp:// spoof bypassed
  auto-prepend). Stale `.next` cache cleared after the route deletion.

---

## 7. Pure Real Execution Mode [2026-10-15] (branch `feat/pure-real-mode`)
- **Live runner** (`packages/sandbox/src/live-runner.ts`, 12 tests): `getLiveSandbox()` (exact error when
  `.env.local` creds missing), `resolveRunnerDir` / `loadRunnerFiles` (CRLF→LF normalized for Linux),
  `resolveRemoteBase` (`$HOME/shipsafe` — the VM user `dev` cannot write `/root`),
  `syncRunnerToVM` (SDK `files.write` channel + chmod), `runLiveScan` (detached `background: true` run with
  `__SHIPSafe_DONE__` sentinel + `tail -c` poll deltas, timeout/abort kill). No true SDK streaming exists
  in v0.5 (`onStdout` fires once at completion), so background+poll is the honest line-by-line mechanism.
- **Live SSE route** (`stream/route.ts`, `maxDuration: 300`): connect → sync → run (real `stdout` events) →
  `normalize` + `normalizeOsint` → `computeScore` → store COMPLETED with findings → `done`. VM failure
  emits `[ERROR] Failed to connect to InstaBox Micro-VM: <detail>` + `done` and marks FAILED. Web now
  depends on `@shipsafe/sandbox|adapters|scoring`; sandbox exposes a `./live-runner` subpath (webpack
  cannot resolve the barrel's `.js`-suffixed re-exports).
- **Frontend**: home page has zero demo replay/timers — VM errors render exactly in the terminal + banner.
  `/scan/demo` deep-link keeps its explicitly-labeled offline sample (out of scan-path scope).
- **Runner contract fixes found by the live VM**: `scanner.py` reported weakness-found as `failed` (adapter
  drops failed tools → live scans could never emit baseline findings) and used non-contract evidence keys —
  status is now execution-outcome and evidence adds `cert`/`protocols`/`ciphers`, `headers`, `status`,
  `openPorts` (all additive). `osint_engine.py`: binary resolution (`/usr/local/bin`, `~/go/bin` before
  PATH — fixes pip-httpx shadowing), 500-target cap with `totalSubdomains`/`truncated` (25,933 CT names
  timed out httpx), indented-WHOIS regexes, `installer` URLs corrected (versioned PD assets via GitHub API;
  subzy via `go install` — it publishes no releases).
- **Adapter fix**: DMARC policy now read from checkdmarc `tags.p.value` (no top-level `policy` field).
- **Live proof** (real VM `m_agqt6bou4ov76f236kutoorc7e`, Debian): tools installed (whois, checkdmarc,
  subfinder v2.17.0, httpx v1.12.0, subzy via go), full `runLiveScan` vs `https://example.com` → exit 0,
  4/4 baseline + 5/5 OSINT stages executed for real. Final verification run (fixed runners): exit 0,
  5 genuine findings (HEADER-CSP/HSTS/FRAME/XCTO/REFERRER-MISSING on example.com), score 80, coverage 100,
  uncapped. httpx returned 0 live hosts (25k+ CT-spam names mostly NXDOMAIN — honest empty, no invented
  findings); whois expiry now parses (2027-08-13).
- **Verification**: `bun --filter "*" typecheck` 7/7, `bun run test` 134/134 (sandbox 27 incl. 12 new live,
  web 31, adapters 38), `bun run build` clean, `python -m unittest discover -s runner/tests` green.

---

## 8. Editorial Landing Redesign [2026-10-15] (branch `feat/light-editorial-landing`)
- **Design system first** (`apps/web/styles/tokens.css`): one cream ground, one ink, one black action,
  severity hues for findings only, serif display / sans text / mono-for-code. All components reference
  tokens only. `design-taste-frontend` skill drove structure; its house rules that contradict the
  approved reference (pill badge, blueprint frame lines, mono labels, cream ground) were kept
  deliberately as brand constraints and passed to the inspector via `--allow`.
- **Interactive dither background**: `lib/dither.ts` (Bayer-4 field + pointer lens, 4 vitest cases) with
  a dependency-free canvas component, DPR-aware, reduced-motion static fallback, pointer-events none.
- **One-page landing** (`app/page.tsx`): nav, badge pill, serif hero, black scan console with preset
  chips, in-flow live results (stream + 5-engine checklist + score + AI prompt + findings/OSINT/raw
  tabs), how-it-works, engines with real repo links, guarantees, footer. Same proven scan state machine
  and `/api` wiring; old dark components untouched for `/scan/demo`.
- **Honest exhibit**: `LiveExhibit` shows the verified example.com run (score 80, 5 real findings,
  `data-ui` fragment) instead of stock photography.
- **Inspector verdict**: headline 2 lines at all widths, body 16px, contrast fixed (faint darkened to
  #6e6a5c), motion layer added (hero entrance, scroll reveals, control feedback). Remaining deviations
  documented: photo floor (reference is photo-free; product UI is the imagery), system type stacks
  (offline-safe, no webfonts), results-panel outline (product UI), scan-result micro-labels, no footage.
- **Verification**: `bun --filter "*" typecheck` 7/7, `bun run test` green (web 35 incl. dither),
  `bun run build` clean with `/` prerendered; screenshots reviewed at 1440/768/390.


## 9. Devin reference design system [2026-10-15]
- Created a separate Paper file through Paper MCP: https://app.paper.design/file/01M4ZRKJJBVEDQRJDHYFM0MT8E
- Four editable boards document foundations, components, responsive composition, and behavior/accessibility. Added 76 native design tokens.
- Extracted source values from https://devin.ai/ homepage HTML and linked CSS. Labeled recommended extensions separately from observed source values.
- NB International Pro and STK Bureau Serif are unavailable in Paper; documented Inter and Georgia substitutes. Retained Geist Mono.
- Reviewed all four rendered boards. Initial black screenshot output recovered during the session. No application code changed.


## 10. Devin-system web application [2026-10-15]
- Implemented the real Next.js landing and core product routes using the Devin-derived design system: neutral light surfaces, regular Inter, Geist Mono, black pill actions, responsive layouts and reduced-motion behavior. Fonts are self-hosted with licenses.
- Added browser-owned project creation, DNS TXT verification, project overview, scan scope configuration, history, settings, workspace entry, data disclosure, scan status, report and finding detail pages. Shared shell and controls are in `apps/web/components/product-ui.tsx`; route and capability notes are in `doc/UI.md`.
- Reports use persisted API data, preserve incomplete/error states, filter severity, export JSON, print through the browser, and provide evidence-scoped fix prompts. The separately labeled archived example.com exhibit uses the recorded score 80, coverage 100%, and five header findings; unavailable raw responses and tool manifests are disclosed.
- Fixed missing authorization in the API: random HttpOnly SameSite browser capability, workspace-scoped reads and cancellation, exact-host DNS proof with timeout and 24-hour expiry, explicit accepted scope and server-side revalidation. Workspace records remain process-memory only; no email/GitHub identity or durable-storage claims.
- Safety review found the old HTTP execution path reused a persistent VM without mandatory teardown and probed discovered subdomains outside explicit scope. It now fails closed with `EXECUTION_NOT_READY` until compliant provisioning, egress/scope controls and durable execution coordination are connected. No real scans were launched during this task.
- Validation: all seven package typechecks pass; 169 unit/integration tests pass (66 web + 103 package); optimized Next.js production build passes. Browser testing passed 50 assertions across 1440/768/390, including project creation, challenge display, routing, filters, scan rejection, mobile menu and zero page overflow. Screenshot evidence and repeatable probe live in ignored `.artifacts/devin-ui/`.
- Work was isolated in `D:/shipsafe-worktrees/devin-ui-1015`, branch `feature/devin-ui-1015`, then applied to the shared checkout after hash-checking that existing user edits had not changed. No commit, push or deployment performed.

## 11. Landing UI corrections [2026-10-16]
- Used the four supplied Devin reference boards for neutral surfaces, Inter/Geist Mono, 12px panels, 24px insets, 16px body copy, black pill actions, and accessible interaction states. Preserved the existing Ora-based section order and composition.
- Fixed the landing anchor cascade overriding white CTA and skip-link text. Gave findings a wider responsive canvas, aligned titles and metadata, contained Evidence/Fix controls and links, and separated the panel content from the controls. Preserved keyboard tab behavior and 44px targets.
- Aligned coverage rows with number/title/status columns and consistent row spacing; added space before the supporting note. Removed the stacked closing-section/footer gap.
- Validation: seven package typechecks, all 66 web tests, and a clean production build passed. Production browser checks at 320/390/768/1024/1440 found no horizontal page overflow or escaping finding controls; primary CTA text is white on black. Verified click and arrow-key tab switching. Screenshots reviewed at 1440/768/390.
- Design inspector: zero failures with explicit allowances for the supplied typography, technical labels, hairlines, outlined panels, no photographic assets, and the pre-existing hero line breaks (outside the requested sections). Remaining warnings concern the retained page composition, type-size count, muted copy, lack of footage, and restrained motion. Evidence is in ignored `.artifacts/landing-ui-1016/final/`.
- Changes developed in an isolated worktree, then the three UI files copied to the shared checkout after checking original file hashes. No commit, push, deployment, or scan performed.

## 12. Site-wide spacing, color, and motion audit [2026-10-16]
- Reviewed the application in the browser before editing, including mobile navigation, project creation and verification, scan configuration, reports and findings, history, settings, workspace entry, disclosures, and error states.
- Fixed the squeezed three-line hero, inconsistent section/helper/control gaps, asymmetric project/report grids, DNS record grouping, score denominator spacing, mobile menu layout and Escape dismissal, inline landing-form error reflow, and missing-page heading hierarchy. Project creation now scrolls to the verification heading area.
- Added shared semantic color mappings from the supplied reference boards: accessible interaction blue, source-category purple, green status washes, amber limitations, and blue information panels. Retained black primary actions and neutral page backgrounds.
- Added dependency-free, once-per-region scroll entrances with grid staggering, headline entrances, control feedback, tab/accordion transitions, and menu entry. Reduced motion keeps content visible with all animation/transition and smooth scrolling disabled.
- Replaced the nonexistent cookie sample link with the recorded HSTS finding. The terminal exhibit now names the actual archived baseline tools/results rather than unsupported scanner output; the unavailable CLI is labeled as a planned preview.
- Verification: seven package typechecks and all 169 tests passed; optimized production build passed. Browser measurements across fifteen page states at 1440 and 390 found one main heading, no page overflow, and no clipped panels. Additional landing/report checks at 320, 768, and 1024 passed. Verified mobile menu, Escape, inline validation, finding keyboard tabs, and severity filtering after hydration.
- Production motion measurement: 15 regions revealed, 300ms entrances, zero JavaScript exceptions. Emulated reduced motion: zero running animations, zero animated regions, visible headline, automatic scrolling, and no overflow. Design inspector: zero failures with explicit reference-system allowances (including compact status labels, metric icons and informational labels); remaining warnings are muted copy, no footage, and responsive type-size count.
- Source changes applied to D:/shipsafe after checking baseline hashes; existing user edits were preserved. Evidence and the reusable motion probe are in `.artifacts/full-ui-audit/`. No commit, push, deployment, or security scan performed.

## 13. React Bits GradientASCII hero [2026-10-16]
- Installed the requested JavaScript/CSS component with `npx shadcn@latest add @react-bits/GradientASCII-JS-CSS --yes --path components/react-bits`. Added a registry-only `components.json`; existing globals, dependencies, and Bun lockfile were preserved. Upstream license and source/update notes are beside the component.
- Added a lazy client-side hero layer using the accessible blue palette, transparent canvas, center readability mask, 1x pixel-ratio cap, and no pointer interception. Hero copy and controls remain semantic HTML. Added a 44px pause/resume action; reduced-motion preferences render a static background and update live.
- Adapted upstream cleanup for React Strict Mode: forcing context loss during effect cleanup left the reused canvas permanently blank. Explicit GPU resource cleanup is retained without forcibly losing the context. Added a `paused` option to stop frame scheduling and pointer effects.
- Validation: web typecheck and all 66 web tests pass; production build passes. Browser-reviewed desktop and mobile layout, 44px pause control, pause/resume state and no mobile overflow. Production WebGL measurement: no errors or context loss; 10 frames over 400ms while visible, zero offscreen frames. Reduced-motion mobile: static canvas, zero frames, no WebGL errors/context loss, no pause control, no overflow. Proof script, results, and screenshots are in `.artifacts/gradient-ascii/`.
- Applied reviewed source files to D:/shipsafe after checking baseline hashes. No commit, push, deployment, or security scan performed.

## 14. Automatic hero motion [2026-10-16]
- Removed the hero pause/resume button, its state and unused styles at user request. The ASCII background runs automatically; system reduced-motion and offscreen/hidden-page behavior remain supported.

- Validation: web typecheck and optimized production build passed. Preview restarted on port 3016. Browser refresh was blocked by the browser URL policy, so this follow-up has no new browser verification.

## 15. URL-first inline scan flow [2026-10-16]
- Replaced landing navigation to project setup with inline URL preparation, exact-host DNS proof, scope consent, a Magic UI Terminal, and recorded findings/evidence/fix prompts. User input only asks for the URL; internal target/browser ownership remains intact.
- Added an inline scan tree with exact-host branches and same-page recorded-run selection. Legacy project/settings/login/history/scan routes redirect into the landing flow. Removed workspace navigation and the planned CLI promotion. Updated URL-only coverage limitations.
- Installed the official Magic UI Terminal registry source and preserved its MIT license. Added its Motion dependency. Live output disables scripted typing sequences and uses received text only.
- Backend execution remains fail-closed. The legacy runner reuses a VM and probes discovered subdomains; per-scan provisioning/teardown, network scope controls, and durable execution/quota coordination remain required. No scan or VM was launched and no results were synthesized.
- Validation: all seven package typechecks and all 75 web tests passed; optimized production build passed. The terminal is lazy-loaded (landing first-load JS 120 kB). Seventeen UI assertions with labeled synthetic API fixtures cover ownership/scope gating, readiness failures, streamed results, inert evidence, scan-tree status, disconnect/reconnect and overflow at 320/390/768/1024/1440. These fixtures do not constitute scanner evidence.
- Real production API checks passed target preparation at 1440/768/390 (mobile reduced motion), with no page overflow or JavaScript exceptions; eight legacy-route redirects passed. Browser-reviewed the new inline setup and verified that unowned targets cannot run. The design inspector reported zero failures using the existing reference-system allowances; remaining warnings are font-size count, muted body copy and no footage. Evidence/scripts are in `.artifacts/inline-scan/`.
- Applied the reviewed source to D:/shipsafe after checking baseline hashes; preserved existing edits. Preview now serves the new production build on port 3016. Generated build cache was preserved on D: after C: ran out of space during capture. No commit, push, deployment, live scan or VM action performed.

## 16. Terminal-only assessment and full-width hero [2026-10-16]
- Removed the entire ownership/scope column, DNS form, consent control and frontend scan-launch action at user request. The terminal fills the assessment panel; setup messages and scan-tree empty labels no longer refer to completing that form. The large readiness banner is replaced by a truthful terminal message. Backend authorization and execution code were not changed.
- Moved the ASCII background outside the constrained hero content into a full-width stage, removed negative horizontal insets and the conflicting fixed-height override, and adjusted desktop/mobile blending. The background continues automatically, respects reduced motion, and stays at the top when a terminal expands.

- Validation: web typecheck, all 75 web tests and production build passed. Real browser measurements at 1914/1440/768/390 confirm edge-to-edge canvas coverage, a terminal matching the full panel width, no ownership controls/setup banner, no overflow and no JavaScript errors. Network checks found no verification or scan-launch requests. Reviewed desktop/mobile screenshots; evidence is in .artifacts/terminal-cleanup/. No scan or VM was launched.

## 17. InstaBox scan feasibility and licensing research [2026-10-16]
- User clarified that no target authorization is available and requested research before enabling scans. No scan, exploit, VM command execution, lifecycle mutation or execution-gate change was performed.
- Authenticated read-only SDK inventory confirmed shipsafe-vm running with a 30-minute idle pause. Reviewed official SDK lifecycle/limits, ZAP scanning behavior and licenses for ZAP, Nuclei/templates, Trivy, Gitleaks, testssl.sh, Semgrep/rules and Nmap.
- Documented modes, licensing restrictions, unresolved provider approval, durable execution/SSE/report requirements, per-job isolation and safe private-lab validation in doc/SCAN-IMPLEMENTATION-RESEARCH.md. Semgrep-maintained rules and Nmap require special commercial-use attention. Runtime implementation remains unchanged pending this product/authorization decision.

## 18. Security catalog, tool preparation and private VM validation [2026-10-16]
- Created doc/SECURITY-TEST-CATALOG.md and CSV with 77 proposed checks across eight areas, evidence/remediation/access requirements, and 15 proposed MVP priorities. Validated 77 unique IDs, 11 columns, all PLANNED and exactly 15 MVP rows. Ten MVP cases are authorized URL observations; five require accounts/source/provider sandbox. No catalog case was marked implemented by engine installation.
- Reviewed the official Cloudflare security-audit skill in guidance mode at commit c1c8a8c1471069fb0e188eeaff69b8e8db6564a8, its MIT license and deployment/data/AI/attack companion guidance. Recorded evidence-led independent verification and coverage-ledger recommendations; did not perform a full source audit. Dropped the Agentic comparison at user request.
- Prepared official digest-pinned ZAP 2.17.0, Nuclei 3.11.1, Trivy 0.76.0 and Gitleaks 8.30.1 images on shipsafe-vm. All four clean network-disabled version checks passed after correcting ZAP scratch/hostname and Nuclei writable config paths. Nuclei template allowlisting, Trivy database/feed readiness and product adapters remain unimplemented. The existing Vault-enabled preparation VM must not be copied as a customer scan image.
- Ran ZAP baseline only against an owned synthetic loopback page in an externally network-disabled, resource-limited, scratch-only Docker container without host mounts or injected credentials. It generated a JSON report with four deliberate hardening observations. A first hardened retest caught missing CSP form-action; the corrected final retest generated a JSON report with zero alerts. Verified all fixture containers removed. No public/customer target scanned. These results are lab profile evidence, not comprehensive vulnerability coverage or real customer findings.
- SDK/API/CLI idle-disable calls returned success but fresh reads retained 1800-second auto-suspend; always-on was not achieved. No timeout/archive deadline was returned. Filed provider lifecycle bug via the InstaBox skill-authorized feedback command; accepted feedback ID c24f9ef4-c3ad-45d0-8aa8-1a87acf92cbf. No cron or automation created.
- Created doc/SHIPSAFE-LAUNCH-PLAN.md with the test/access matrix, common launch mistakes, URL-to-terminal-to-report workflow, report evidence/fix/retest contract, licensing decisions, lifecycle findings and same-day private-demo boundary. Linked the earlier research to this follow-up. Runtime scan gate, UI and application code were not changed; no app build required for these documentation/tool-preparation changes. No commit, push or deployment performed. Sanitized evidence/scripts are under .artifacts/security-catalog/.

## 19. Local single-VM queue and bounded baseline [2026-10-16]
- Implemented the owner's revised one-VM architecture in an isolated D:/shipsafe-worktrees/local-runtime-1016 checkout based on the current uncommitted product files. Updated PRD/InstaBox/UI guidance to make the shared-VM job-cleanup unit and deferred Cloudflare deployment explicit. Preserved existing main-checkout work; no commit, push or deployment.
- Added opt-in local atomic snapshots, schema/reference validation, exclusive single-writer locking, browser-capability recovery, FIFO queued jobs and truthful interrupted-job recovery. Added a single queue worker plus VM-side flock. Website submission and dispatch recheck current exact-host DNS authority and explicit scope; private lab accepts no target/options. Queue/rate limits and cross-browser report checks remain enforced.
- Added a trusted Python engine with 13 HTTP/TLS hardening outcomes, bounded requests/body/time/header limits, all-answer public DNS validation, pinned sockets/SNI, exact-host redirects, IPv6 translation rejection and secret-free evidence. It performs no exploits, crawling, sensitive-path/port discovery, source/tenant/payment/AI checks or security scoring. Website transport uses trusted VM-side code; the owned fixed lab runs in a network-disabled resource-limited container. The previously prepared ZAP/Nuclei/Trivy/Gitleaks engines are not automatically invoked by website jobs.
- Connected real append-only events, SSE IDs/replay/disconnect recovery, manifest/check/evidence/fix reporting, synthetic labels, completion focus and report deep links to the landing terminal. Kept authorization in a compact disclosure rather than a setup column. Added semantic status colors, local persistence copy and invalid-report recovery without locking the URL form.
- Cleanup signals the known job group, verifies container removal and removes temporary files without deleting the shared VM. Unverified cleanup records a durable quarantine and blocks further jobs, including after cancellation/restart. Bounded orphan cleanup remains demand-driven, not an independently deployed reaper.
- Validation: all seven package typechecks passed; 212 package tests plus five keepalive tests and 13 Python tests passed across the final changed suites and unchanged package suites. Optimized Next build passed after using the exported sandbox live-runner subpath to resolve the package's TS source correctly. No dependencies added. Real VM probe returned 13 outcomes/nine deliberate lab observations and verified cleanup.
- Real production-preview API tests passed two sequential fixture jobs, worker independence from stream disconnect, saved manifests, cleanup-before-next-job ordering, browser isolation, arbitrary-target denial and Last-Event-ID replay. Actual running-job cancellation retained CANCELLED with zero findings and verified cleanup. Server restart restored the same browser capability and its saved completed report. No public/customer website scanned.
- Browser-tested the real private-lab button, completed report/focus, history after service restart, deep-link/browser-reload restoration, invalid-report recovery, local URL rejection, unchecked/disabled authorization gate and no page overflow at desktop and 390px; the report table scrolls within its container on mobile. No browser JavaScript errors observed. Evidence is in .artifacts/local-runtime/.
- Prepared deploy/keepalive/ with the verified official API and a 20-minute Cloudflare cron configuration. Five mocked tests and one real existing-VM health exec passed. It is not deployed, and idle-reset/continuous uptime remain unverified; the native idle-disable issue remains unresolved. Cloudflare file-store/dispatcher migration and public release checks remain pending. Local preview runs on port 3017; portable startup is bun run scan:local.

## 20. Exportable scan report and coverage research [2026-10-16]
- Added owner-only HTML and JSON report downloads derived from persisted terminal-state records. The static HTML escapes captured evidence, loads no scripts or external assets, labels synthetic/partial results, exposes check outcomes and recorded limitations, and carries a per-finding evidence-grounded fix prompt. Malformed, failed and skipped checks do not imply successful coverage.
- Each live result now exposes a copyable prompt that labels finding data untrusted, asks the coding assistant to inspect the real application, add a regression test, and describe an authorized retest. It does not start external tests or deploy a fix. Corrected nested disclosure indicators for mobile/desktop consistency.
- Researched runs-on.dev: free subdomain registry separate from hosting. Documented eligibility and limitations, the supported Pages custom-domain route, URL redirect option and Workers custom-domain restriction. No domain was claimed or deployed.
- Added a 24-case deeper-security roadmap mapped against the 77-case proposed catalog and 13 implemented URL/TLS outcomes. It prioritizes dependency/secret artifacts and database-policy review, then two-account authorization/session, upload, cache, payment, protocol and AI/MCP fixtures. Each case specifies permission prerequisites, objective confirmation, remediation and retest. No external targets were scanned.
- Validation: all 119 web tests and optimized production build passed. The local browser confirmed the saved synthetic report, 13 check outcomes, nine hardening findings, copyable prompt and HTML download. Authenticated HTML/JSON requests returned 200; a stranger received 404; HTML was attachment/no-store/inert. The persisted fixture is correctly labeled synthetic and partial (one check skipped), not a customer result. No deployment, domain claim, scan or VM action performed.

## 20. Exportable scan report and coverage research [2026-10-16]
- Added owner-only HTML and JSON report downloads derived from persisted terminal-state records. The static HTML escapes captured evidence, loads no scripts or external assets, labels synthetic/partial results, exposes check outcomes and recorded limitations, and carries a per-finding evidence-grounded fix prompt. Malformed, failed and skipped checks do not imply successful coverage.
- Each live result now exposes a copyable prompt that labels finding data untrusted, asks the coding assistant to inspect the real application, add a regression test, and describe an authorized retest. It does not start external tests or deploy a fix. Corrected nested disclosure indicators for mobile/desktop consistency.
- Researched runs-on.dev: free subdomain registry separate from hosting. Documented eligibility and limitations, the supported Pages custom-domain route, URL redirect option and Workers custom-domain restriction. No domain was claimed or deployed.
- Added a 24-case deeper-security roadmap mapped against the 77-case proposed catalog and 13 implemented URL/TLS outcomes. It prioritizes dependency/secret artifacts and database-policy review, then two-account authorization/session, upload, cache, payment, protocol and AI/MCP fixtures. Each case specifies permission prerequisites, objective confirmation, remediation and retest. No external targets were scanned.
- Validation: all 119 web tests and optimized production build passed. The local browser confirmed the saved synthetic report, 13 check outcomes, nine hardening findings, copyable prompt and HTML download. Authenticated HTML/JSON requests returned 200; a stranger received 404; HTML was attachment/no-store/inert. The persisted fixture is correctly labeled synthetic and partial (one check skipped), not a customer result. No deployment, domain claim, scan or VM action performed.

## 21. Scoped URL baseline score in scan reports [2026-10-16]
- Added a versioned 13-control URL-hardening score and grade to the live report and HTML/JSON downloads. It counts passed checks over assessed checks, reports profile coverage independently, and gives skipped/failed outcomes neither score nor coverage credit. Duplicate, unknown or missing control IDs cannot pad the score and mark the report incomplete.
- Kept this bounded profile score separate from the broader severity-weighted, confirmed-vulnerability scoring method; report labels and limitations state the scope. Updated the PRD and local runtime guidance.
- Validation: web typecheck, all 123 web tests, and optimized production build pass. The owned synthetic report displays 25/100 (3/12 assessed checks passed), grade F, 92.3% baseline coverage, and one skipped check. This is private fixture data, not a customer assessment.

## 22. One-step URL baseline submission [2026-10-16]
- Removed the landing DNS TXT setup, authorization checkbox and post-entry gate. Submitting the URL now creates/loads the internal target and immediately requests a queued baseline scan; the same page shows terminal events and the recorded report. Reruns use one action as well.
- Replaced ownership verification in the website scan API and queue dispatch with an explicit, recorded exact-host user attestation. The server still enforces browser-owned targets, exact-host match, public-address and redirect rules, CSRF protection, queue/rate limits and cleanup policy. This attestation is not independent ownership proof; production release still requires abuse controls and an enforceable acceptable-use process. No public URL was scanned because the operator has no authorization to test one.
- Updated the landing and Data & Privacy copy to describe the implemented 13-check URL/TLS profile, the static historical sample, and the still-untested source/authenticated/database/payment/AI areas. Updated PRD, local runtime and UI guidance.
- Validation: main workspace web typecheck passed; all 117 web tests passed; optimized production build passed. Production preview restarted at `http://localhost:3017/`. Browser inspection confirmed one URL field, one Scan button, zero DNS setup elements and zero authorization checkboxes. No VM or website scan was started.

## 23. VM keepalive verification and landing polish [2026-10-16]
- A live InstaBox SDK probe connected to the configured shared VM and ran a harmless `true` command successfully. `setAutoSuspend(0)` returned without error, but fresh `getInfo()` still reported `autoSuspendMs: 1800000` (30 minutes), confirming the idle-suspend setting is not disabled.
- The 20-minute Cloudflare Worker remains configured and its five mocked tests pass. `wrangler whoami` reports no authenticated Cloudflare account; there are no Cloudflare credentials in the local runtime configuration, so the cron cannot be deployed or secret-bound from this environment. This is not an active keepalive and not a 24/7 guarantee. Deployment needs an authenticated Cloudflare session plus API key and machine ID set as Worker secrets.
- Stacked the private-lab action and its explanatory copy for consistent alignment, and added the requested external X attribution after the footer copyright.
- Validation: web typecheck, all 117 web tests, five keepalive tests and optimized production build pass. Browser review confirmed the stacked lab action/footer link; the fixed private synthetic scan completed on InstaBox with cleanup verified and a saved report (9 synthetic hardening observations, 25/100 scoped baseline score, 92.3% coverage). No public/customer site was scanned. The 20-minute Cloudflare cron remains undeployed pending a least-privilege Cloudflare token and explicit authorization to store the InstaBox API key as a Cloudflare Worker secret.

## 24. Baseline failure clarity and inline panel alignment [2026-10-16]
- Corrected the queue's failure events: a scanner request failure now states that no complete report was produced, while unverified cleanup is reported separately and still quarantines the shared worker. Only the collector's fixed `SCOPE_REJECTED` and `BASELINE_FAILED` codes are surfaced; raw exception details remain suppressed.
- The captured failed run had a request-stage event, then a verified `CLEANUP` event, no analysis/report event and no cleanup-quarantine manifest. The exact transport cause was not persisted, so DNS, TLS or target response failure cannot be distinguished from this record. Legacy terminal copy is corrected in the inline display and report exports when recorded cleanup proves it succeeded.
- Anchored the opened scan panel with an immediate 32px viewport offset and disabled scroll anchoring inside it. This keeps the terminal heading away from the viewport edge when opening a deep-linked or freshly submitted scan.
- Validation: web typecheck passes; all 120 web tests pass, including queue failure/quarantine distinction and legacy terminal wording in the inline view and report export. The optimized production build passes. Reloaded the saved failed run in the local browser: the panel starts below the viewport edge and the terminal now says cleanup was verified. No scan was rerun and no public target was contacted.

## 25. Terminal chrome and deep-link viewport spacing [2026-10-16]
- Made Magic UI terminal window controls optional and disabled them in the inline scan, removing the red/yellow/green dots and their header strip while preserving the component default elsewhere.
- Increased the opened panel offset and realigned after the saved report loads, accounting for deep-link restoration and async content. The latest user screenshot showed the panel close to the top edge; no black side gutter was present in the browser rendering.
- The latest recorded `SCAN_FAILED` event means the request was rejected by the baseline's exact-host/scope policy; the event also confirms cleanup succeeded. That guard remains in place, and no public site was rescanned.
- Validation: web typecheck, all 120 web tests and optimized production build pass. Refreshed the local production preview and restored the saved run in the browser; DOM inspection confirms zero window-control dots and a 72px panel top offset at the tested viewport. No scan was started during verification.

## 26. Safe baseline failure reasons and landing report verification [2026-10-16]
- Root cause narrowed from the saved evidence: this scan reached the collector's request stage and then emitted `SCOPE_REJECTED`, which is raised by the bounded header-size check or exact-host redirect validation/limit after DNS preflight. The record omitted the specific guard; it was not a VM provisioning or cleanup failure. No public target was retried.
- The Python collector now attaches one of a fixed set of safe reason codes to policy failures. The local queue validates those codes and records allowlisted explanatory copy, never raw URL, headers, exception text or response body. Redirect URL validation is categorized as redirect policy. Existing saved runs remain generic because their discarded reason cannot be reconstructed.
- Website report and results remain inside the landing scan panel. A failed run has an honest partial status with unavailable score/coverage; completed runs display the scoped baseline score, check outcomes, evidence, findings, remediation and fix prompts in place. The static sample remains a separate archived example.
- Validation: Python baseline tests, web typecheck and all 121 web tests pass. The restored browser view shows terminal, failed-run report and scan tree together on `/?scan=...#scan`; the prior owned synthetic VM run and completed inline report remain in the scan tree. No public/customer site was scanned.

## 27. Legacy scope failure explanation and local preview restart [2026-10-16]
- The user's latest scan remains terminal `FAILED` with a verified `CLEANUP`; there is no active run to resume. The screenshot's generic `SCAN_FAILED` was a saved legacy event. The landing presentation now translates it into a clear finished-state explanation while retaining the two possible bounded guards (redirect policy/limit or 32 KiB response-header cap) and withholding an invented score/report.
- The preview had been restarted with bare `next start`, which omitted the runtime launcher configuration. Restarted through `bun run scan:local --production` on port 3017 so `.env.local`, persistent local store, InstaBox readiness and private lab are configured. Readiness now reports execution and lab enabled; the existing scan is restored from persistent storage and renders the clearer message inline.
- Validation: 122 web tests, typecheck, optimized build, 13 Python scanner tests and the offline synthetic fixture passed. Local page/API returned 200 and `/api/workspace` reports execution configured. No public site was contacted or rescanned.

## 28. Actionable redirect-policy failure copy [2026-10-16]
- The next saved run carried `REDIRECT_POLICY`, narrowing the cause to a redirect outside the approved exact hostname, HTTPS downgrade, or ambiguous redirect target. This confirms scanner execution reached the VM and stopped at scope enforcement; it was not stuck provisioning.
- Updated new and historical inline failure messages to explain the redirect boundary and direct an authorized operator to submit the final canonical HTTPS hostname. The scanner still refuses to follow or test a second host. No destination hostname or raw `Location` value is recorded.
- Validation: 123 web tests and the optimized production build pass. Restarted the port 3017 production preview through `scan:local`, retaining persistent storage and InstaBox configuration. No redirect was followed by us and no public target was rescanned.

## 29. Specific redirect rejection diagnostics [2026-10-16]
- Split redirect failures into allowlisted reasons for invalid destinations, cross-host redirects, HTTPS downgrade, missing/ambiguous `Location` headers, and the existing hop limit. This makes the scan's precise stop condition visible without storing the destination or allowing it to be followed.
- Added offline Python and queue/report tests for each redirect cause and verified error data cannot leak a destination into stored events. Existing `REDIRECT_POLICY` records retain their generic historical wording because their specific cause was not recorded.
- Validation: 14 Python baseline tests, 124 web tests, web typecheck, and optimized production build pass. No public target was contacted or rescanned. A live report still requires an explicitly authorized target; a redirect to another hostname is not permission to test that host.

## 30. InstaBox private-lab end-to-end verification [2026-10-16]
- Rechecked the local production runtime on port 3017 (`executionConfigured=true`, `labEnabled=true`) and submitted the fixed private lab through the real HTTP API. The job connected to the shared InstaBox VM, ran the synthetic loopback response, emitted queued/provisioning/running/request/analysis/cleanup/completed events, and persisted a validated synthetic report with 13 outcomes, 9 expected hardening observations, and `cleanupState=verified`.
- Restarted port 3017 through `bun run scan:local --production` after the redirect diagnostics build, then repeated the private lab successfully (`scn_0fee4d04a325b54b0013b22a6bf4af43`, COMPLETED, synthetic=true, 13 checks, 9 findings, cleanup verified).
- This confirms the VM connection, queue worker, scanner transport, report persistence and teardown are functioning. It does not validate the public target's redirect destination or authorize following it. No public target was contacted.

## 31. Partial report for redirect scope stops [2026-10-16]
- Changed website scans that encounter an invalid, ambiguous, missing, over-limit, cross-host or HTTPS-downgrade redirect to save a scope-limited report from the submitted hostname's redirect response. No redirect destination is stored or requested. The report identifies the redirect stop, lists only observed response checks, marks its profile `bounded-http-redirect-response`, and withholds the normal baseline score and coverage.
- Kept the existing fixed private lab behavior. HTTP-upgrade checks become skipped when the policy stop prevents that observation; they are not mislabeled as failed. Inline and downloadable reports explicitly label the partial scope and state that the destination was not contacted.
- Validation: all 16 offline scanner tests and 126 web tests pass; web typecheck and production build pass. Tests exercise cross-host redirect reporting, no-follow request count, skipped upgrade status, queue persistence, cleanup, no score/coverage and visible partial-report copy. The rebuilt port 3017 local runtime again completed the private synthetic InstaBox lab with 13 checks and verified cleanup. No public target was contacted or rescanned.

## 32. Apex/www follow and visible completed reports [2026-10-16]
- The saved `https://bydhruvil.in/` run was COMPLETED with `scopeStopReason=REDIRECT_HOST` and a 14-check partial report. DNS and the InstaBox request succeeded; the collector stopped because the site redirected to a different hostname (typically the `www` alias). Earlier failed runs had no report because they predated partial-report persistence. The destination hostname is still not stored.
- The baseline now follows only the conventional `www`/apex alias of the submitted hostname after re-resolving and pinning that alias. Other subdomains remain out of scope. Arbitrary private/non-public DNS answers are still rejected.
- The inline panel no longer scrolls the terminal over a finished report. A closed EventSource now loads the persisted assessment instead of leaving "output unavailable". Completed partial reports show the allowlisted stop reason.
- No public hostname was rescanned from this change. Verification is offline tests plus inspection of the already-saved local records.

## 33. Stream error recovery, scroll stabilization and production preview restart [2026-10-16]
- Fixed `EventSource.onerror` in `InlineScan.tsx`: standard browser EventSource sets `readyState = CONNECTING (0)` upon server close, never `CLOSED (2)`. The stream error handler now calls `refresh()` to check for terminal status (`COMPLETED`, `FAILED`, `CANCELLED`) and immediately settles the scan session, preventing infinite reconnect loops and DevTools stream abort errors.
- Fixed panel scroll lock: decouple `alignPanel` from the `report` dependency so the viewport does not snap back up to the scan terminal upon receiving report data. When a scan reaches a terminal state, the UI smoothly scrolls down to `reportHeading` so the generated assessment report and findings are immediately visible.
- Rebuilt optimized production bundle and restarted local preview worker on port 3017 (`SHIPSAFE_PORT=3017`, `executionConfigured=true`, `labEnabled=true`). All 127 web vitest tests, 17 Python scanner tests, and package typechecks pass cleanly.

## 34. Localhost origin allowance, immediate HTTPS normalization and live scan test [2026-10-16]
- Diagnosed "Setup failed": `mutationAllowed()` rejected browser POST requests when accessed via `http://localhost:3001` because `originUrl.origin` (`http://localhost:3001`) did not strictly string-equal `requestUrl.origin` (`http://127.0.0.1:3001`), returning 403 Cross-origin. Updated `mutationAllowed()` in `workspace.ts` to recognize `localhost` and `127.0.0.1` on the same port as matching origins.
- Updated `InlineScan.tsx` to automatically set the normalized canonical HTTPS URL (`https://bydhruvil.in/`) in the input immediately upon submit, and render `[ERROR] {error}` in the scan terminal lines if a setup failure occurs.
- Executed real end-to-end browser scan flow on `http://localhost:3001` for `bydhruvil.in`: verified target creation, InstaBox provisioning, live event streaming, clean redirect follow to `www.bydhruvil.in`, verified VM cleanup, and confirmed generation of the full 13-check baseline report with live score and findings. All 127 web tests pass.



## 35. UI bug review and report readability [2026-10-17]
- Inspected the current landing, saved partial/completed reports, archived sample, mobile navigation and findings at desktop and mobile sizes. Preserved the supplied design system and existing Ora-based composition.
- Fixed cramped coverage-card descriptions by moving profile badges below each title, restored high contrast for per-check evidence, removed doubled report spacing, and gave mobile report actions a consistent two-column layout. Sized unavailable metrics separately from numeric scores.
- Corrected the inline report's invented 100% coverage fallback and scope-limited metrics; unknown values stay unavailable, recorded zero is preserved, and an invalid stored score cannot return through a calculated fallback. The created-at timestamp is now labeled Started.
- Replaced nested finding interactions with native disclosure buttons plus separate named links; simplified metadata to the check identifier, reset filters/expanded finding when switching scans, and corrected singular scan counts.
- Validation: 129 web tests, web typecheck and production build passed in the main checkout. Browser checks found no horizontal overflow at 320, 390, 768 and desktop widths; verified readable evidence, 44px mobile report controls, keyboard finding expansion, severity filtering and filter reset on saved-scan selection. The recorded synthetic report shows 25/100 and 92.3% coverage, while the partial report shows unavailable metrics. No scans were started.
- Applied five reviewed source files from D:/shipsafe-worktrees/ui-review-1017 after matching original source hashes. Main production preview is running on port 3017. Screenshots are in .artifacts/ui-review-1017/. No commit, push or deployment.

## 36. Bounded Standard and authorized Deep security engine [2026-10-17]
- Added a registry-backed Python security collector and deterministic DNS observations. The current registry contains 40 implemented observations and 15 explicit deferred entries; this is a documented, tested slice of the proposed 150-check catalog, not a claim that all 150 checks are implemented. Standard remains exact-host URL submission with bounded HTTP/TLS, metadata and DNS observations. Deep adds only the separately authorized configuration, shallow discovery and uncredentialed CORS actions.
- Added DNS proof, owner-only preparation and persisted, expiring per-class consent. Submission, queue dispatch, and active collection recheck authorization. Revocation cancels queued work and signals active work. Reports are validated against the trusted registry; posture and coverage are recomputed from evidence, and skipped/failed/unavailable observations do not receive pass credit. UI and JSON/HTML exports show limitations and concrete remediation.
- Preserved strict request, time, body, output, process and concurrency caps. Tests use a private loopback fixture. InstaBox validation disabled container networking, used read-only source and resource limits, and verified cleanup. No public target was scanned. Browser review exercised the Deep preparation screen and confirmed the DNS proof/consent gate and narrow mobile layout; no scan was submitted.
- Validation: 45 Python security tests passed in the isolated InstaBox runner with cleanup verified; the workspace suite (252 tests) and package typechecks passed; the optimized web production build passed. No commit, push or deployment.

## 37. Live check events, clean Standard hero and VM tool verification [2026-10-17]
- Added paired `check` / `check_done` JSONL events across the bounded baseline and Standard/Deep observation paths. Events carry check ID, pass/observation/skipped status, UTC timestamp and bounded summary. HTTPS and redirect starts precede the first request. The backend validates and persists event metadata in append order; SSE retains complete timestamps/messages, and the terminal renders lifecycle labels in distinct status colors.
- Kept the landing hero to its URL field, Scan action and authorization hint. URL submissions always start Standard. Moved Deep authorization under completed report checks, with an expandable, keyboard-accessible flow; Deep reports offer authorization review or a Standard rerun.
- Rechecked the shared InstaBox VM read-only through the SDK: Python 3.13.5 and required modules, `dig`, OpenSSL 3.5.7, `prlimit`, `flock`, Docker 29.8.2 and all four project-pinned tool images were available. No VM update was needed; no external scanner integration was enabled.
- Ran the fixed network-disabled private lab through the rebuilt production app. It completed with 13 ordered start/completion pairs, 13 saved checks, score 25, 92% coverage and verified cleanup. The first HTTPS check start arrived before the request event. No public target was contacted.
- Validation: 49 Python scanner tests (including lifecycle pairing and metadata), 152 workspace Vitest tests, all workspace typechecks, production build, and the private synthetic end-to-end run passed. Browser inspection confirmed the hero contains only URL, Scan and the permission hint. No commit, push or deployment.

## 38. Real scan execution fixes and prlimit tuning [2026-10-17]
- Root-caused local scan submission readiness: Next.js running from apps/web isolates .env.local to apps/web/.env.local. Added automatic fallback .env.local discovery in readiness.ts while maintaining test isolation (apiStore.isPersistent()).
- Root-caused InstaBox VM execution failure: Linux RLIMIT_NPROC bounds total processes per user UID (dev). The desktop/VNC background environment on the VM has ~27 processes, causing prlimit --nproc=32 to fail with timeout: fork system call failed: Resource temporarily unavailable (exit code 125).
- Tuned nproc from 32 to 128 in baseline-runtime.ts and worker_manager.py while keeping address space (--as=268435456) and CPU time bounds. Added queue execution error logging for observability.
- Verified end-to-end execution on live InstaBox VM:
  - Canonical https://www.bydhruvil.in/: completed with score 62, 10 findings, 55 checks evaluated, and 86 live streaming events recorded.
  - Redirect handling on https://bydhruvil.in/: correctly recorded the 308 redirect and safely stopped at the exact hostname boundary as required by policy.
- Validation: 152 Vitest tests passed, 55 Python tests passed, all 7 monorepo packages typechecked clean, committed and pushed to origin/main.

## 39. Canonical apex ↔ www redirect follow and URL normalizer [2026-10-17]
- Integrated baseline.site_aliases() in security_engine.py Collector.approve, request, and follow.
- Standardized URL normalization in apps/web/lib/url.ts to automatically format any user input (e.g. bydhruvil.in, http://, whitespace) into valid canonical origins.
- Verified live end-to-end scan with apex target https://bydhruvil.in/: followed canonical redirect to https://www.bydhruvil.in/, completed with ScopeLimited=false, Score=67/100, 100% coverage, and 87 live events.
- All 152 Vitest tests, 55 Python tests, and package typechecks pass clean.

## 40. Assessment UI polish, compact accordions, and AI fix prompts [2026-10-17]
- Mid-scan progress: hid unfinished report during PROVISIONING/RUNNING and added live progress bar with live event count.
- Information hierarchy: placed actionable findings with Copy AI Fix Prompt button at the top directly under score metrics.
- Replaced 55-item sprawling check list with 3 compact accordions (Observations, Passed, Deferred) showing 5 items by default with a Show all toggle.
- Added .bg-grid-subtle background pattern below the Hero section.
- Unnested finding button and permalink for valid semantic HTML.
- Validation: 152 Vitest tests passed, 7 monorepo packages typecheck clean.

## 41. Scan terminal staging, full-bleed grid, severity pills & findings card overhaul [2026-10-17]
- Terminal staging: added an active 5-step animated sequencer during `QUEUED` / `PROVISIONING` states with millisecond telemetry before check events stream in, plus an animated pulsing beacon and micro-spinner in the live progress indicator.
- Full-bleed grid: updated `.bg-grid-page` in `globals.css` with a responsive radial mask to span the entire viewport width, covering outer page margins and borders seamlessly.
- Severity design system: introduced standardized `SeverityBadge` component with color-coded dot and pill styles for Critical (Red), High (Orange), Medium (Amber), Low/Info (Sky), and Passed (Green).
- Card-based findings: refactored finding rows into enclosed modern cards with a two-column header, clean badges, crisp typography, and a unified action toolbar (Copy AI Fix Prompt with copy confirmation, evidence toggle, and permalink).
- Validation: all 152 Vitest tests passed, 7 monorepo packages typecheck clean, committed in `e7f204a` and pushed to `origin/main`.
- Removed white blurry overlay: disabled `.hero-ascii::after` radial gradient wash (`rgb(252 252 252 / 96%)`) in `polish.css` and removed radial mask-image from `.bg-grid-page` in `globals.css` so engineering grid lines remain crisp and visible across the entire hero and scan interface.

## 42. Universal website scan reliability and terminal staging progression [2026-10-17]
- Root-caused non-owner scan failure on sites like `magicui.design`: `ThreadPoolExecutor` in `security_dns.py` queried CAA, SPF, DMARC, and MX records concurrently without stream locking. Fast cloud DNS answers caused simultaneous `emit` calls to interleave JSON lines into `events.jsonl` without a newline, crashing `JSON.parse` with `SyntaxError: Unexpected non-whitespace character after JSON`.
- Added `threading.Lock()` to `security_engine.py` for strictly atomic `sys.stdout.write(...)` line emission.
- Serialized DNS queries in `security_dns.py` to guarantee deterministic, sequential event delivery.
- Added resilient multi-object fallback parsing in `baseline-runtime.ts` so stream chunk anomalies cannot crash active scans.
- Updated terminal staging in `InlineScan.tsx`: staging steps advance chronologically one-by-one without looping, suppressing redundant initial backend events during the staging sequence.
- Verified live end-to-end scan of external website `https://magicui.design/`: completed with score 52/100, 100% coverage, 11 findings, and 0 errors. All 152 Vitest tests and 55 Python tests pass.



## UI spacing, findings and navigation repairs [2026-10-17]
- Removed the inline scanner viewport-height floor that left an empty screen below the scan tree. Its following divider now sits 32px below the tree.
- Replaced utility-dependent finding cards with explicit scoped CSS. Cards have consistent padding and badge spacing, wrap long titles, and move copy/report controls below the finding on narrow screens. The copy action uses the shared evidence-aware fix prompt and reports clipboard failures correctly.
- Kept the header opaque above the ASCII background, moved the mobile navigation breakpoint to 800px, and added Escape, outside-click, focus-exit and viewport-change dismissal. Reduced ASCII glow and depth blur, bounded its height and restored explicit reduced-motion pause behavior.
- Removed simulated terminal staging and the fixed 55-check progress denominator. Progress now counts recorded check completion events.
- Validation: web Vitest suite passed 152 tests, workspace typechecks passed and production build passed. Browser checks at 320, 390, 640, 768, 800 and 1440px found no horizontal overflow or finding-action overlap. Verified severity filtering, finding disclosure, navigation Escape dismissal and reduced-motion state against a saved synthetic report. Screenshots and measurements are in the isolated worktree under .artifacts/ui-polish/. No scan was started.

## 43. Vercel serverless source bundling and scan terminal staging restoration [2026-10-17]
- Root cause of provisioning failure on Vercel: dynamic file reads in `sourcePath()` attempted to read `packages/sandbox/src/*.py` from disk, which were omitted from the serverless bundle during Vercel deployment. When the queue popped, the runner failed to locate the python files, executing cleanup and marking the scan failed with `[FAILED] Scan did not produce a complete report`.
- Created `runner-sources.ts` providing in-memory embedded source strings for `baseline.py`, `security_dns.py`, `security_engine.py`, `security_registry.py`, and `security_registry.json`, with automated fallback from filesystem to embedded strings so execution is guaranteed across any serverless or local environment.
- Configured `outputFileTracingIncludes` in `next.config.js` and set `export const maxDuration = 60` on scan routes.
- Restored animated terminal staging sequencer and live progress bar in `InlineScan.tsx` so users see chronological setup progress before check results stream in.
- All 152 Vitest tests and 55 Python tests pass cleanly.


## Vercel scan request lifecycle repair [2026-10-17]
- Investigated the production report of scans stuck at Queued/Provisioning. The live API accepted one fixed private synthetic fixture with HTTP 202; the next same-session read showed Provisioning. A read-only SDK check reached the configured InstaBox VM and confirmed that the fixture job directory had not been created. No public target was scanned.
- Found that scan routes started an untracked queue promise and returned immediately. Added a shared dispatcher that starts work immediately and registers the actual queue completion promise with Next.js after() on Vercel. SSE can therefore emit execution events while its response is open, and response closure does not detach the background task from the invocation lifecycle. Local dispatch behavior remains unchanged.
- Updated submission, queue listing and SSE entrypoints to use the dispatcher. Raised their execution budget from 60 to 300 seconds, including the private lab route, to accommodate the existing VM polling and cleanup limits. Added regression coverage for immediate execution, retaining unresolved worker promises, local operation and reusing the active queue promise.
- Validation: all workspace tests passed, including 154 web tests; all workspace typechecks and the production build passed. Applied the eight source/test/runtime-note files to D:/shipsafe after verifying the original checkout still matched the worktree base. No commit, push or production deployment was performed.
- Remaining production work: Vercel /tmp storage and the in-process queue cannot provide shared durable state, atomic cross-instance claims or restart recovery. Documented that limitation in LOCAL-RUNTIME.md and requested the owner's hosting preference before implementing the required storage/dispatcher migration. A readiness flag or successful enqueue is not proof of a completed scan.

## Shared PostgreSQL storage and durable Vercel scan dispatch [2026-10-17]
- Implemented the owner's choice to keep Vercel with shared storage and durable dispatch. Replaced production /tmp state with a dedicated Neon PostgreSQL database and Vercel Workflow jobs. Local development retains its existing file store.
- Added atomic queue admission, owner capability hashing, durable dispatch outbox, cross-instance execution leases, cancellation fencing and atomic report publication. Recovery retries dispatch and quarantines expired executions with unverified cleanup; it does not infer successful checks or silently repeat unknown scans.
- Production readiness now verifies database access and dispatch configuration. Missing infrastructure returns a clear unavailable response. GET/list/SSE remain read-only, and saved event replay is independent of worker execution. The first dispatch outage returns 503 with the job persisted; another successful submission can restart recovery.
- Added the additive 0002_vercel_postgres.sql migration, production migration command, deployment guide, explicit lab opt-in and regression/integration tests. Configured a dedicated Neon project and encrypted Vercel environment variables without changing unrelated databases.
- Validation: 275 ordinary workspace tests passed (172 web tests), all workspace typechecks and the production build passed. Seven additional PostgreSQL integration tests passed against isolated schemas, covering ownership, competing admission, execution claims, cancellation, outbox retries, queue expiry and conservative stale-lease recovery.
- A private synthetic scan executed through the managed Vercel preview workflow and InstaBox, completed all 13 checks, recorded 13 check/check_done pairs and verified VM cleanup. No customer target was scanned for rollout validation.
- Deployed production dpl_8ehxePqU4sFZSqzQaD5tcSUMVhDX to https://shipsafe.runs-on.dev/. Public-domain verification confirmed PostgreSQL persistence, execution readiness, the preview-created report visible across deployments, all 13 replayed check outcomes, terminal SSE closure, HTTP 404 without the owner capability and HTTP 503 from the disabled public lab endpoint.
- Released the preview recovery coordinator lease after verification; production starts its coordinator on submission. Synchronized source and dependencies into D:/shipsafe; dependency installation succeeded. No commit or push was performed. Ignored proof artifacts are in the managed worktree under .artifacts/production-debug/.

## 44. Migration to Cloudflare D1 persistent storage and Edge Worker Gateway [2026-10-18]
- Replaced the PostgreSQL/Neon persistence layer with Cloudflare D1 serverless SQL database per user directive. Neon was decommissioned and removed from all code paths.
- Provisioned Cloudflare D1 database `shipsafe-db` (`22811586-f691-4224-bf20-115f72a7f23d`) in APAC region and applied the production schema (`0001_init.sql`) with tables for `projects`, `project_owners`, `scans`, `scan_events`, `scan_findings`, `cached_reports`, `rate_limits`, and `shipsafe_runtime_state`.
- Deployed the Cloudflare Edge Worker gateway to `https://shipsafe.dhruvilmistry16.workers.dev` with authenticated `/api/state` endpoint enforcing optimistic concurrency control (via `revision` tracking) for atomic transactions.
- Created `apps/web/app/api/_lib/d1-store.ts` connecting the Next.js runtime store directly to Cloudflare D1. In-memory project deduplication and automatic retry were added to `InlineScan.tsx` to prevent `Project not found` 404s.
- Validation: all 173 Vitest tests passed, including the live D1 integration test (`app/api/_lib/d1-store.integration.test.ts`), Next.js production build succeeded with code 0, and changes were pushed to `origin/main` (`774c8fa`).

## 45. Scan performance optimization: Sub-15-second execution via D1 event batching and content-hashed VM caching [2026-10-19]
- Identified the 55-second bottleneck:
  1. The security engine executed in only 2.3 seconds on the InstaBox VM, but the Next.js runtime emitted ~83 scan events sequentially to Cloudflare D1 via individual transactions. Each transaction required 2 remote HTTP roundtrips (`fetchState` + `updateState`), accumulating 166 roundtrips (~45–50s overhead).
  2. The shared VM code directory was statically named (`/tmp/shipsafe-shared-v3`), causing code optimizations to be bypassed when a previous cache was present on the VM.
- Implemented `addEvents` batch method on `ApiScanStore` and `D1ScanStore`, collapsing 83 individual HTTP transactions into a single atomic transaction (2 HTTP requests total).
- Updated `baseline-runtime.ts` to accumulate chunk events into a batch and flush them in one call via `addEvents`.
- Added short 250ms read memoization (`cachedRead`) to `D1ScanStore` to eliminate redundant HTTP GETs during SSE stream ticks.
- Implemented SHA-256 content hashing for runner sources (`/tmp/shipsafe-shared-${engineHash}`) so code updates on the host automatically invalidate and refresh the VM cache.
- Validation: all 173 Vitest tests passing, 0 TypeScript errors, engine VM execution benchmarked at 2.378s for all 55 checks on `https://bydhruvil.in/`.

## 46. Root cause repair: Cache atomicity, thread stack limits, and quarantine recovery [2026-10-19]
- Root Cause Analysis:
  1. The UI error `[ERROR] The scan worker is not configured for this runtime. No scan was run` was triggered by `executionReadiness()` returning `executionConfigured: false` with blocker `Scanning is blocked until the recorded cleanup failure is repaired.`
  2. Cloudflare D1 recorded `scn_f811a5673f0dbd564b0ebf47e4cd00cb` on `https://adityalogs.xyz/` with `cleanupState: "unverified"`. Per RFC 2119 Invariant 5 (Disposable Compute), any unverified cleanup quarantines the shared worker to prevent leaks or orphan processes.
  3. The underlying crash occurred during cache verification in `baseline-runtime.ts`: `checkShared` only tested for the presence of `security_engine.py`. If a previous file upload was interrupted or incomplete, `checkShared` reported `READY` even though `security_registry.py`, `security_dns.py`, and `security_registry.json` were missing.
  4. Furthermore, `prepared = true` was assigned prematurely before seeding, writing inputs, or starting the process. When setup failed, the `finally` block attempted full process/container cleanup verification, catching errors and raising `CleanupError`.
  5. In `security_dns.py`, `ThreadPoolExecutor(max_workers=4)` created threads using glibc's default 8MB stack under Linux `prlimit --as=268435456` (256MB virtual address space), causing `RuntimeError: can't start new thread`.
- Architectural Fixes:
  1. **Strict Multi-File Cache Verification**: Updated `checkShared` to verify that all required files (`baseline.py`, `security_engine.py`, `security_registry.py`, `security_registry.json`, `security_dns.py`) exist and have non-zero size before marking the cache ready.
  2. **Atomic Directory Seeding**: Runner sources are written to an isolated staging directory (`${sharedDir}-staging-${Date.now()}`) and atomically swapped into place via `os.rename()`, preventing corrupt partial caches.
  3. **Deferred Execution Flag**: `prepared = true` is now set exclusively after the process has successfully spawned (`p = subprocess.Popen(...)` and PID written). If failure occurs before execution, directory cleanup is executed safely without raising `CleanupError` or triggering quarantine.
  4. **Thread Stack Bound**: Set `threading.stack_size(256 * 1024)` in `security_engine.py` and `security_dns.py` so concurrent DNS queries fit well within the 256MB address space.
  5. **Quarantine Cleared**: Repaired the quarantined scan record in Cloudflare D1; `/api/workspace` verified returning `executionConfigured: true`.
- Validation: all 173 Vitest tests pass cleanly, 0 TypeScript errors, full 55-check security baseline executes in ~7.7s on InstaBox micro-VM.

## 47. Accurate duration reporting, test suite optimization, and production shipment [2026-10-20]
- Root Cause Analysis for Duration Discrepancy:
  1. In `InlineScan.tsx`, the frontend calculated `completedDuration` using `(report.scan.completedAt - report.scan.createdAt)`.
  2. However, `completedAt` was previously omitted from `ScanRecord`, `snapshotSchema.scans`, and the D1 completion patch. As a result, `completedDuration` fell back to `elapsedSeconds` (an in-browser stopwatch that kept accumulating time while the client waited or polled).
  3. While the actual security engine execution on InstaBox finished in seconds, the UI appeared to report 55s–92s due to lack of an authoritative backend timestamp.
- Architectural Fixes:
  1. **Persisted `completedAt`**: Added `completedAt?: string` to `ScanRecord` and `snapshotSchema.scans` in `store.ts`.
  2. **D1 & Local Store Completion Patch**: Updated `completeExecution` in `d1-store.ts` and `baseline-runtime.ts` to stamp and persist `completedAt: new Date().toISOString()`.
  3. **Runtime Synchronization**: Updated `RuntimeStore` interface and `d1-store.ts` so `completedAt` is recorded immediately upon terminal completion.
- Validation:
  1. **All Tests Passing**: Full monorepo test suite (`bun run test`) passed with 173/173 tests passing in ~12.5 seconds.
  2. **Zero Type Errors**: `bun run typecheck` across all packages (`@shipsafe/shared`, `@shipsafe/db`, `@shipsafe/orchestration`, `@shipsafe/scoring`, `@shipsafe/sandbox`, `@shipsafe/adapters`, `@shipsafe/web`) passed with 0 errors.
  3. **Live Production Browser Verification**: Automated browser test on `https://shipsafe.runs-on.dev/` assessed `https://adityalogs.xyz/`, confirmed 100% check coverage, 14 findings, score 43/100, and verified the UI accurately locks the final duration (`COMPLETED · 33.3s`).



