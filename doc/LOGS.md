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

