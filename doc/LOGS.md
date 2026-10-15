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
- [ ] Configure linting, formatting, and CI workflows.
- [ ] Wire orchestration contracts to @shipsafe/shared (remove local TODO copies in orchestration + api/_lib).
- [ ] Live InstaBox E2E against https://example.com with real INSTABOX_API_KEY.

### [2026-10-15] Parallel Build — Agents 1-4 merged
- **Orchestrator**: scaffolded TS monorepo root (pnpm workspaces, tsconfig.base, apps/web shell), created 4 worktrees/branches, spawned 4 parallel agents.
- **Agent 1** (`feat/agent-1-instabox-runner`, 903472a): `packages/sandbox` (SandboxProvider, Instabox + Fake providers, quota 5 VMs/4 execs, streaming, S-09/S-19) + `runner/` (shipsafe-runner.sh + scanner.py, scan_result.json with ToolResult evidence). 15/15 vitest + 2/2 python unittest pass.
- **Agent 2** (`feat/agent-2-scoring-engines`, bf835bd): `packages/shared` (Zod contracts v1.0), `packages/adapters` (30-rule normalize, fingerprint dedup, redactSecrets), `packages/scoring` (weighted v1.0, critical-cap 40, coverage, explainer). 50/50 vitest pass.
- **Agent 3** (`feat/agent-3-backend-api`, 12c30db): `packages/db` (Drizzle pg schema + InMemoryScanStore), `packages/orchestration` (runScan QUEUED→COMPLETED, always-kill teardown, AbortSignal cancel), `apps/web/app/api` (POST scans with SSRF-guard + 5-slot quota, GET scan, SSE stream, POST cancel). 22/22 tests pass.
- **Agent 4** (`feat/agent-4-frontend-ui`, c1256b7): dark #0a0a0c dashboard (ScanBar, TelemetryBar sbx_live hero, Terminal, Checklist, ScoreGauge, FindingCard, mocks), landing + /scan/[id] split-screen, Export JSON/Print. typecheck + build pass. Also fixed `apps/web/tsconfig.json` extends placement (TS5023).
- **Merge sequence**: agent-2 → agent-1 → agent-3 → agent-4, all clean (2 fast-forward, 2 ort, zero conflicts).
- **Post-merge verification on main**: `pnpm -r typecheck` 7/7 pass, `pnpm -r test` 91/91 pass (db 6, orchestration 5, sandbox 15, web 15, shared 12, adapters 23, scoring 15), `runner` python 2/2 OK, `pnpm --filter @shipsafe/web build` pass after fixing Next 15 route `params: Promise<{id}>` types in 3 API routes.
- **E2E status**: `pnpm dev` + UI scan flow wired to /api/scans + SSE with mock fallbacks; live InstaBox E2E pending real API key.
