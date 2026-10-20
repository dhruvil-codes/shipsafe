# Agent Guidelines for ShipSafe

Welcome, Agent. This file outlines instructions, principles, and workflows you MUST follow when working on the ShipSafe repository.

---

## 1. Context-First Principle: Use All Relevant Files
Before planning, implementing, debugging, or modifying any code or configuration:
- **Inspect Project Documentation First**:
  - [`doc/PRD.md`](file:///d:/shipsafe/doc/PRD.md): Product requirements, core invariants (RFC 2119), architecture, data contracts, and milestones.
  - [`doc/RULES.md`](file:///d:/shipsafe/doc/RULES.md): Coding standards, git conventions, safety guidelines, and review protocols.
  - [`doc/INSTABOX.md`](file:///d:/shipsafe/doc/INSTABOX.md): Complete InstaBox SDK, API, CLI, and resource limits reference from [https://instabox.sh/docs](https://instabox.sh/docs).
- **Consult Code & Schemas**: Always inspect relevant schema files, contracts, types, and existing tests before writing new logic. Never invent APIs or assume specifications without checking existing files.

---

## 2. Skill Discovery & Execution Workflow

### Using Available Skills
The repository maintains specialized agent skills in `.agents/skills/`. Always check and use them when handling relevant domains:
- **`ui-ux-pro-max`**: Design systems, UI components, styling, typography, responsive design, and UX guidelines.
- **`design-taste-frontend`**: Anti-slop frontend art direction, high-polish layouts, and landing page designs.
- **`improve-codebase-architecture`**: Architecture review, modularity, refactoring, and code organization.
- **`find-skills`**: Skill discovery and installation.

### Skill Discovery via `find-skills`
If you encounter a task or domain for which there is no matching skill installed in `.agents/skills/`:
- **Use the `find-skills` skill** to locate, evaluate, and install the required skill.
- Refer to [`.agents/skills/find-skills/SKILL.md`](file:///d:/shipsafe/.agents/skills/find-skills/SKILL.md).
- Search using `npx skills find <query>` or explore official registries to obtain the skill required for the job.

---

## 3. Core Invariants (from PRD)
1. **Evidence First**: A confirmed finding MUST be backed by scanner output or recorded test results. An LLM MUST NOT invent vulnerabilities.
2. **No Credit for What Did Not Run**: Skipped or failed tests never improve scores.
3. **Authorization Before Action**: No scan runs without validated ownership and scope.
4. **Policy Lives in the Backend**: Deterministic code enforces policy, never an LLM prompt.
5. **Disposable Compute**: Scans run in ephemeral, isolated sandboxes (InstaBox) and must always be cleaned up.

---

## 4. InstaBox Compute & Sandbox Guidelines
All scan compute runs in InstaBox cloud VMs. Refer to [`doc/INSTABOX.md`](file:///d:/shipsafe/doc/INSTABOX.md) and official documentation at [https://instabox.sh/docs](https://instabox.sh/docs).
- **SDK**: Use the official `@insforge/instabox-sdk` TypeScript package (`Sandbox.create`, `sbx.commands.run`, `Sandbox.kill`).
- **Capacity Limits**: Standard accounts are limited to **5 total machines** and **4 concurrent execs** (excess commands return `429 quota_exceeded`). Command executions timeout at **10 minutes**. Always enforce quota-aware scheduling.
- **Pull Architecture (S-09)**: Sandboxes never hold credentials or dial back to the ShipSafe control plane. The backend drives sandboxes via the SDK.
- **Mandatory Teardown (S-19)**: Every scan sandbox must be terminated (`Sandbox.kill`) upon completion, failure, or cancellation.

