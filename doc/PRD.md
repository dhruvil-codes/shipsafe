# ShipSafe — Product Requirements Document

_Security testing for apps built at AI speed._

|                            |                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Status**                 | Proposed implementation specification (v1.1 draft)                                                            |
| **Product type**           | Developer security SaaS                                                                                       |
| **Primary infrastructure** | InstaBox cloud VMs. All scan compute runs there                                                               |
| **Hosting**                | Vercel: Next.js, serverless route handlers, Vercel Workflow, Vercel Cron. No separately hosted backend server |
| **Initial market**         | Indie hackers, SaaS founders, AI-assisted developers, small engineering teams                                 |

## Current product direction — URL-first scan flow (2026-10-16)

### Owner-directed runtime revision: single VM and $0 hosting (2026-10-16)

The owner's subsequent instructions supersede the per-job VM and Vercel hosting assumptions below for this MVP. Use one persistent `shipsafe-vm`, serialize scan jobs and retain per-job temporary-resource cleanup. Never kill the shared VM on normal job completion. This changes the S-19 teardown unit to the job process/container; authorization, exact-host network scope, evidence and credential separation remain required. Use only trusted built-in scanner code; uploaded customer code is out of scope for this persistent credential-bearing host.

Target hosting is Cloudflare Free with an initial workers.dev URL. Deployment is deferred until local behavior is verified. The current local implementation uses an opt-in, single-writer atomic file store; it is not a Cloudflare persistence adapter. Durable Cloudflare storage/dispatch must be connected and tested before public deployment. A separate externally scheduled keepalive is prepared; its 20-minute cadence is not an uptime guarantee or proof that provider idle detection resets.

The local baseline has 13 bounded HTTP/TLS hardening outcomes, no exploit scans and no source/tenant/payment/AI testing. Its report may show the versioned URL baseline check score (passed checks / passed plus observed checks) and profile coverage, clearly separated from the broader confirmed-vulnerability score in Section 15. Skipped and failed tests receive no credit. If the submitted hostname redirects outside the approved hostname (including its conventional www/apex alias) or HTTPS policy, or the redirect response is invalid or ambiguous, ShipSafe records a partial report of that hostname's redirect response only; it does not contact the destination and does not assign the full-profile score or coverage. On URL submission, the user action records an explicit exact-host authorization attestation; DNS TXT setup and a separate consent checkbox are not part of the flow. This attestation is not independent proof of ownership, so the profile stays low-impact, exact-host, rate-limited and technically constrained; production deployment still needs abuse controls and an enforceable acceptable-use process. A fixed owned lab fixture is available for end-to-end verification and must be labeled synthetic. Job execution is independent of browser/SSE connections. Persist reports/events, cap the queue, enforce VM-level mutual exclusion, retain cancelled/failed status and stop the worker if cleanup is unverified. Full details and current limits: [LOCAL-RUNTIME.md](LOCAL-RUNTIME.md).

This user-directed scope supersedes the project/workspace onboarding screens and
mandatory integration steps described in the original workflow below.

- Enter a website URL on the landing page. Open output inline without
  navigation to another page. No project name, environment, GitHub, team, login,
  workspace or settings screen is required.
- Open a terminal-only assessment panel and start the URL baseline as soon as the
  user submits a URL. Do not show an ownership column, DNS setup or separate
  authorization checkbox. The Scan action itself records the user's exact-host
  authorization attestation; backend scope and network safeguards remain required.
- Show actual server/scanner events in the Magic UI Terminal. Keep results,
  captured evidence, remediation and repeated runs on the same page.
- A scan tree groups this browser's targets and recorded runs. Legacy UI routes
  redirect to the landing scan or scan tree. Internal owner/target identifiers
  remain implementation details and retain access isolation.
- Website-only assessment cannot confirm source, dependency, authenticated,
  database or AI controls without additional access. Mark them untested.
- The opt-in local worker uses the shared InstaBox VM, a bounded trusted transport,
  a durable single-writer queue and verified job cleanup. Outside configured local
  mode, the API fails closed. A Cloudflare storage/dispatch adapter and production
  validation remain required before public deployment. An unavailable runner must
  not produce simulated output, scores or findings.

Acceptance: one URL submission creates the target, records the user's exact-host
authorization attestation and queues the bounded baseline without DNS setup;
old routes return to the landing flow; recorded scan selection stays inline;
failures/disconnections stay explicit; mobile reflows without horizontal overflow.

## 0. How to Use This Document

This PRD is written for both humans and coding agents.

- **MUST / MUST NOT / SHOULD** follow RFC 2119. A MUST is an invariant, not a preference.
- Requirements have IDs: features `F01–F16`, security rules `S-xx`, acceptance criteria `AC-xx`. Reference them in tasks, tests and commits.
- Section 5 lists the **core invariants**. If an implementation choice conflicts with one, the invariant wins.
- Appendices hold implementation detail: InstaBox integration notes (A), tool runbook (B), data contracts (C), build order (D).
- Items tagged **\[VERIFY\]** depend on external documentation or vendor policy. Confirm them before relying on them.

**Building with parallel agents.** Appendix E defines the runtime architecture, Appendix F the workstreams, file ownership, contracts and merge rules, and Appendix G the decision log. If you are an implementing agent, find your workstream in Appendix F, read only the contracts it names, and edit only the paths you own.

## 1. Product Summary

ShipSafe is a security assessment platform that helps developers find, understand and fix vulnerabilities in their web applications before and after deployment.

A developer submits a website URL, verifies ownership, authorizes a scan, and receives a report covering the controls ShipSafe can assess remotely. Connecting a GitHub repository, providing test accounts and configuring API access unlock deeper assessments.

ShipSafe runs security tools inside isolated InstaBox cloud machines, combines their findings, explains the results and provides remediation guidance. Every finding includes **evidence, severity, an explanation and a recommended fix**.

The product makes security checks _repeatable_. It does not promise that every vulnerability will be discovered.

## 2. Problem Statement

Modern tools let developers build and deploy SaaS applications quickly. Security verification has not become equally easy.

- Security checks are scattered across multiple tools.
- Vulnerability reports require expertise to interpret.
- Developers often overlook API authorization and database permissions.
- AI-generated code can introduce insecure defaults and authorization mistakes.
- Teams cannot easily compare security before and after a fix.
- Basic scanners cannot verify important behavior without credentials or source access.
- Founders lack a straightforward way to judge release readiness.

ShipSafe brings these checks into one workflow while preserving the evidence and limitations of each testing method.

## 3. Goals and Non-Goals

### Goals

| ID  | Goal                                                                                                      |
| --- | --------------------------------------------------------------------------------------------------------- |
| G1  | An authorized developer can run a baseline security assessment without installing security tools locally. |
| G2  | Identify high-impact web, API, authentication, dependency and database weaknesses.                        |
| G3  | Provide actionable, evidence-backed findings rather than unverified AI-generated claims.                  |
| G4  | Make repeat assessments easy so developers can measure whether changes resolved findings.                 |
| G5  | Provide security testing for AI-powered SaaS applications and agent integrations.                         |
| G6  | Offer a safe, auditable framework for running tools inside disposable cloud environments.                 |

### Non-Goals

ShipSafe will not claim to provide:

- A guarantee that an application is secure.
- A replacement for a comprehensive manual penetration test.
- Unrestricted offensive testing against third-party websites.
- Automatic authorization to assess any submitted domain.
- Compliance certification because a scan passed.
- Automated production exploitation or destructive testing.
- Infrastructure protection, DDoS mitigation or a web application firewall.

Those are separate products or services.

## 4. Target Users

| Tier      | Who                                                                                                                  | Main need                                                                           |
| --------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Primary   | Indie hackers and AI-assisted developers (Cursor, Codex, Claude Code, Replit, Lovable, Bolt, traditional frameworks) | A clear answer to what to fix before launch                                         |
| Secondary | Small SaaS teams with customers but no application security engineer                                                 | Repeatable testing across releases, APIs, dependencies and customer-data boundaries |
| Third     | Development agencies                                                                                                 | Standardized reports, project history and evidence of remediation                   |

## 5. Core Invariants

These apply to every feature and every line of code.

1. **Evidence first.** A confirmed finding MUST be backed by scanner output or a recorded test result. An LLM MUST NOT create a confirmed vulnerability.
2. **No credit for what did not run.** Skipped, failed or inconclusive checks MUST NOT improve a score. A failed tool execution is never a passed test.
3. **Authorization before action.** URL baseline requires an explicit user action that attests they own or are authorized to assess the exact hostname; the backend records that attestation and enforces exact-host network scope. This attestation is not independent ownership proof. Active testing requires separate approval and stronger authorization.
4. **Policy lives in the backend.** Scan profiles, scope and limits are enforced by deterministic backend code, never by an LLM.
5. **Untrusted outputs.** Scanner output and LLM-generated content are untrusted input. They cannot issue commands or override policy.
6. **Tenant isolation.** Every query is scoped to a workspace. Secrets and artifacts are isolated per tenant.
7. **Disposable compute.** Scan VMs are ephemeral, resource-limited, network-restricted and always cleaned up.
8. **Honest reporting.** Always show coverage and limitations next to the score. Never present a score as certification.

## 6. Scope and Phasing

| Phase | Theme                       | Headline deliverables                                                                                                                                                                          |
| ----- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | **ShipSafe Core**           | Auth, projects, domain verification, InstaBox provisioning, passive web scan, TLS checks, GitHub connect, Semgrep/Gitleaks/Trivy, normalization, score + coverage, reports, cleanup, audit log |
| 2     | **Application Security**    | Supabase/Firebase checks, multi-account authorization tests, OpenAPI import, authenticated scanning, controlled active testing, finding history, retest, comparison                            |
| 3     | **AI Application Security** | Promptfoo and garak, LLM endpoint evaluations, agent tool-permission tests, synthetic sensitive-data tests, separate AI score                                                                  |
| 4     | **Developer Workflow**      | PR checks, CLI, CI gates, scheduled scans, notifications, teams, trends, remediation PRs, public API                                                                                           |

Build Phase 1 first with InstaBox, OWASP ZAP, testssl.sh, Semgrep, Gitleaks, Trivy, Next.js and PostgreSQL.

## 7. Product Workflow

### Step 1 — Create a project

The user signs in and enters: project name, website URL, optional GitHub repository, framework (if known), optional API specification, and environment type (production, staging or development). ShipSafe creates a project record.

### Step 2 — Verify ownership

Supported methods: DNS TXT record, hosted verification file, GitHub integration for repository ownership.

- Repository authorization grants repository analysis only. It does not authorize testing deployed domains.
- Verification MUST be current, and the user MUST explicitly authorize the selected targets.

### Step 3 — Configure testing

The user picks a scan profile (see Section 8).

### Step 4 — Provision the environment

A durable Vercel Workflow run (Appendix E) performs these steps. Every step is idempotent and keyed by `scan_id`:

1. Re-validate scope and authorization. Any failure ends the scan as `POLICY_BLOCKED`.
2. Reserve a scan slot against the InstaBox quota.
3. Create a sandbox from the compatible snapshot and wait for the operation to finish.
4. Upload the scan manifest, apply outbound network restrictions and execution limits.
5. Hand the repository to the sandbox with a short-lived read-only token, then discard the token before scanners start.
6. Start the on-VM scan runner and the approved scan jobs.
7. Poll progress, collect results, and always delete the sandbox, including after failure or cancellation.

### Step 5 — Execute tests

Tools run according to the scan manifest. Every run logs: tool and version, execution status, start and end times, targets accessed, checks attempted, results, error conditions and resource usage.

### Step 6 — Process findings

ShipSafe normalizes scanner output, de-duplicates, maps findings to OWASP and CWE references and calculates severity. Deterministic rules and verified scanner evidence determine findings. The LLM explains and groups results only.

### Step 7 — Show results

Overall assessed-security score, assessment coverage, findings by severity, evidence and affected resources, fix recommendations, tests that did not run, suggested next checks, and an exportable report.

### Step 8 — Fix and retest

The user fixes an issue manually or via a suggested patch. ShipSafe reruns the relevant checks, records results and compares against the previous baseline.

Finding states: `open → fixed_pending_verification → resolved`, plus `accepted_risk` and `false_positive`.

## 8. Scan Profiles

| Profile                       | What it does                                                            | Required access                                       | Phase |
| ----------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------- | ----- |
| **Baseline**                  | Non-invasive HTTP, TLS, headers and passive analysis                    | Verified domain                                       | 1     |
| **Code Audit**                | Repository, dependency, secret and configuration analysis               | GitHub repo (read)                                    | 1     |
| **Authenticated Application** | Test accounts, declared roles, test resources, scoped API checks        | Two or more test accounts, role definitions, fixtures | 2     |
| **AI Application**            | Authorized model endpoint, safe fixtures, budgets, expected behavior    | Endpoint, synthetic data, budgets                     | 3     |
| **Advanced Assessment**       | Explicitly approved, rate-limited active testing, preferably on staging | Separate written approval                             | 2     |

Each profile MUST display its capabilities, required access, risks, expected resource usage and unsupported checks.

## 9. Feature Requirements

### F01 — Authentication and Workspaces _(Phase 1)_

Users register, sign in and create workspaces. Support personal and team projects. Roles: **Owner, Admin, Developer, Viewer**. Only authorized roles can start scans, manage credentials or approve active testing.

### F02 — Project Dashboard _(Phase 1)_

Show projects, verification status, scan history, unresolved findings, test coverage and recent changes. Filter by project, severity, date and scanner.

### F03 — Scan Profiles _(Phase 1)_

Offer the five profiles in Section 8, each with capabilities, required access, risks, expected resource usage and unsupported checks.

### F04 — InstaBox Lifecycle Manager _(Phase 1)_

Create, connect, pause, resume, snapshot and delete machines. Support warm snapshots, per-scan identification, worker health checks, cancellation, execution deadlines, idempotent job creation, cleanup after failures, CPU and memory monitoring, and quota-aware scheduling. A scan MUST NOT require a permanently running VM.

### F05 — Web Security Engine _(Phase 1)_

Baseline checks: HTTPS and certificate validation, TLS configuration, HTTP security headers, cookie attributes, CORS, information-disclosure indicators, error-message leakage, exposed source maps and configuration indicators, passive crawling, known browser-security configuration weaknesses. Active checks are separate and require authorization.

### F06 — Source Security Engine _(Phase 1)_

Languages: JavaScript/TypeScript, Python, Java. Scan for hardcoded credentials, dangerous coding patterns, known vulnerable and outdated dependencies, insecure container configuration, unsafe build and CI configuration, and selected framework-specific mistakes. Full source repositories MUST NOT be sent to LLM providers by default.

### F07 — Database Security Engine _(Phase 2)_

First integrations: **Supabase, Firebase**. Checks: RLS or security-rule configuration, excessive privileges, exposed elevated credentials, inappropriate public access, tenant-isolation controls, storage access policies. Prefer configuration review and test fixtures. Do not enumerate production customer records or perform destructive writes.

### F08 — Authentication and Authorization Engine _(Phase 2)_

Support two or more user-controlled test accounts and defined roles. Test: unauthenticated access restrictions, cross-user and cross-tenant isolation, administrative function restrictions, session invalidation, cookie and token configuration, unauthorized response-data exposure. Use disposable accounts and known test records. One successful check MUST NOT be treated as proof that authorization is correct everywhere.

### F09 — API Security Engine _(Phase 2)_

Import OpenAPI specifications. Support declared credentials and safe fixtures. Check: schema validation, unexpected server errors, data exposure, authorization behavior, unsupported HTTP methods, unsafe configuration, endpoint inventory drift, property-level authorization. Potentially destructive operations require explicit fixtures or mocked/staging services.

### F10 — AI Security Engine _(Phase 3)_

Support approved LLM application endpoints. Assess: prompt-injection resistance, sensitive-information disclosure, system-instruction exposure indicators, tool-permission boundaries, unauthorized tool actions, insecure output handling, cost and token-use controls, user-to-user context isolation. Use controlled synthetic data and never require real customer secrets. Results MUST distinguish observed behavior from probabilistic inference.

### F11 — AI Security Analyst _(Phase 1 basic, Phase 3 patches)_

Explain findings in plain language: what happened, why it matters, evidence, affected component, remediation, how to verify the fix, relevant security reference. Explanations MUST cite the underlying finding or code location.

### F12 — Security Scoring _(Phase 1)_

Display three separate metrics: **security score** (severity-weighted, controls actually tested), **test coverage** (share of applicable controls successfully evaluated) and **confidence** (quality and repeatability of evidence). See Section 15.

### F13 — Reports _(Phase 1)_

Export PDF and JSON. Include scope and authorization, date and scanner versions, executive summary, score and coverage, finding severity, reproduction evidence, recommended fixes, exclusions, failed and skipped checks, and comparison with prior assessments. Public reports MUST redact secrets, session tokens, personal data and sensitive exploitation details.

### F14 — GitHub Integration _(Phase 1 connect, Phase 4 PR checks)_

Least-privilege connection with repository selection, commit-specific scans, pull-request checks, finding-to-source mapping, suggested patches and retesting. Patch creation requires user approval.

### F15 — Scan Scheduling _(Phase 4)_

Manual, post-deployment and scheduled scans. Notifications for: new critical finding, previously fixed issue detected again, completed scan, scan failure, verification expiry, major dependency vulnerability relevant to a connected project.

### F16 — CLI and CI Integration _(Phase 4)_

CLI supports login, project selection, scan submission, status, report retrieval and configurable CI security gates. Structured JSON output and clear exit codes.

## 10. Security Rules for ShipSafe Itself

This is a security product, so its own attack surface needs explicit controls.

### Target authorization

- **S-01** Record the user's ownership/authorization attestation on every URL baseline scan.
- **S-02** Enforce exact-host scope and public-address validation in the backend and scanner.
- **S-03** Separate approval for active testing.
- **S-04** Recheck target scope at dispatch; DNS ownership verification is not required for the low-impact URL baseline.
- **S-05** No third-party targets without valid authorization.

### Network isolation

- **S-06** Restrict outbound connections to approved targets and required scanner services.
- **S-07** Block private, loopback, link-local, metadata and other prohibited ranges unless an explicitly isolated customer-owned testing network is supported.
- **S-08** Validate DNS responses, redirects, IPv4 and IPv6 destinations and rebinding attempts.
- **S-09** Scan machines MUST NOT reach the ShipSafe control plane.

### Execution boundaries

- **S-10** Per-job timeouts, request-rate and concurrency limits, resource quotas.
- **S-11** Immediate cancellation.
- **S-12** No default credential stuffing, volumetric DoS, persistence or destructive operations.
- **S-13** Profiles enforced by backend policy, not LLM decisions.

### Credentials and data

- **S-14** Encrypted secrets and short-lived credentials.
- **S-15** No shared vault for untrusted scan jobs.
- **S-16** Redact sensitive scanner output.
- **S-17** Per-tenant storage isolation and configurable retention.
- **S-18** Audit all administrative actions.
- **S-19** Reliably delete temporary test environments.

### Incident controls

- **S-20** Emergency stop for a running scan.
- **S-21** Automatic suspension on policy violations.
- **S-22** Abuse detection and clear reporting procedures.
- **S-23** Review InstaBox's acceptable-use policy before launch. **\[VERIFY\]**

## 11. Technical Architecture

| Layer          | Choice                                                                    | Notes                                                                                                                                                                                                       |
| -------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hosting        | Vercel                                                                    | One Next.js project holds the UI, API and workflows. No separately hosted server                                                                                                                            |
| Frontend       | Next.js (App Router) + TypeScript + Tailwind CSS + shadcn/ui              | Pages: Landing, Sign in, Projects, Project overview, New scan, Live scan, Findings, Finding details, Report comparison, Integrations, Team settings, Billing, Administration                                |
| API            | Next.js route handlers (Node.js runtime)                                  | Authentication, authorization, project records, ownership verification, scan configuration, reporting, notifications. Stateless. Every route validates input with Zod and writes an audit event on mutation |
| Orchestration  | Vercel Workflow (durable, resumable)                                      | One workflow run per scan. MUST NOT depend on a request staying open. Long waits use workflow sleep, not a held connection **\[VERIFY\]**                                                                   |
| Scheduling     | Vercel Cron                                                               | Reconciler, scheduled scans, verification expiry. Cadence depends on plan **\[VERIFY\]**                                                                                                                    |
| Compute        | InstaBox VMs                                                              | All scanning. Prepared snapshots with pinned tools and the `shipsafe-runner`. One VM per scan job where feasible                                                                                            |
| Database       | PostgreSQL, managed (for example Neon via the Vercel Marketplace)         | Users, projects, verification, scan metadata, findings, history, audit events. Drizzle ORM. Pooled or HTTP driver for serverless **\[VERIFY\]**                                                             |
| Object storage | Vercel Blob (private) behind a `Storage` interface                        | Redacted logs, reports, scanner artifacts, evidence. The interface lets R2 or S3 replace it                                                                                                                 |
| Authentication | Auth.js with GitHub sign-in                                               | Repository access uses a separate GitHub App with least privilege                                                                                                                                           |
| AI             | External LLM API (Anthropic) called from route handlers or workflow steps | Explanations, prioritization assistance, optional patch suggestions. Security decisions stay with deterministic policy and evidence checks                                                                  |

**No-backend principle.** ShipSafe runs no always-on server of its own. Request handling is serverless route handlers, long-running orchestration is Vercel Workflow, and all heavy work runs inside InstaBox VMs. Managed Postgres and Blob are services ShipSafe uses, not servers it operates. Do not add a separate API server, worker fleet or message broker without a decision-log entry (Appendix G).

## 12. Core Data Model

| Entity            | Fields                                                                                                                              |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| User              | `id, email, name, created_at`                                                                                                       |
| Workspace         | `id, name, owner_id, created_at`                                                                                                    |
| Membership        | `id, workspace_id, user_id, role`                                                                                                   |
| Project           | `id, workspace_id, name, primary_url, repository_id, framework, environment`                                                        |
| Target            | `id, project_id, hostname, resolved_scope, verification_status, verified_at, expires_at`                                            |
| ScanPolicy        | `id, project_id, profile, allowed_targets, request_limits, permitted_methods, active_testing_approved`                              |
| Scan              | `id, project_id, policy_id, status, requested_by, sandbox_id, started_at, completed_at, score, coverage`                            |
| ScanJob           | `id, scan_id, tool, tool_version, status, duration, exit_code, artifact_reference`                                                  |
| Finding           | `id, project_id, fingerprint, category, severity, confidence, status, title, description, remediation, first_seen_at, last_seen_at` |
| FindingOccurrence | `id, finding_id, scan_id, evidence_reference, affected_resource`                                                                    |
| Integration       | `id, project_id, provider, permissions, secret_reference, connection_status`                                                        |
| AuditEvent        | `id, workspace_id, actor_id, action, resource_id, timestamp`                                                                        |

All queries MUST enforce workspace tenancy. Appendix C adds the scan manifest and normalized finding contracts.

## 13. API Routes

| Method | Route                            | Purpose                                                                          |
| ------ | -------------------------------- | -------------------------------------------------------------------------------- |
| POST   | `/api/projects`                  | Create project                                                                   |
| POST   | `/api/projects/:id/verify`       | Start ownership verification                                                     |
| GET    | `/api/projects/:id/verification` | Check verification state                                                         |
| POST   | `/api/projects/:id/policies`     | Save scan policy                                                                 |
| POST   | `/api/projects/:id/scans`        | Submit scan                                                                      |
| GET    | `/api/projects/:id/scans`        | List scans                                                                       |
| GET    | `/api/scans/:id`                 | Scan status                                                                      |
| POST   | `/api/scans/:id/cancel`          | Cancel active scan                                                               |
| GET    | `/api/scans/:id/events`          | Scan event stream (reads `ScanEvent` rows from Postgres)                         |
| GET    | `/api/scans/:id/findings`        | Retrieve findings                                                                |
| POST   | `/api/findings/:id/status`       | Change a finding's state                                                         |
| GET    | `/api/projects/:id/findings`     | Consolidated findings                                                            |
| GET    | `/api/scans/:id/report`          | Export report                                                                    |
| GET    | `/api/projects/:id/comparison`   | Compare assessments                                                              |
| POST   | `/api/integrations/github`       | Connect repository                                                               |
| POST   | `/api/github/webhook`            | GitHub App webhook. Signature verified                                           |
| GET    | `/api/cron/reconcile`            | Vercel Cron. Delete orphaned sandboxes, fail stuck scans. Requires `CRON_SECRET` |
| GET    | `/api/cron/schedules`            | Vercel Cron. Start scheduled scans                                               |
| GET    | `/api/cron/expiry`               | Vercel Cron. Verification expiry and notifications                               |

Every mutation requires authenticated authorization, request validation and an audit event.

## 14. Scan State Machine

`DRAFT → VERIFYING → AUTHORIZED → QUEUED → PROVISIONING → RUNNING → PROCESSING → COMPLETED`

Other terminal states: `FAILED`, `CANCELLED`, `TIMED_OUT`, `POLICY_BLOCKED`.

- Partial results MUST remain available even when the overall job fails.
- Worker retries MUST be idempotent and MUST NOT repeat active testing unintentionally.
- A queue lease and recovery process MUST handle workers that disappear mid-execution.
- Cancellation MUST work in `QUEUED`, `PROVISIONING` and `RUNNING`, and trigger cleanup.

**Workflow mapping.** Each state transition is written by exactly one workflow step, is idempotent, and is recorded as a `ScanEvent`. The UI reads scan state from Postgres only and never talks to InstaBox directly.

## 15. Security Scoring Specification

### Category weights (product defaults to validate, not empirical breach probabilities)

| Category                          | Weight |
| --------------------------------- | -----: |
| Authentication and authorization  |    25% |
| API security                      |    20% |
| Source code and dependencies      |    20% |
| Database and storage security     |    15% |
| Web configuration and transport   |    10% |
| Logging, integrity and resilience |    10% |

AI security is a separate additional score for applications with AI functionality. Ordinary applications MUST NOT be penalized for lacking AI endpoints.

### Control outcomes

| Outcome        | Meaning                                     |
| -------------- | ------------------------------------------- |
| Pass           | No weakness observed under the defined test |
| Fail           | Supported weakness found                    |
| Inconclusive   | Insufficient evidence                       |
| Not tested     | Execution unavailable                       |
| Not applicable | Control does not apply                      |

### Rules

- Compute the score only from successfully assessed, applicable controls, with penalties based on confirmed severity.
- Show coverage independently.
- A confirmed critical vulnerability MUST visibly override a reassuring aggregate score.
- Scores are versioned (`scoring_version`) so rule or weight changes do not produce misleading historical comparisons.
- Never present the score as certification or assurance.

### Proposed starting formula (v0.1, tunable)

- Per-finding penalty: Critical 40, High 20, Medium 8, Low 2.
- Category score = `max(0, 100 − sum of penalties)` for categories with at least one assessed control.
- Overall = weighted average over assessed categories, renormalizing weights to those categories.
- If any confirmed Critical is open, display the overall score capped at 40 with a visible override banner.
- Coverage = assessed applicable controls ÷ applicable controls.

## 16. Reliability and Quality

### Detection quality

Maintain a benchmark suite of applications with known vulnerabilities and secure controls. Track true and false positives, false negatives, precision, recall, coverage and inconclusive-test rate. Do not claim a general detection percentage until evaluated against a defined dataset.

### Platform objectives (proposed targets, not measured performance)

- At least 99% of completed jobs clean up runtime resources automatically, with reconciliation for failures.
- At least 99% successful result persistence after a scanner finishes.
- No cross-tenant access in security regression tests.
- All active scan requests tied to authorization evidence.
- Cancellation works while queued, provisioning and running.

### Repeatability

Store tool versions, scan policy, environment metadata and test fixtures so findings can be reproduced. Prioritize consistent results over the largest number of checks.

## 17. User Experience

**Landing page.** Headline: _Ship fast. Know what's exposed._ Subheading: _Security testing for SaaS developers. Scan your app, understand the risks, and verify your fixes._ Primary CTA: **Scan your app**. Secondary CTA: **See a sample report**.

**Dashboard.** Should feel like a developer tool, not a generic cybersecurity console. Lead with security score, coverage, latest scan, unresolved findings and recent changes.

**Live scan.** Show current stage, active tools, successful and failed checks, findings as they arrive, elapsed time, cancel action and execution log. Never claim a control passed until its test completes.

**Finding page.** In order: (1) what is wrong, (2) where, (3) what impact the evidence supports, (4) what code or configuration should change, (5) how to verify the fix.

## 18. Release Plan and Exit Conditions

| Phase                  | Exit condition                                                                                                                            |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| 1 Core                 | An authorized user can submit a website and optional repository, run a repeatable scan and obtain a report with evidence-backed findings. |
| 2 Application Security | ShipSafe detects and verifies known authorization and database-misconfiguration cases in controlled benchmark apps.                       |
| 3 AI Security          | ShipSafe evaluates a documented set of AI security controls with repeatable fixtures and known limitations.                               |
| 4 Workflow             | Small teams can use ShipSafe as a repeatable release-security workflow.                                                                   |

## 19. Success Metrics

- **Activation:** registrations that verify a project; verified projects completing a first scan; time from project creation to first useful report.
- **Product value:** reports with actionable findings; findings users validate or fix; users who retest; median time from discovery to verified resolution.
- **Quality:** false-positive rate on validated findings; benchmark precision and recall by vulnerability class; scan completion rate; unplanned interruptions; cleanup failure rate.
- **Business:** weekly active projects; returning developers; connected repositories per workspace; repeat scan frequency; free-to-paid conversion once pricing exists.

## 20. Acceptance Criteria

Ready for initial external testing when:

| ID    | Criterion                                                                        |
| ----- | -------------------------------------------------------------------------------- |
| AC-01 | A user can create and verify a project.                                          |
| AC-02 | Unverified targets cannot receive active scans.                                  |
| AC-03 | Invalid and out-of-scope targets are rejected.                                   |
| AC-04 | The backend can create and clean up an InstaBox machine.                         |
| AC-05 | Passive scanning produces normalized findings.                                   |
| AC-06 | Source scanning identifies seeded test vulnerabilities and exposed test secrets. |
| AC-07 | A report contains tool evidence, severity and remediation.                       |
| AC-08 | Failed or skipped tests cannot improve a security score.                         |
| AC-09 | Cancellation stops work and triggers cleanup.                                    |
| AC-10 | One workspace cannot access another's scans or credentials.                      |
| AC-11 | Scanner output cannot issue commands or override scan policy.                    |
| AC-12 | Known benchmark vulnerabilities are detected with documented results.            |
| AC-13 | A repeat scan shows whether a previously reported issue remains.                 |
| AC-14 | The application displays testing limitations and coverage clearly.               |

## 21. Risks, Dependencies and Open Questions

| ID  | Risk                                 | Mitigation                                                                                                                                                                                                                  |
| --- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1  | InstaBox acceptable-use restrictions | Confirm hosted scanning of explicitly authorized targets is permitted **\[VERIFY\]**                                                                                                                                        |
| R2  | Network isolation                    | Test InstaBox egress controls; add a restrictive gateway or in-VM firewall if missing **\[VERIFY\]**                                                                                                                        |
| R3  | False positives                      | Never treat scanner alerts or AI interpretation as confirmed without evidence                                                                                                                                               |
| R4  | Source-code confidentiality          | Scan inside the sandbox; give AI only selected, redacted evidence                                                                                                                                                           |
| R5  | Shared SaaS capacity                 | Free InstaBox account has limited concurrent machines; scheduler must be quota-aware **\[VERIFY\]**                                                                                                                         |
| R6  | Cost                                 | Measure VM time, storage, network, tool execution and LLM use before offering unrestricted scans                                                                                                                            |
| R7  | Scope abuse                          | Domain verification does not grant permission to test third-party infrastructure behind a site; require explicit authorization and enforce technical boundaries                                                             |
| R8  | Vulnerability disclosure             | Private reports, retention limits, disclosure contact, incident-response procedures                                                                                                                                         |
| R9  | Vercel limits                        | Function duration is capped (300 s default, higher on paid plans) and Hobby cron runs at most daily. Keep every workflow step short, use workflow sleep for waits, and do not rely on cron for scan progress **\[VERIFY\]** |
| R10 | Workflow maturity                    | Vercel Workflow and Queues are new. Pin the SDK version and keep step logic in pure functions in `packages/orchestration` so another engine could run it                                                                    |
| R11 | SSRF from ShipSafe's own functions   | Ownership verification, report fetches and webhooks make outbound requests from Vercel. All of them MUST use `packages/safe-fetch` (S-07, S-08)                                                                             |
| R12 | Serverless database connections      | Use a pooled or HTTP Postgres driver and short transactions                                                                                                                                                                 |

## 22. Final Product Definition

ShipSafe is not a one-click hacking platform. It is an application security assessment and remediation platform for developers who want to ship quickly without ignoring security.

The foundation is an isolated testing environment, a curated set of security tools, reliable finding evidence and a clear path from detection to verified remediation.

**Build ShipSafe Core first using InstaBox, OWASP ZAP, testssl.sh, Semgrep, Gitleaks, Trivy, Next.js and PostgreSQL. Then add authenticated authorization checks, database analysis, API testing and AI security evaluations.**

## Appendix A — InstaBox Integration Notes

### A.1 Research status (read first)

The InstaBox docs index (`instabox.sh/docs`, published by InsForge AI, Inc.) was reviewed. It gives the page structure and one-line summaries only; the individual pages (Limits, API reference, SDK reference) render client-side and could not be retrieved. Rows marked _Docs index_ come from that index. Rows marked _Third-party_ come from the open-source `v01dstar/herdr-instabox` plugin and a public benchmark. Anything not stated on the index, such as endpoint paths, limits and machine sizes, stays **\[VERIFY\]**: read the matching page before hard-coding it.

### A.2 Observed facts

| Topic              | Observation                                                                                                                                                    | Source             |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| SDK and API        | TypeScript SDK `@insforge/instabox-sdk`, an HTTP API, and a CLI that accepts an API key                                                                        | Docs index         |
| Authentication     | API keys for code, scripts and the CLI. The Account API reports who a key belongs to                                                                           | Docs index         |
| API conventions    | Shared across endpoints: authentication, operations, idempotency, errors. Changes to a machine are tracked as operations until done (asynchronous)             | Docs index         |
| Machines           | Create, list, change, delete. Lifecycle: start, stop, pause, resume. Guides cover timeouts, labels and secrets                                                 | Docs index         |
| Commands and files | Run a command in a machine and read its files. Upload support is not stated                                                                                    | Docs index         |
| Snapshots          | Save a machine, then start new machines from it                                                                                                                | Docs index         |
| Templates          | Listed through the Account API                                                                                                                                 | Docs index         |
| Access             | SSH with `ssh` or `mosh`; HTTPS URLs for public ports; desktop view and control                                                                                | Docs index         |
| Usage and limits   | A Limits page lists account defaults. `GET /v1/usage` and the Account page show your own                                                                       | Docs index         |
| API base URL       | `https://api.box.instacloud.com`, overridable with `INSTABOX_SERVER`                                                                                           | Third-party plugin |
| Sign-in            | GitHub or Google for interactive use                                                                                                                           | Third-party plugin |
| SSH certificates   | The API issues 24-hour certificates. The gateway checks one only when a connection opens, so an open session outlives it                                       | Third-party plugin |
| Machine states     | Running, stopped, suspended, starting; machines may auto-suspend                                                                                               | Third-party plugin |
| Sample machine     | KVM guest, Debian 13, kernel `6.18.54-instabox`, 4 vCPU AMD EPYC, \~8 GiB RAM, \~37 GB disk, IPv4 and IPv6, AWS Oregon. One instance; sizes may differ by plan | Public benchmark   |

### A.3 Questions the official docs must answer

Resolve these in the M0 spike (Appendix D) before building on assumptions.

1. **Limits.** Concurrent machines, vCPU, RAM and disk per machine, API rate limits, and what the free tier allows (Limits page and `GET /v1/usage`).
2. **Writing files.** The Commands and files page covers reading files. Confirm whether uploads are supported, or whether input goes through command stdin or `scp`.
3. **Egress control.** Any per-machine firewall or egress allowlist, and whether a metadata endpoint exists to block (risk R2).
4. **Snapshots.** How snapshots are built, restore time, size limits, and whether one snapshot can start many concurrent machines.
5. **Start times.** Time from create to command-ready, and from resume to ready.
6. **Timeouts and billing.** Auto-suspend and timeout semantics, and what is billed while paused or stopped.
7. **Operations and idempotency.** How operations are polled, their error codes, the idempotency-key mechanism and its retention window, and whether webhooks exist.
8. **Labels and secrets.** Whether `list` can filter by label, label limits, how secrets are injected, and whether scanner code inside the guest can read them.
9. **Docker.** Whether Docker runs in the guest (needed for the ZAP image).
10. **Public ports.** Confirm ports are closed by default, so scan machines expose nothing.
11. **Acceptable use.** Whether scanning explicitly authorized targets is permitted, and whether a written exception is needed (risk R1).

### A.4 Recommended integration design

These are design decisions, not InstaBox facts.

**Isolate the vendor behind an interface.** All InstaBox calls go through one provider module so API details live in one place and tests use a fake.

```ts
interface SandboxProvider {
  create(opts: {
    snapshotId: string;
    labels: Record<string, string>;
  }): Promise<SandboxRef>;
  start(ref: SandboxRef): Promise<void>;
  get(ref: SandboxRef): Promise<SandboxStatus>;
  exec(
    ref: SandboxRef,
    cmd: string[],
    o: { timeoutMs: number; env?: Record<string, string>; stdin?: string },
  ): Promise<ExecResult>;
  putFile(ref: SandboxRef, path: string, data: Buffer): Promise<void>;
  getFile(ref: SandboxRef, path: string): Promise<Buffer>;
  suspend(ref: SandboxRef): Promise<void>;
  stop(ref: SandboxRef): Promise<void>;
  delete(ref: SandboxRef): Promise<void>;
  list(labels: Record<string, string>): Promise<SandboxRef[]>;
}
```

Ship two implementations: `InstaboxProvider` and `FakeProvider` (in-memory, for unit and integration tests).

**Use operations and idempotency.** Per the docs index, machine changes are operations you follow until done, and the API has an idempotency mechanism. `InstaboxProvider` MUST wait for each operation to finish before the next step, and MUST send an idempotency key derived from `scan_id` and the step (for example `scn_123:create`) so a retry never creates a second machine. Prefer the `@insforge/instabox-sdk` package over hand-written HTTP once its reference page is read. Leave public ports and the desktop feature unused.

**Pull, driven by the workflow.** The Vercel workflow drives each VM through the InstaBox API: it uploads the manifest, starts the on-VM runner, polls a status file, and downloads results. The VM never calls ShipSafe, holds no ShipSafe credentials and has no route to the control plane (S-09). The runner writes a SHA-256 checksum file next to its results, and the workflow verifies it before ingesting anything.

**One VM per scan, labeled.** Tag every machine with `scan_id`, `workspace_id` and an expiry time. A **reconciler** job lists machines by label and deletes any whose scan is terminal or whose expiry has passed (supports the 99% cleanup objective).

**Egress enforcement.** If InstaBox has no per-machine egress controls, enforce a default-deny firewall (for example `nftables`) inside the guest, applied by root at boot from the manifest:

- Allow: the resolved IPs of authorized targets, DNS to a pinned resolver, and any tool-infrastructure hosts that cannot be pre-bundled.
- Deny: RFC 1918, loopback, link-local (`169.254.0.0/16`, `fe80::/10`), cloud metadata addresses, and the ShipSafe control plane.
- Resolve DNS in the orchestrator, pass concrete IPs to the VM, and re-validate after redirects to defeat rebinding (S-08).
- Run scanners as an unprivileged user (ideally in a container) so a compromised tool cannot edit the firewall. Treat the in-guest firewall as defense in depth, and prefer a provider-level or gateway-level control if one exists.

**Bundle dependencies in the snapshot.** Pre-install tools, the Trivy vulnerability database, Semgrep rule packs and ZAP add-ons so scans need no outbound access beyond the target. Rebuild the snapshot on a schedule (for example nightly) and on tool-version bumps. Record the snapshot ID in every `ScanJob` for reproducibility.

**Quota-aware scheduler.** Keep a counter of active machines against the account limit. Queue jobs when at capacity, prefer warm or resumable machines, and surface queue position in the live-scan view.

**Failure handling.** Treat create, exec and delete as retryable with idempotency keys derived from `scan_id` and `tool`. A retry MUST NOT repeat active testing: persist a per-job `started` marker before running and check it on retry.

## Appendix B — Tool Runbook (Phase 1)

Pin exact versions in the snapshot build and record them in each `ScanJob`. Confirm flags against the pinned version; CLIs change.

| Tool                 | Profile    | Example invocation                                                                                   | Output | Exit-code caution                                                                                                       |
| -------------------- | ---------- | ---------------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------- |
| OWASP ZAP (baseline) | Baseline   | `zap-baseline.py -t <url> -J zap.json -m 5`                                                          | JSON   | Returns non-zero for warnings and failures. Map 0/1/2 to completed, and 3 to tool error                                 |
| testssl.sh           | Baseline   | `testssl.sh --jsonfile-pretty tls.json --warnings batch <host:port>`                                 | JSON   | Exit code is not a reliable pass/fail signal. Parse the JSON                                                            |
| Semgrep              | Code Audit | `semgrep scan --config <pinned-rules-dir> --metrics=off --json --output semgrep.json .`              | JSON   | Exits 0 even with findings unless `--error` is set. Avoid `--config auto` (needs registry access and metrics)           |
| Gitleaks             | Code Audit | `gitleaks detect --source . --report-format json --report-path gitleaks.json --redact --exit-code 0` | JSON   | Exits 1 when leaks are found by default. Set `--exit-code 0` and read the report. Newer releases may rename subcommands |
| Trivy                | Code Audit | `trivy fs --scanners vuln,secret,misconfig --format json --output trivy.json --skip-db-update .`     | JSON   | Exits 0 by default. Needs a preloaded DB when `--skip-db-update` is used                                                |

**Adapter rules**

- Each tool has an adapter that (1) builds the command from the manifest, (2) runs it with a deadline, (3) parses output into `NormalizedFinding[]`, and (4) returns a `ToolResult` with an explicit status.
- Distinguish `completed`, `tool_error`, `timed_out` and `skipped`. Only `completed` with a parsed report counts as an assessed control.
- Missing or unparseable output is `tool_error`, never a pass.
- Redact secrets in scanner output before storage (Gitleaks `--redact`, plus a post-parse scrubber for tokens, cookies and `Authorization` headers).
- Never execute or interpolate scanner text. Escape it when rendering and when passing it to an LLM.
- ZAP baseline spiders and passively scans. Do not enable active scan rules in the Baseline profile.
- Phase 3 additions: Promptfoo and garak run against an authorized endpoint with synthetic fixtures and a token budget.

## Appendix C — Data Contracts

### C.1 Scan manifest (orchestrator to VM)

```json
{
  "manifest_version": 1,
  "scan_id": "scn_123",
  "profile": "baseline",
  "deadline_seconds": 1800,
  "targets": [
    { "hostname": "app.example.com", "ips": ["203.0.113.10"], "ports": [443] }
  ],
  "limits": { "max_rps": 5, "max_concurrency": 2 },
  "permitted_methods": ["GET", "HEAD", "OPTIONS"],
  "active_testing_approved": false,
  "jobs": [
    { "tool": "zap-baseline", "timeout_seconds": 600 },
    { "tool": "testssl", "timeout_seconds": 300 }
  ],
  "authorization_ref": "auth_456"
}
```

The manifest is generated by the backend from the saved `ScanPolicy` and is the only source of scope inside the VM.

### C.2 ToolResult

| Field                                 | Notes                                                   |
| ------------------------------------- | ------------------------------------------------------- |
| `tool`, `tool_version`                | Exact pinned version                                    |
| `status`                              | `completed` \| `tool_error` \| `timed_out` \| `skipped` |
| `exit_code`, `started_at`, `ended_at` | Raw execution metadata                                  |
| `targets_accessed`                    | Hosts actually contacted                                |
| `checks_attempted`                    | Rule or control identifiers                             |
| `artifact_reference`                  | Redacted raw output in object storage                   |
| `error`                               | Present for `tool_error` and `timed_out`                |

### C.3 NormalizedFinding

| Field                                 | Notes                                                                                                                            |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `fingerprint`                         | Stable hash of `category + rule_id + normalized_affected_resource + target`. Must survive re-scans so retest and comparison work |
| `category`                            | One of the scoring categories                                                                                                    |
| `rule_id`, `source_tool`              | Original identifiers                                                                                                             |
| `severity`                            | `critical` \| `high` \| `medium` \| `low` \| `info`                                                                              |
| `confidence`                          | `confirmed` \| `likely` \| `unverified`. Only `confirmed` findings affect the score                                              |
| `title`, `description`, `remediation` | Deterministic text first. LLM text is added separately and labeled                                                               |
| `affected_resource`                   | URL, header, file path and line, or package and version                                                                          |
| `evidence_reference`                  | Pointer to redacted evidence                                                                                                     |
| `references`                          | OWASP and CWE identifiers                                                                                                        |
| `status`                              | `open` \| `fixed_pending_verification` \| `resolved` \| `accepted_risk` \| `false_positive`                                      |

### C.4 ControlResult

`control_id`, `category`, `outcome` (`pass` | `fail` | `inconclusive` | `not_tested` | `not_applicable`), `evidence_reference`, `scan_job_id`, `scoring_version`. A control is `pass` only when the owning tool completed and the check ran with no weakness observed.

## Appendix D — Suggested Repository Layout and Build Order

### D.1 Monorepo layout

```
apps/web               Next.js app: UI, route handlers, workflow entrypoints
workflows/             Vercel Workflow definitions (scan, retest, reconcile)
packages/db            Drizzle schema, migrations, workspace-scoped query layer
packages/policy       Scope, authorization, profile enforcement (pure)
packages/orchestration Step logic used by workflows (engine-agnostic)
packages/scoring       Versioned scoring and coverage (pure)
packages/adapters      Tool parsers and normalizers (pure, no I/O)
packages/sandbox       SandboxProvider, InstaboxProvider, FakeProvider
packages/safe-fetch    SSRF-safe HTTP and DNS helpers
packages/storage       Storage interface, Blob implementation, fake
packages/analyst       LLM explanation layer
packages/shared        Zod schemas and types: manifest, finding, events, API
runner/                shipsafe-runner: runs on the VM, executes the manifest
infra/snapshot         Scripts that build InstaBox snapshots
benchmarks/            Known-vulnerable and secure fixture apps
tests/                 Cross-workstream integration and security regression tests
docs/contracts/        Contract change log
```

### D.2 Build order for Phase 1

| Wave | Deliverable                                                                                                                                                                                                                                                              | Proves                                            |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| M0   | **InstaBox spike** (runs beside W0): create from snapshot, run a command, read a file, delete. Measure start time. Test egress to a private IP and a metadata address. Read the Limits, Commands and files, Snapshots and Operations pages and the acceptable-use policy | Answers to Appendix A.3. Go or no-go on R1 and R2 |
| W0   | **Contracts and scaffold**: shared schemas, DB schema, `SandboxProvider` + `FakeProvider`, `Storage` + fake, env validation, CI, Vercel project                                                                                                                          | Parallel work can start without collisions        |
| W1   | **Parallel workstreams** WS-1 to WS-10 (Appendix F), each against fakes and fixtures                                                                                                                                                                                     | Most of AC-01 to AC-14 in isolation               |
| W2   | **Integration**: real InstaBox provider, built snapshots, end-to-end baseline and code scan on Vercel                                                                                                                                                                    | AC-04, AC-05, AC-06, AC-07                        |
| W3   | **Hardening**: benchmark run, tenancy and SSRF regression, cleanup and cancellation drills                                                                                                                                                                               | AC-09 to AC-13                                    |

Write the acceptance-criteria tests alongside each milestone rather than at the end.

## Appendix E — Runtime Architecture on Vercel and InstaBox

This appendix is the source of truth for how the pieces run. Vercel product behavior marked **\[VERIFY\]** was taken from current Vercel docs and articles and must be re-checked against the pinned versions.

### E.1 Who does what

| Component       | Responsibility                                                                                            | Never does                                 |
| --------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Browser         | UI, polls `/api/scans/:id/events`                                                                         | Talks to InstaBox or tools                 |
| Route handlers  | Auth, validation, authorization, audit, reads and writes to Postgres, starting workflows, serving reports | Run scans, hold a request open for a scan  |
| Vercel Workflow | One durable run per scan. Creates the sandbox, drives the runner, collects results, tears down            | Store secrets in workflow state            |
| Vercel Cron     | Reconciler, scheduled scans, verification expiry                                                          | Drive scan progress                        |
| Postgres        | Source of truth for all state                                                                             | Hold raw scanner artifacts                 |
| Blob storage    | Redacted logs, evidence, reports                                                                          | Hold unredacted output                     |
| InstaBox VM     | Runs the on-VM `shipsafe-runner` and all tools                                                            | Call ShipSafe, hold ShipSafe credentials   |
| GitHub App      | Repository read access, webhooks, later PR checks                                                         | Authorize deployed-domain testing          |
| LLM API         | Explains findings from redacted evidence                                                                  | Create confirmed findings or change policy |

### E.2 Scan workflow

The workflow lives in `workflows/scan.ts`. Directive names and the sleep API follow the Vercel Workflow SDK **\[VERIFY\]**.

```ts
export async function scanWorkflow(scanId: string) {
  "use workflow";
  const plan = await authorizeAndPlan(scanId); // step: re-verify targets, build manifest
  if (!plan.ok) return finish(scanId, "POLICY_BLOCKED", plan.reason);
  const slot = await reserveSlot(scanId); // step: quota-aware, retries with backoff
  let box;
  try {
    box = await createSandbox(scanId, plan.snapshotId); // step: idempotency key scanId:create
    await prepareSandbox(scanId, box, plan.manifest); // step: upload manifest, firewall, repo handoff
    await startRunner(scanId, box); // step: writes 'started' marker first
    for (;;) {
      await sleep("5s");
      const p = await pollRunner(scanId, box); // step: reads status.json, writes ScanEvents
      if (p.cancelRequested) {
        await stopRunner(scanId, box);
        break;
      }
      if (p.done || p.deadlineExceeded) break;
    }
    const results = await collectResults(scanId, box); // step: read files, verify checksums, redact, store
    await processFindings(scanId, results); // step: normalize, dedupe, score
    await finish(scanId, "COMPLETED");
  } catch (err) {
    await finish(scanId, classifyFailure(err));
  } finally {
    if (box) await teardown(scanId, box); // step: delete and confirm gone
    await releaseSlot(slot);
  }
}
```

**Step rules (MUST)**

- Every step is idempotent and takes an idempotency key of the form `<scan_id>:<step>`.
- Every step finishes well inside the function duration limit (target under 60 seconds). Waiting uses workflow sleep, never a held connection.
- Every step writes a `ScanEvent`.
- Workflow state is persisted. Steps MUST NOT return or log secrets, tokens, test-account credentials or unredacted scanner output. Steps fetch secrets themselves and use them in place.
- `startRunner` MUST write a `started` marker (a `ScanJob` row plus a file in the VM) before launching, and check it first on retry, so a replayed step never repeats active testing.
- Cancellation sets `cancel_requested_at` on the scan row. `pollRunner` reads it, `stopRunner` places a `CANCEL` file for the runner, and the flow goes to teardown.
- Teardown MUST also be guaranteed outside the workflow: the cron reconciler deletes any sandbox whose scan is terminal or whose `expires_at` has passed.

### E.3 On-VM runner contract

`runner/` builds `shipsafe-runner`, a small TypeScript program shipped in the snapshot (Node LTS) that shares Zod schemas with `packages/shared`.

```
/opt/shipsafe/            root-owned, read-only to scanners: runner, tools, rule packs, vulnerability DB
/work/in/manifest.json    written by the workflow
/work/in/CANCEL           optional; its presence requests cancellation
/work/repo/               repository checkout (Code Audit)
/work/out/status.json     heartbeat, rewritten atomically (write temp, rename)
/work/out/raw/<tool>.json redacted raw tool output
/work/out/result.json     ToolResult[] (Appendix C.2)
/work/out/CHECKSUMS.sha256
/work/out/DONE or FAILED  marker, written last
```

Command: `shipsafe-runner run --manifest /work/in/manifest.json --out /work/out`.

The runner MUST:

- Validate the manifest against the schema and refuse to start on any mismatch.
- Apply the egress firewall from the manifest (default deny, target IPs only) as root before any scanner starts, then drop to an unprivileged `scanner` user.
- Run each job with its own timeout and a global deadline, record per-job status, and never convert a tool error into a pass.
- Write `status.json` at least every 5 seconds with `state`, `current_job`, per-job status and elapsed time.
- Stop within 10 seconds of seeing `CANCEL`.
- Redact tokens, cookies and `Authorization` headers before writing output.
- Never make network requests other than to manifest targets. Never upload anything.

Repository handoff (Code Audit): a workflow step mints a short-lived, read-only GitHub App installation token and runs the clone as a root-controlled command, then removes credentials from the environment and git config before scanners start. Scanners never see the token.

### E.4 Additional entities

These extend the data model in Section 12. All carry `workspace_id` (directly or through their parent) and follow the tenancy rule.

| Entity                | Fields                                                                                                    |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| ScanEvent             | `id, scan_id, seq, ts, type, stage, message, data` (monotonic `seq` per scan; the UI reads `after=<seq>`) |
| SandboxRecord         | `id, scan_id, instabox_id, snapshot_id, status, created_at, expires_at, deleted_at`                       |
| VerificationChallenge | `id, target_id, method, token_hash, expires_at, verified_at`                                              |
| FindingStatusChange   | `id, finding_id, from_status, to_status, actor_id, reason, ts`                                            |
| Report                | `id, scan_id, format, storage_key, created_at, scoring_version`                                           |
| Notification          | `id, workspace_id, type, payload, created_at, read_at`                                                    |
| EncryptedSecret       | `id, workspace_id, kind, ciphertext, key_version, created_at` (test-account credentials, tokens)          |

Scan rows also carry `workflow_run_id`, `scoring_version`, `cancel_requested_at` and `snapshot_id`.

### E.5 Environment variables

Validate all of them at startup with one Zod schema in `packages/shared/env.ts`. Missing required variables fail the build or boot, never a request.

| Variable                                                               | Purpose                                                                |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `APP_URL`                                                              | Public base URL                                                        |
| `DATABASE_URL`                                                         | Postgres connection string (pooled or HTTP driver)                     |
| `AUTH_SECRET`, `AUTH_GITHUB_ID`, `AUTH_GITHUB_SECRET`                  | Auth.js and GitHub sign-in                                             |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_WEBHOOK_SECRET` | GitHub App                                                             |
| `INSTABOX_API_KEY`                                                     | InstaBox API key for the environment                                   |
| `INSTABOX_API_URL`                                                     | Optional base URL override **\[VERIFY\]**                              |
| `INSTABOX_SNAPSHOT_BASELINE`, `INSTABOX_SNAPSHOT_CODE`                 | Snapshot IDs per worker profile                                        |
| `BLOB_READ_WRITE_TOKEN`                                                | Blob storage                                                           |
| `SECRETS_KEK`                                                          | Key-encryption key for `EncryptedSecret` (AES-256-GCM envelope)        |
| `ANTHROPIC_API_KEY`                                                    | AI analyst                                                             |
| `CRON_SECRET`                                                          | Bearer token required by `/api/cron/*`                                 |
| `SCAN_MAX_CONCURRENCY`                                                 | Upper bound on simultaneous sandboxes (defaults to the InstaBox limit) |
| `SANDBOX_PROVIDER`                                                     | `instabox` or `fake`. Preview deployments MUST use `fake`              |

### E.6 Vercel project configuration

- One project, monorepo with `apps/web` as the root. Node.js runtime for all route handlers and workflows; no Edge runtime for code that touches Postgres, secrets or InstaBox.
- `vercel.json` registers the three cron routes. Plan limits decide cadence: Hobby allows daily cron only, Pro allows per-minute **\[VERIFY\]**. Scan progress MUST NOT depend on cron.
- Set `maxDuration` explicitly on every route that calls InstaBox or an LLM. Default function duration is 300 seconds on all plans and can go higher on paid plans **\[VERIFY\]**.
- Choose the function region closest to InstaBox's region and the database **\[VERIFY\]**.
- Production uses the real provider and production keys. Preview and development use `SANDBOX_PROVIDER=fake`, separate database branches and no real targets.
- Response headers: strict CSP, `frame-ancestors 'none'`, `Referrer-Policy`, `X-Content-Type-Options`, HSTS.

### E.7 Security of the Vercel side

- **Tenancy.** Route handlers and workflow steps query tenant tables only through `withWorkspace(workspaceId)`. Add Postgres row-level security keyed on a session setting as defense in depth. A lint rule or test MUST fail on direct table access outside `packages/db`.
- **SSRF.** Ownership verification, hosted-file checks, report links and webhooks go through `packages/safe-fetch`: resolve DNS, block private, loopback, link-local and metadata ranges for IPv4 and IPv6, pin the connection to the validated IP, cap redirects, size and time.
- **Secrets.** Test-account credentials and tokens are encrypted with an envelope scheme before storage, decrypted only inside the step that uses them, and never written to logs, events or workflow state.
- **Untrusted text.** Scanner output and LLM output are escaped on render and passed to the LLM only as data inside clearly delimited blocks.
- **Abuse controls.** Per-user and per-workspace rate limits on scan creation, verification attempts and report generation (Vercel Firewall rules or database-backed counters **\[VERIFY\]**).
- **Webhooks and cron.** Verify the GitHub signature; require `CRON_SECRET` on cron routes.
- **Audit.** Every mutation writes an `AuditEvent` in the same transaction.

### E.8 Live scan data flow

The workflow writes `ScanEvent` rows. The Live scan page polls `GET /api/scans/:id/events?after=<seq>` every 2 to 3 seconds (SSE is an optional upgrade). The page shows stage, tool statuses, findings as they are stored, elapsed time and a cancel button. It never claims a control passed until the corresponding `ControlResult` exists.

## Appendix F — Parallel Build Plan

This appendix lets many agents build at once without colliding.

### F.1 Rules for every agent

1. **Own your paths.** Edit only the paths listed for your workstream. Reading anything is fine.
2. **Contracts are frozen after Wave 0.** `packages/shared` and the interface files in F.4 change only through the contract-change protocol below.
3. **Contract-change protocol.** Add an entry to `docs/contracts/CHANGES.md` (what, why, affected workstreams), make the change in a branch named `contract/<topic>`, and wait for the Wave 0 owner or the human to merge it. Do not patch shared types locally.
4. **Build against fakes.** Use `FakeProvider`, the fake `Storage`, fixture tool outputs in `benchmarks/fixtures/` and the typed mock API in `packages/shared/mocks`. Do not wait for another workstream.
5. **Never guess InstaBox or Vercel behavior.** If a detail is marked **\[VERIFY\]**, code to the interface, leave `TODO(VERIFY): <question>` and list it in your handoff note.
6. **Respect the invariants** in Section 5 and the security rules in Section 10. A change that weakens one is a bug even if tests pass.
7. **Tests ship with the code.** Each acceptance criterion has a named test file (F.6). Your workstream is done only when its tests pass in CI with `pnpm typecheck && pnpm lint && pnpm test`.
8. **Handoff note.** End with `docs/handoff/<WS-id>.md`: what exists, how to run it, open questions, `TODO(VERIFY)` list.
9. **Branches.** `ws/<id>-<topic>`. Small commits. Merge to `main` only after your tests pass and no other workstream's tests broke.

### F.2 Wave 0 — contracts and scaffold (one agent, finishes first)

Owner: **WS-0**. Nothing else starts until this merges, except WS-3's InstaBox spike (M0), which only reads docs and calls the API.

Deliverables:

- Monorepo (pnpm workspaces, Turborepo), TypeScript strict, ESLint, Prettier, Vitest, Playwright, CI running typecheck, lint and tests.
- `packages/shared`: Zod schemas and inferred types for the scan manifest, `ToolResult`, `NormalizedFinding`, `ControlResult`, `ScanEvent`, API request and response bodies, env schema, error codes. Plus `mocks/` with realistic sample data.
- `packages/db`: Drizzle schema and migrations for every entity in Sections 12 and E.4. No query layer yet.
- `packages/sandbox`: the `SandboxProvider` interface (Appendix A.4) and a working in-memory `FakeProvider` that simulates operations, exec results, files and failures.
- `packages/storage`: the `Storage` interface and a fake.
- Empty package skeletons with the folder layout in D.1, each with a `README.md` stating its owner and contract.
- Vercel project config, `vercel.json` with cron routes returning 501, env validation, `docs/contracts/CHANGES.md`.

### F.3 Wave 1 — workstreams (run in parallel)

| ID    | Workstream                           | Owns                                                                                                                                  | Consumes                                          | Done when                                                                                                                                                                                                                                                |
| ----- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WS-1  | Identity, workspaces, tenancy, audit | `apps/web/app/(auth)/**`, `apps/web/app/api/workspaces/**`, `packages/db/src/scoped/**`, audit writer                                 | shared, db schema                                 | Sign-in, workspaces, roles, `withWorkspace`, RLS, audit on every mutation. **AC-10** test passes. Lint rule blocks direct table access                                                                                                                   |
| WS-2  | Targets, verification, policy        | `packages/policy/**`, `packages/safe-fetch/**`, verification routes, `/api/cron/expiry`                                               | shared, db scoped                                 | DNS TXT and hosted-file verification, expiry, `authorizeScan`, `safeFetch`. **AC-01, AC-02, AC-03** pass. SSRF suite passes (private, loopback, link-local, metadata, IPv6, redirects, rebinding)                                                        |
| WS-3  | InstaBox provider and snapshots      | `packages/sandbox/src/instabox/**`, `infra/snapshot/**`                                                                               | `SandboxProvider`, InstaBox docs                  | `InstaboxProvider` passes the same contract test suite as `FakeProvider`. Snapshot build scripts pin tool versions and bundle rules and the vulnerability DB. Answers to Appendix A.3 written to `docs/handoff/WS-3.md`. **AC-04** against real InstaBox |
| WS-4  | Runner and tool adapters             | `runner/**`, `packages/adapters/**`                                                                                                   | shared schemas, fixtures                          | Runner implements E.3 with a fake tool harness. Adapters for ZAP baseline, testssl.sh, Semgrep, Gitleaks and Trivy parse recorded fixtures into `NormalizedFinding[]`. Tool errors never become passes. **AC-05, AC-06, AC-11**                          |
| WS-5  | Orchestration workflows              | `workflows/**`, `packages/orchestration/**`, `/api/cron/reconcile`, `/api/projects/:id/scans`, `/api/scans/:id`, `/cancel`, `/events` | `FakeProvider`, policy interface, runner contract | Full E.2 workflow runs end to end against `FakeProvider` with failure injection: create failure, runner crash, timeout, cancel at each state, replayed steps. Reconciler deletes orphans. **AC-09**, and **AC-04** against the fake                      |
| WS-6  | Findings, scoring, reports           | `packages/scoring/**`, normalization and dedupe pipeline in `packages/orchestration/findings/**`, report and comparison routes        | shared, fixtures                                  | Fingerprinting, dedupe, severity, OWASP/CWE mapping, versioned scoring (Section 15), JSON and PDF reports, scan comparison, finding state machine. **AC-07, AC-08, AC-13, AC-14**                                                                        |
| WS-7  | Frontend                             | `apps/web/app/(app)/**`, `apps/web/components/**`                                                                                     | `packages/shared/mocks`, typed API client         | Every page in Section 11 works against the mock API, including Live scan and Finding page rules from Section 17. Responsive, accessible, dark mode. Playwright smoke tests                                                                               |
| WS-8  | GitHub integration                   | `apps/web/app/api/github/**`, `apps/web/app/api/integrations/**`, `packages/integrations/github/**`                                   | shared, db scoped                                 | GitHub App install, repository selection, short-lived read-only token minting, webhook verification. Repository authorization never grants domain authorization (Step 2)                                                                                 |
| WS-9  | AI analyst                           | `packages/analyst/**`                                                                                                                 | shared, redacted evidence fixtures                | `explainFinding` returns schema-validated JSON that cites the finding ID and location, cannot create or upgrade a finding, treats evidence as data, and has a prompt-injection test set                                                                  |
| WS-10 | Benchmarks and security regression   | `benchmarks/**`, `tests/**`                                                                                                           | everything, read-only                             | Seeded vulnerable and secure fixture apps and repos, precision and recall harness, cross-tenant, SSRF, policy-bypass and cleanup regression tests wired into CI. **AC-12**                                                                               |

### F.4 Interface contracts

Signatures are binding. Implementations may add optional parameters, not change required ones.

```ts
// packages/policy
authorizeScan(input: { project: Project; targets: Target[]; policy: ScanPolicy; actor: Member; now: Date }):
  Promise<{ ok: true; manifest: ScanManifest } | { ok: false; reason: PolicyDenial }>;

// packages/safe-fetch
safeFetch(url: string, opts?: { timeoutMs?: number; maxBytes?: number; maxRedirects?: number }): Promise<Response>;
resolveTxt(name: string): Promise<string[]>;

// packages/sandbox  (SandboxProvider as in Appendix A.4)

// packages/storage
interface Storage {
  put(key: string, data: Buffer, o?: { contentType?: string }): Promise<void>;
  get(key: string): Promise<Buffer>;
  signedUrl(key: string, ttlSeconds: number): Promise<string>;
  deletePrefix(prefix: string): Promise<void>;
}

// packages/adapters  (pure, no I/O)
parseToolOutput(tool: ToolId, raw: Buffer): ParsedOutput;
normalize(parsed: ParsedOutput, ctx: { scanId: string; target: string }): NormalizedFinding[];

// packages/scoring  (pure)
computeScore(controls: ControlResult[], scoringVersion: string):
  { score: number | null; coverage: number; confidence: 'high' | 'medium' | 'low'; byCategory: Record<Category, number | null>; criticalOverride: boolean };

// packages/db
withWorkspace(workspaceId: string): ScopedDb;   // the ONLY way to query tenant tables

// packages/analyst
explainFinding(f: NormalizedFinding, evidence: RedactedEvidence): Promise<Explanation>;
```

CLI contract: `shipsafe-runner run --manifest <path> --out <dir>`; exit code 0 means the runner finished (even if tools failed), nonzero means the runner itself failed. Per-tool results live in `result.json`.

### F.5 Integration order and merge gates

| Gate | Condition                                                                                             | Unlocks                                                  |
| ---- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| A    | WS-0 merged, CI green                                                                                 | All Wave 1 workstreams start                             |
| B    | Each workstream passes its own tests and the shared contract suites                                   | Wave 2 integration                                       |
| C    | WS-3 handoff answers the Appendix A.3 questions, or records the gaps                                  | Switching `SANDBOX_PROVIDER` to `instabox` outside tests |
| D    | End-to-end baseline and code scan pass on a real InstaBox VM from a production-like Vercel deployment | AC-04 to AC-07 signed off                                |
| E    | Benchmark, tenancy, SSRF, cleanup and cancellation suites pass                                        | External testing (Section 20)                            |

Wave 2 integration is owned by one agent: wire WS-1 through WS-9 together, flip the provider to InstaBox in a staging environment, fix seams, and do not rewrite another workstream's internals; file an issue against it instead.

### F.6 Acceptance criteria to test files

| AC    | Test file                                                               | Owner      |
| ----- | ----------------------------------------------------------------------- | ---------- |
| AC-01 | `tests/ac/ac01-project-verification.test.ts`                            | WS-2       |
| AC-02 | `tests/ac/ac02-unverified-no-active.test.ts`                            | WS-2       |
| AC-03 | `tests/ac/ac03-scope-rejection.test.ts`                                 | WS-2       |
| AC-04 | `tests/ac/ac04-sandbox-lifecycle.test.ts` (fake in CI, real in staging) | WS-3, WS-5 |
| AC-05 | `tests/ac/ac05-passive-findings.test.ts`                                | WS-4       |
| AC-06 | `tests/ac/ac06-source-scan-seeded.test.ts`                              | WS-4       |
| AC-07 | `tests/ac/ac07-report-contents.test.ts`                                 | WS-6       |
| AC-08 | `tests/ac/ac08-skipped-never-improves-score.test.ts`                    | WS-6       |
| AC-09 | `tests/ac/ac09-cancel-and-cleanup.test.ts`                              | WS-5       |
| AC-10 | `tests/ac/ac10-tenant-isolation.test.ts`                                | WS-1       |
| AC-11 | `tests/ac/ac11-scanner-output-untrusted.test.ts`                        | WS-4, WS-9 |
| AC-12 | `tests/ac/ac12-benchmark.test.ts`                                       | WS-10      |
| AC-13 | `tests/ac/ac13-repeat-scan-diff.test.ts`                                | WS-6       |
| AC-14 | `tests/ac/ac14-limitations-shown.test.ts` (Playwright)                  | WS-7       |

### F.7 Later workstreams (start after Phase 1 is integrated)

| ID    | Workstream                                                                                                             | Phase | Owns                                                   |
| ----- | ---------------------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------ |
| WS-11 | Supabase and Firebase configuration engine (F07)                                                                       | 2     | `packages/engines/database/**`                         |
| WS-12 | Multi-account authorization engine, OpenAPI import, API engine (F08, F09), advanced assessment approval flow           | 2     | `packages/engines/authz/**`, `packages/engines/api/**` |
| WS-13 | AI security engine with Promptfoo and garak, separate AI score (F10)                                                   | 3     | `packages/engines/ai/**`                               |
| WS-14 | Developer workflow: CLI, CI gates, PR checks, scheduled scans, notifications, remediation PRs, public API (F14 to F16) | 4     | `packages/cli/**`, `apps/web/app/api/v1/**`            |

Each later workstream plugs in by adding adapters and control definitions plus a new manifest job type. Adding one MUST NOT require changing `packages/orchestration`.

## Appendix G — Decision Log

| ID  | Decision                                                                                                                                     | Status                 |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| D1  | Deploy on Vercel (read from the request as Vercel)                                                                                           | Decided                |
| D2  | No separately hosted backend. Serverless route handlers plus Vercel Workflow                                                                 | Decided                |
| D3  | InstaBox runs all scan compute and is the core of the product                                                                                | Decided                |
| D4  | Pull model: workflow drives the VM; the VM never calls ShipSafe                                                                              | Default                |
| D5  | PostgreSQL via Vercel Marketplace (for example Neon), Drizzle ORM                                                                            | Default **\[VERIFY\]** |
| D6  | Vercel Blob (private) behind a `Storage` interface                                                                                           | Default **\[VERIFY\]** |
| D7  | Auth.js with GitHub sign-in; separate GitHub App for repositories                                                                            | Default                |
| D8  | Runner written in TypeScript on Node LTS, sharing Zod schemas                                                                                | Default                |
| D9  | pnpm workspaces, Turborepo, Vitest, Playwright                                                                                               | Default                |
| D10 | Anthropic API for the AI analyst, called directly from steps and routes                                                                      | Default                |
| D11 | Scoring weights and penalties (Section 15) are tunable and versioned                                                                         | Default                |
| D12 | Vercel plan: Pro assumed for per-minute cron and longer function duration. Hobby works with daily cron and the in-workflow reconciler timers | Open                   |
| D13 | Pricing, billing provider and free-tier scan limits                                                                                          | Open                   |
| D14 | Region for functions, database and InstaBox                                                                                                  | Open **\[VERIFY\]**    |

Status meanings: **Decided** is fixed by the product owner. **Default** is a proposal agents follow unless a contract-change entry replaces it. **Open** needs an answer before the workstream that depends on it can finish.
