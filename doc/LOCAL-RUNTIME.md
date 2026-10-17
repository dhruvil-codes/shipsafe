# Local single-VM baseline

The owner selected one persistent InstaBox VM, a queue and a $0 Cloudflare hosting target. This local implementation is the first bounded profile, not the 77-check roadmap or a completed public deployment. No third-party site has been authorized or scanned during development.

## Run locally

Install with `bun install --frozen-lockfile`. Keep `INSTABOX_API_KEY` and `INSTABOX_SANDBOX_ID` in the ignored root `.env.local`. Run `bun run scan:local` from the repository root; it starts a loopback-only preview on port 3016 with the local worker and fixed private lab enabled. Set `SHIPSAFE_PORT` to use another free port. For a production preview, first `bun run --filter @shipsafe/web build`, then `bun run scan:local --production`. Do not build while a dev server uses that same worktree's `.next` directory.

The default state directory is `.artifacts/local-scans`, outside Git and the public folder. Override `SHIPSAFE_DATA_DIR` if necessary. One server process owns its exclusive writer lock. Queued jobs and browser capabilities survive a restart; interrupted jobs become failed, never automatically successful or silently rescanned. Reusing the same browser cookie restores that browser's records. There is no cross-device account or multi-instance storage support. Protect the local state directory with operating-system permissions; it contains capability identifiers and scan attestations.

## Current checks (13)

| Check | What it actually establishes |
| --- | --- |
| HTTPS | A successful certificate-chain and hostname-validated HTTPS connection, with certificate validity metadata |
| HTTP redirect | Observed same-host HTTP-to-HTTPS redirect; unavailable probes are skipped |
| HSTS | Positive max-age in the observed HTTPS response; HTTP fixture is skipped |
| CSP | Presence of an enforced policy, not comprehensive policy quality |
| Framing | Supported restrictive frame-ancestors or X-Frame-Options configuration |
| MIME sniffing | Exact nosniff header value |
| Referrer policy | A recognized restrictive explicit policy |
| Cookie Secure | Attribute presence on response cookies, without retaining values |
| Cookie HttpOnly | Attribute presence; non-session cookie purpose requires contextual review |
| Cookie SameSite | Attribute presence, not full session/CSRF behavior |
| CORS | Ordinary response wildcard-header observation; no authenticated cross-origin exploit validation |
| Error disclosure | Known diagnostic markers in at most 64 KiB of the ordinary returned page; no error-inducing exploit payloads |
| HTTP response | Returned status; receiving HTTP does not prove authorization or absence of vulnerabilities |

Observations are INFO hardening records with concrete evidence and fix directions. The report's versioned URL baseline score is the share of assessed checks that passed; observed gaps are assessed but do not pass. Skipped and failed checks receive no score or coverage credit. Coverage is assessed unique check IDs out of the fixed 13-check profile. This profile score is not the broader severity-weighted confirmed-vulnerability score and says nothing about untested application areas. TLS/transport failure fails the job without manufacturing a successful report or certificate vulnerability finding. If a site returns a redirect that cannot be safely followed within the exact-host HTTPS policy, ShipSafe records a scope-limited report from only the submitted hostname's redirect response; it does not request the destination and assigns no full-profile score or coverage. Unavailable access is explicit; a missing header is not proof of exploitable XSS or compromise.

## Permission and scope boundaries

Submitting a website records the user's explicit attestation that they own or are authorized to assess the exact hostname. No DNS TXT setup or separate checkbox is required. This is a self-attestation, not independent proof of ownership; it only authorizes the bounded URL baseline and does not authorize third-party infrastructure, other domains or discovered subdomains. Dispatch requires the stored attestation and matching exact hostname. User authorization must cover the assessment's ordinary bounded requests, including the HTTP upgrade observation. Redirects are followed only on the submitted hostname and its conventional `www`/apex alias, and cannot downgrade HTTPS. Other subdomains are not in scope. When the redirect is invalid, ambiguous, missing, over the hop limit, changes host or downgrades HTTPS, ShipSafe stops there and records only the last in-scope hostname's response. The scanner rejects credentials, fragments, query parameters, custom ports, IP/local targets, private/mapped/translation addresses and mixed public/private DNS answers. Approved public IPs are pinned into the socket while TLS verifies the original hostname. It sends no session credentials, exploits or arbitrary shell arguments.

The private lab route accepts no body or target options and always runs the same owned loopback fixture inside a network-disabled container on InstaBox. It cannot be used to scan arbitrary localhost services. Its observations are labeled synthetic in the UI and report manifest.

The website transport is a trusted, small Python collector running on the VM with a sanitized environment, bounded requests, pinned connections and no target-controlled code execution. It is not a general-purpose customer-code sandbox or a network-enabled ZAP/Nuclei runner. Customer uploads/builds and arbitrary template execution remain disabled. The existing host has Vault enabled, so never mount its HOME, environment or Docker socket into a customer container.

## Execution and recovery

At most five jobs may be active/queued globally and each browser may submit three jobs per minute. The local worker drains FIFO one at a time. A VM-side flock prevents overlapping scans after a control-plane restart or accidental second dispatcher. Fixed trusted processes have a timeout, sanitized environment and private job directories; the lab also has container resource limits and no external network. SDK operations remain backend-driven. The VM never receives control-plane credentials.

The backend pulls bounded JSONL events, validates the report schema, saves findings/manifest/check outcomes, verifies cleanup, then records completion. SSE replays ordered event IDs and supports Last-Event-ID. Closing a browser stream only detaches the subscriber. Cancellation signals the job group, removes the lab container and temporary files, and preserves partial evidence. The shared VM is never deleted.

If cleanup cannot be verified, the job records `reportManifest.cleanupState=unverified`, emits CLEANUP_FAILED and the shared worker is quarantined across restarts. The operator must inspect the known job process/container and resolve that stored record through a trusted local maintenance operation before accepting more work; no public bypass exists. Expired private job directories are reaped only after bounded process lifetimes and identity checks. A crash can leave temporary state until the next worker invocation; this is not a continuously deployed reaper service.

## Downloadable reports and fix prompts

Terminal assessments (completed, failed or cancelled) expose an owner-only HTML download at `/api/scans/ID/report` and structured JSON with `?format=json`. Downloads use persisted records only and never start another scan. The HTML contains no scripts or external resources; evidence is escaped, served as an attachment with a restrictive CSP, and marked private/no-store. Synthetic fixtures and partial assessments remain labeled. Failed/skipped/malformed outcomes receive no success credit.

Every recorded issue has a visible and copyable fix prompt containing the target, engine, finding, evidence and remediation. Captured fields are explicitly untrusted data. The prompt asks the coding tool to inspect the actual implementation, preserve protections, add a regression check and report actual results; it does not authorize deployment or external testing. A fix remains unverified until an authorized retest. See [the expanded coverage roadmap](SECURITY-COVERAGE-ROADMAP.md) for planned deeper cases and [runs-on.dev deployment choices](RUNS-ON-DEV.md) for the free subdomain option.

## Deferred test profiles

Permission-dependent: authenticated API/tenant/admin tests, injection/SSRF/upload behavior, webhook replay and business logic require explicitly authorized staging/test accounts or provider sandboxes. Source-dependent: dependency CVEs, secret history, RLS and cloud IAM need supplied artifacts/configuration. AI/MCP checks need an owned agent fixture and tool-policy access. They are not silently included in the URL baseline.

Excluded from the default product: credential guessing, brute force, destructive writes, denial-of-service, data extraction, guessed sensitive-path/port sweeps, arbitrary subdomain testing and unrestricted exploit templates. Some are out of the default risk profile even with domain control. Semgrep-maintained rules and Nmap are deferred for commercial licensing review; engine availability does not resolve template, add-on or feed terms. ZAP/Nuclei/Trivy/Gitleaks images were prepared earlier, but the website flow currently uses only the trusted ShipSafe HTTP baseline engine.

## Deployment still required

The Cloudflare keepalive in `deploy/keepalive/` is prepared and mocked-tested, not deployed. No cron or 24/7 guarantee is active. On 2026-10-16, an SDK `setAutoSuspend(0)` call returned without error, but a fresh `getInfo()` still reported `autoSuspendMs: 1800000`; a harmless VM `true` command succeeded. A 20-minute Worker schedule can resume a paused box and run a harmless command, but its delivery and the provider's idle-reset behavior are not guaranteed. Wrangler currently has no authenticated Cloudflare account in this environment, so deployment and secret configuration remain pending. Cloudflare Workers Free can host a lightweight scheduled handler, but the full Next.js application and its CPU/runtime compatibility must be verified. This file store and in-process local dispatcher cannot be deployed to Workers unchanged: durable storage, dispatch/recovery, production abuse controls for self-attested scans and worker packaging remain deployment tasks. A workers.dev URL avoids buying a domain for the initial demo.
