# Proposed security test catalog

**Status: engineering proposal. Every full case in the companion CSV remains `PLANNED` for product acceptance.** A narrower [local baseline](LOCAL-RUNTIME.md) now implements 13 hardening outcomes and has been exercised against a private fixture; it does not establish complete coverage of these broader cases. No authorized production website validation has occurred. This catalog does not authorize target assessments or claim a finding about any site. A confirmed finding must be supported by actual scanner output or recorded test evidence. A missing header or other hardening recommendation is not itself proof of exploitability.

The catalog contains **77 distinct planned cases**. It proposes **15 launch-MVP cases** (`launch_priority=Launch MVP` in the CSV): ten exact-host URL cases, plus five access-dependent essentials that need owned test accounts, source/schema access, or a payment sandbox. The local baseline implements limited observations related to the URL cases; acceptance of their full intended behavior remains pending. The access-dependent cases must not be represented as URL-only coverage.

## Scope and operating boundary

URL-only access can inspect a limited set of externally observable behavior, such as a certificate, ordinary response headers, redirects, and a harmless error response. It cannot establish source-code secret hygiene, database RLS behavior, client/server authorization parity, cross-tenant isolation, webhook verification, dependency risk, cloud IAM, CI trust, or agent tool policy. No URL-only result represents complete coverage.

The catalog separates:

- `URL-only authorized production low-impact`: exact authorized hostname only; capped ordinary HTTP/TLS observations; no guessed paths, port scanning, credential attempts, exploit payloads, or unapproved redirects.
- `Staging with test accounts` / `Staging/provider sandbox`: controlled actions against owned test identities, synthetic records, disposable resources, and provider test mode.
- `Source/artifact review`, `Source/local fixture`, and `Provider/source access`: checks requiring code, build outputs, schemas, effective configuration, or read-only provider access. Local behavior checks use synthetic fixtures.

Authorization must specify the host and paths, permitted assessment profile, rate/duration limits, and expiry. Authorization to assess an application does not authorize tests against its hosting provider, identity provider, payment processor, linked third-party service, or other shared infrastructure. Production login should be read-only and use an owner-provided test account; state-changing cases belong in staging or a provider sandbox. These are proposal boundaries, not legal clearance.

## Launch MVP cases (15)

These are the proposed first bounded cases; each requires its stated access. Full acceptance remains planned. URL observations should be low-rate and limited to the exact authorized hostname.

| IDs | Check | Minimum access and boundary |
| --- | --- | --- |
| WEB-01–WEB-07 | Certificate, HTTPS redirect, HSTS, CSP, framing, MIME-sniffing, and referrer-policy response inspection | Exact authorized production hostname; ordinary TLS/HTTP observations only. Missing CSP is not an XSS finding. |
| AUTH-07 | Session-cookie Secure, HttpOnly, and SameSite attribute inspection | Exact authorized production hostname; inspect cookies returned by ordinary approved page responses. |
| INJ-09, INJ-11 | CORS policy inspection and harmless error-response disclosure review | Exact authorized production hostname and documented client origins; use benign requests only. |
| TEN-01 | Cross-account record read authorization | Two owned test accounts and records seeded for this test; staging preferred. |
| TEN-04 | Supabase RLS policies on exposed tables | Source/schema access plus dummy principals; confirm actual policies and behavior, not merely the presence of a tenant column. |
| TEN-05 | Supabase service-role key absent from client artifacts | Source/build artifact access; output must redact secret values. |
| PAY-01, PAY-02 | Payment webhook signature verification and replay/idempotency | Payment-provider sandbox, its documented test event mechanism, and disposable test order; never replay a real production transaction. |

This selection is a practical first slice, not a compliance profile. It prioritizes commonly missed trust boundaries in modern hosted apps while keeping checks bounded. Other launch-readiness work such as queueing, isolation, teardown, report durability, rate controls, and actual scanner integration is outside this test catalog and remains governed by [SCAN-IMPLEMENTATION-RESEARCH.md](SCAN-IMPLEMENTATION-RESEARCH.md).

## Catalog contents

The CSV is the machine-readable source of check-level detail: access prerequisites, execution mode, priority, method, confirmation evidence, remediation direction, status, and source family. Priority is a proposed sequencing aid, not a severity rating. `Standard` and `Later` checks are not implied to be implemented or scheduled.

Coverage includes TLS and browser policy; authentication and session lifetime; object authorization and tenant isolation; Supabase RLS and key handling; files, exports, caches, and vector stores; input handling, SSRF, uploads, and APIs; source secrets and dependency review; cloud IAM, storage, deployment, and CI; payments and business rules; and AI agent/MCP boundaries. The planned cases explicitly include access token expiry, webhook signatures and replay, cross-tenant files and vector results, and deterministic authorization of agent tools.

Do not overstate evidence:

- Missing CSP is a configuration gap to assess in context, not proof of exploitable XSS.
- An HTTP `200` response does not prove a secret was exposed. Evidence must identify the actual credential or sensitive value and its privilege, with the value redacted in retained output.
- A Supabase anon/publishable key is intended for client use when paired with appropriate grants and RLS; it is not equivalent to a service-role key.
- A source map being public is not automatically a critical vulnerability. Confirm specific sensitive content and impact.
- A tenant column, UI route guard, or model instruction is not an authorization boundary by itself; check the enforcement point and test with dummy principals.
- A skipped, unavailable, or failed check receives no coverage credit. Reports must state what ran, what failed or was skipped, and what access was unavailable.

## Implementation and licensing notes

The existing feasibility research identifies candidate tool licenses and unresolved packaging review. In particular, **do not bundle Semgrep-maintained registry rules into a competing SaaS without separate agreement**; review rule provenance and exact terms. **Nmap is excluded from the default commercial bundle pending review or an OEM agreement** because its NPSL has proprietary-product restrictions. Tool/engine licenses do not authorize testing a target. Review pinned tool, add-on, template, rule, image, dependency, and data-feed terms before shipping; this catalog is not legal clearance.

The source-first audit guidance emphasizes evidence tied to a concrete principal/resource boundary, safe local fixtures, and treating unavailable deployment/provider facts as needing validation rather than assuming them. It is methodology guidance, not a scanner specification or live-target authorization.

## Primary references

Standards and methods are cited by edition or stable project page. This catalog uses no invented ASVS or WSTG requirement identifiers.

- [OWASP Application Security Verification Standard (ASVS) 5.0.0](https://github.com/OWASP/ASVS/releases) — stable release reference.
- [OWASP Web Security Testing Guide (WSTG) v4.2](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/) — testing methodology, not a compliance checklist.
- [OWASP API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x00-header/), including [API1:2023 Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).
- OWASP Cheat Sheet Series: [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [Server-Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), and [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
- Cloudflare [security-audit-skill](https://github.com/cloudflare/security-audit-skill), especially [CLOUD-AND-DEPLOYMENT.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/CLOUD-AND-DEPLOYMENT.md), [DATA-ISOLATION-AND-LIFECYCLE.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md), [AI-AND-LLM.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/AI-AND-LLM.md), and [ATTACK-CLASSES.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/ATTACK-CLASSES.md). These are source-audit guidance; they do not constitute a live scanner.
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) and [API keys](https://supabase.com/docs/guides/api/api-keys).
- [Next.js environment variables](https://nextjs.org/docs/app/guides/environment-variables).
- [Stripe webhook signature verification](https://docs.stripe.com/webhooks/signature) is an example of provider-specific primary documentation; use the actual configured payment provider's instructions and test environment.
- Payment webhook checks must use the exact provider's official webhook documentation and sandbox when the provider is known; the relevant provider is application-specific and is intentionally not guessed here.
- [ShipSafe scan feasibility and implementation research](SCAN-IMPLEMENTATION-RESEARCH.md) — current product-specific authorization, execution, and license-review constraints.

