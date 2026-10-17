# ShipSafe scanning feasibility and implementation decision

Research date: 2026-10-16. This is an engineering/licensing assessment, not a legal clearance.

Follow-up: [SHIPSAFE-LAUNCH-PLAN.md](SHIPSAFE-LAUNCH-PLAN.md) records the subsequent tool provisioning, private fixture validation and unsuccessful idle-pause setting attempts. Statements below about no VM execution/settings changes describe this initial research pass, not the later preparation work. The [test catalog](SECURITY-TEST-CATALOG.md) contains 77 proposed checks; none is integrated as product coverage yet.

## Decision

The product is feasible as an authorized, evidence-backed security assessment
service. It cannot safely promise to discover every vulnerability or breach from
a URL. Tool licensing, target authorization, infrastructure permission, and data
handling are separate requirements. An open-source license does not grant rights
over a third party's website.

The latest user instruction is to research these questions before implementing
live execution. No scanner was run, no execution gate was removed, and no VM
lifecycle setting was changed in this research pass.

## Current implementation and VM

- The landing page opens its terminal inline, but URL submission currently only
  prepares an internal target. It does not start a security scan.
- The scan API requires current DNS ownership/scope and returns
  `EXECUTION_NOT_READY`. SSE currently replays completed records rather than
  driving an isolated live job. Application records remain process-memory only.
- The legacy scanner runs TLS/header checks, sensitive-path probes, and port
  connections. The OSINT runner also probes discovered subdomains. This is more
  than passive collection of already-public third-party records.
- An authenticated, read-only SDK call confirmed `shipsafe-vm` was running with
  `autoSuspendMs: 1800000` (30 minutes). No timeout/archive deadline was returned
  by the listing. The machine's settings were not changed.
- The installed SDK is `@insforge/instabox-sdk` 0.5.0. Its documented default is
  `https://api.instabox.sh` and it reads `INSTABOX_API_URL`; the repository's
  `.env.example` still mentions an older server address. Update configuration
  documentation before enabling production execution.

## Assessment modes

| Mode | Inputs/access | Suitable checks | Boundary |
| --- | --- | --- | --- |
| Public footprint preview | Domain plus lawfully usable public-data APIs | Certificate transparency, public DNS/RDAP, historical exposure metadata | No exploit templates, sensitive-path discovery, port sweep, or claims of confirmed compromise. Respect each data source's terms and rate limits. |
| Authorized website baseline | Exact-host proof and recorded customer authorization | Normal HTTP response/header/cookie review, bounded crawl and passive analysis, scoped TLS assessment | Still sends traffic. A passive analyzer is different from a zero-contact workflow. |
| Authorized active assessment | Baseline authorization plus explicit test profile, limits, preferably staging | Curated vulnerability templates, selected DAST checks, API testing | No destructive tests, credential guessing, DoS, arbitrary payload uploads or unbounded discovery in the default product. |
| Authenticated/source assessment | Test accounts and/or code, SBOM, lockfiles or container image | Cross-user authorization cases, dependency/config/secrets analysis | A URL cannot supply these inputs. GitHub is optional; uploads or customer CI can supply artifacts. |

Customers can authorize ShipSafe to assess their own systems; the operator does
not need to personally own every customer's domain. Record who granted authority,
the precise host/path scope, expiry and test profile. DNS or a hosted challenge
can verify control once without reintroducing a permanent ownership column.
Control proof alone does not authorize testing a hosting provider's shared
infrastructure or third-party services linked from a customer's application.

ZAP explicitly calls active scanning an attack requiring permission. Its baseline
script omits active attacks but crawls the target first. Therefore we should not
market the word “passive” as blanket permission to scan any URL. Automated scans
also miss important application logic and access-control issues. [ZAP active
scan](https://www.zaproxy.org/docs/desktop/start/features/ascan/), [ZAP baseline](https://www.zaproxy.org/docs/docker/baseline-scan/).

## Tool licensing shortlist

These findings concern the reviewed upstream versions/branches, not a permanent
clearance for every dependency, rule, template, data feed or packaged image.

| Component | Reviewed upstream license | ShipSafe decision |
| --- | --- | --- |
| ZAP | Apache-2.0 | Suitable candidate with required notices, dependency/add-on review and authorized test profiles. [License](https://github.com/zaproxy/zaproxy/blob/main/LICENSE). |
| Nuclei engine and official templates | MIT, separately licensed repositories | Candidate for curated, pinned templates. Preserve both notices and review any external template licenses; MIT is not target authorization. [Engine](https://github.com/projectdiscovery/nuclei/blob/dev/LICENSE.md), [templates](https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md). |
| Trivy | Apache-2.0 | Candidate for supplied artifacts/images; audit the vulnerability-data sources and packaged dependencies too. [License](https://github.com/aquasecurity/trivy/blob/main/LICENSE). |
| Gitleaks | MIT | Candidate for supplied source artifacts; no need to require a GitHub connection. [License](https://github.com/gitleaks/gitleaks/blob/master/LICENSE). |
| testssl.sh, reviewed 3.2 branch | GPLv2 license text | Commercial operation is not automatically prohibited. Review exact release notices, modifications, redistribution and bundled binaries before shipping images. Keep license/source compliance separate from target permission. [License](https://github.com/testssl/testssl.sh/blob/3.2/LICENSE). |
| Semgrep | CE engine LGPL-2.1; Semgrep-maintained registry rules use Semgrep Rules License v1.0 | Do not bundle maintained registry rules into ShipSafe's competing SaaS without a separate agreement. Own independently authored rules or properly licensed third-party rules need their own review. [Official licensing](https://docs.semgrep.dev/licensing). |
| Nmap | Nmap Public Source License | Exclude from the default commercial bundle pending review/OEM agreement. Its upstream page identifies special restrictions for proprietary-product use. [NPSL](https://nmap.org/npsl/). |

Maintain a versioned third-party inventory: binary/image digest, license, NOTICE,
source URL, dependencies, rule/template pack version and data-feed terms. Generate
notices and retain source offers where applicable. Keep proprietary commercial
tools such as Burp Professional out of the worker image without suitable vendor
licensing. Have counsel review the exact commercial packaging and customer terms
before launch; this inventory is not a legal guarantee.

## Proposed implementation

1. URL submission creates an idempotent scan request after backend authorization.
   Show loading immediately and scroll to the existing terminal on the same page.
   An unverified customer receives only the separately labeled public-data mode.
2. Store jobs, authorization, ordered events and results in PostgreSQL. A durable
   queue claims each job once, applies per-user/per-host quotas and survives web
   restarts. Browser SSE subscriptions must not launch jobs or control job life.
3. Keep `shipsafe-vm` available as trusted tooling/template infrastructure if
   desired. Prefer disposable per-scan VMs for a public multi-user product. This
   preserves repository isolation/teardown requirements while the named host
   stays online. Reusing one unrestricted guest and one output directory for all
   users is not the proposed architecture. Containers share a kernel and are not
   equivalent to independent VM isolation; any container-only alternative needs
   an explicit architecture/security review.
4. Enforce exact-target egress independently of scanner code. Validate public
   A/AAAA addresses, reject metadata/private/local destinations, pin resolution,
   validate every redirect, and exclude discovered hosts unless separately
   authorized. Apply resource, output, request-rate and duration limits. Scan
   guests receive no account Vault items or control-plane credentials.
5. Collect actual stdout/stderr through bounded SDK polling. Persist ordered,
   redacted events and send them to the terminal over SSE with replay after
   reconnect. SDK command output is returned at completion, so passing a callback
   alone is not sufficient for interactive logs. Never emit fake progress.
6. Parse structured tool outputs deterministically, record tool/rule versions
   and individual executed/failed/skipped checks, and normalize evidence-backed
   findings. Persist the report before emitting `report.ready`. Show findings,
   evidence, remediation, coverage and limitations inline. An LLM may explain
   evidence, not invent findings or execute scanner-output instructions.
7. On completion/failure/cancellation/timeout, tear down the job VM and expire
   temporary artifacts. An orphan reconciler handles lost workers. Retain reports
   according to customer retention rules, redact secrets, and expose cancellation
   and an operator kill switch.

## Availability and provider constraints

For the named host, the documented SDK calls `setAutoSuspend(0)` and
`setTimeout(0)` disable idle suspension and clear the timeout respectively.
Always-on does not guarantee availability: resume may restore memory or start
fresh, so jobs need durable state, worker restart supervision, health checks,
bounded retries and recovery. Avoid fake traffic or busy loops as a keepalive.
[SDK reference](https://instabox.sh/docs/sdk), [machine lifecycle](https://instabox.sh/docs/machines).

Default limits are five machines across all states and four concurrent execs,
with a ten-minute command ceiling. The account currently lists two machines,
so admission must inspect actual capacity rather than assume four free workers.
Start with one scan at a time and reserve exec capacity for logs, status and
cancellation. An always-on host consumes resources while idle. [Limits](https://instabox.sh/docs/limits).

I did not locate an InstaBox-specific published policy explicitly approving a
public vulnerability-scanning SaaS. SDK availability is not that approval. Obtain
written confirmation from InstaBox covering outbound vulnerability testing,
commercial service use, allowed traffic and abuse handling before public launch.
InsForge's separate platform security policy is not a blanket InstaBox hosting
agreement; do not substitute it for the applicable provider contract.

## First implementation milestone

Build and validate the complete journey against a self-hosted, isolated test lab
under our control, such as a private OWASP Juice Shop instance. Do not assume the
public demo is available for unrestricted scanning. Then test a verified customer
staging host with recorded permission. Validate cancellation, worker death,
reconnect, out-of-scope redirects, failed tools, report durability and cross-user
access before allowing public submissions. [OWASP Juice Shop](https://github.com/juice-shop/juice-shop).

Do not promise “all breaches found” or “100% secure.” The report is an assessment
of the specific controls actually tested, with manual review and deeper inputs
needed for remaining risks.
