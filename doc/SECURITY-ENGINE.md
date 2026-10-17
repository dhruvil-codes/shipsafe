# Standard and verified Deep engine

Implementation date: 2026-10-17. This document records the implemented slice of the supplied security-engine request. The proposed 150 checks are a planning catalog, not current coverage. There are 40 implemented bounded observations and 15 explicit deferred capabilities in the versioned executable registry. A registered observation may still be NOT_TESTED on a particular target.

## Live elementary-check events

The Python engines emit a `stage=check` JSONL record immediately before evaluating a check and a matching `stage=check_done` record with `checkId`, terminal `status` (`passed`, `observation` or `skipped`), timestamp and the complete bounded summary. HTTPS and redirect lifecycle starts precede the first request. DNS records, metadata, response-policy checks and selected Deep classes report as their operations complete. Event text contains the same redacted evidence rules as the report; it never includes cookie values, bodies, DNS payloads or resource destinations.

The InstaBox delta poller validates and forwards those fields into append-ordered persisted events. SSE replay retains event IDs, timestamps and messages; the inline terminal labels `[check]` and `[check_done]`, with passed, observation and skipped completions in distinct high-contrast colors. The top form always starts Standard Scan. A completed report places the expandable Deep authorization flow after its checks; prior Deep reports also offer authorization review and a Standard rerun.

## VM dependency verification

On 2026-10-17, a read-only SDK check of the shared InstaBox VM confirmed Python 3.13.5 with the required standard modules, `dig`, OpenSSL 3.5.7, `prlimit`, `flock`, and Docker daemon 29.8.2. The required images were present by their pinned OCI digests: ZAP `sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6`, Nuclei `sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb`, Trivy `sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`, and Gitleaks `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`. The current pinned cache needed no update. External tool integrations remain disabled in scan dispatch.

## Existing-system audit

The preserved working checkout already had a real 13-outcome HTTP/TLS collector, exact-target public-address checks and socket pinning, a serialized InstaBox queue, cancellation, resumable server events, atomic local report persistence, a private synthetic lab, inline findings and HTML/JSON downloads. Those components remain in use. No simulated scanner output was added.

The old runner/scanner.py also probes ports and sensitive files; runner/osint_engine.py probes discovered subdomains and can install tools. Neither is an approved Standard or Deep engine. The generic orchestration package and database adapter describe the earlier per-job VM design. The local API store/worker is the current application path. Their overlapping types and storage contracts are architectural debt; this change extends the existing local path rather than replacing functioning storage or enabling the legacy runner.

DNS TXT verification already existed, but the URL baseline did not require proof and had no bounded per-class active grant. It previously followed the conventional www/apex alias. New Standard and Deep jobs use strict exact-host redirects; even that alias requires a separately submitted target. Saved legacy reports retain their original provenance.

A read-only SDK inventory on 2026-10-17 confirmed Python 3.13.5, prlimit, flock, dig and OpenSSL on the shared VM, plus prepared ZAP 2.17.0, Nuclei 3.11.1, Trivy 0.76.0 and Gitleaks 8.30.1 images. Installed images are not implemented product checks. The existing Vault-bearing VM remains trusted infrastructure; customer code, arbitrary templates and unrestricted tool runners remain disabled.

## Execution and authorization

Standard Scan remains one URL submission, without DNS proof. It sends bounded ordinary GET requests to the exact host, checks its response and validated TLS connection, reads fixed public metadata and an explicitly referenced same-host HTML source map, and makes four bounded direct DNS lookups. It does not guess sensitive paths, crawl links or contact script/CDN destinations. The user submission records the existing exact-host attestation.

Deep Scan has a separate inline preparation flow. A browser-owned target receives a random DNS TXT challenge at `_shipsafe.HOST`. DNS verification is refreshed on consent creation, scan submission and actual queued dispatch. The backend issues a grant lasting at most 15 minutes, bounded by proof expiry, tied to the exact hostname and selected action classes. A checkbox alone cannot create a runnable Deep job. Grants and authorization references survive the local store restart. Persisted revision checks prevent an in-flight consent request from recreating a grant after revocation. A late VM launch response cannot overwrite a cancelled scan status.

Supported Deep classes are deliberately narrow:

| Class | Exact additional behavior |
| --- | --- |
| configuration | GET `/.git/HEAD`; only a bounded Git HEAD signature is reported, never its contents. Redirects, denied requests and ambiguous responses do not prove the repository is absent. |
| discovery | Read up to three distinct same-host links found in the returned HTML, without queries/fragments or following their redirects. Reject action-like paths and HTTPS downgrade. No recursive crawl. |
| cors | Send an uncredentialed GET with the fixed alternate Origin `https://shipsafe-origin.invalid`. Report response configuration only, without claiming authenticated data access. |

`GET /api/projects/ID/authorization` returns owner-only DNS instructions and the current grant. `POST` accepts only `{consent:true, classes:[...]}` with the supported unique classes and fresh proof. `DELETE` persists revocation, cancels queued Deep jobs and signals a running Deep job. Standard work is independent. `POST /api/scans` defaults to Standard; Deep also requires the matching authorizationId.

Authorization is checked before VM preparation, before process launch, before and after each output poll, and before storing results. The collector checks expiry before every HTTP request and after DNS resolution. The backend stops revoked work through its bounded polling/control channel; a request already in flight may finish before termination. No additional host is authorized by a redirect, link, DNS record or ownership proof.

## Limits and isolation

HTTP requests share a 20-request ceiling, a 40-second collector deadline, four-hop redirect bound, five-second connection/read timeouts, 32 KiB header limit and 64 KiB body limit per response. DNS address resolution is bounded and rejects mixed public/private answers; sockets connect to validated pinned addresses while TLS verifies the original hostname. There are four fixed dig lookups, at most two concurrently, each with a three-second subprocess timeout and bounded accepted output. DNS answers and metadata URLs never expand web scope.

The VM process receives a sanitized environment, a private job directory and fixed argv. prlimit caps address space at 256 MiB, CPU at 45 seconds, processes at 32, open files at 64 and output files at 1 MiB; an outer timeout caps execution at 50 seconds. The existing VM flock and single queue serialize jobs, below the provider's four-exec limit. Queue length and per-browser submission limits remain enforced. Process cleanup now sends TERM, escalates to KILL when needed and verifies no live process-group members remain before deleting job files. Container cleanup failure quarantines the worker across restarts.

This is trusted process isolation on the existing shared VM, not an OS-enforced per-target network namespace. Network policy is enforced by the only permitted collector and fixed DNS utility; arbitrary tools and customer code cannot use this path. Stronger independent egress enforcement and a credential-free container/VM design are required before adding external active scanners. The shared preparation VM is never killed after a job. This preserves the documented owner-directed single-VM runtime decision.

## Results and scoring

Each registered result carries stable check ID, category, title, definition version, severity, confidence, PASS/FAIL/WARNING/NOT_APPLICABLE/NOT_TESTED, redacted evidence, UTC timestamp, affected URL, impact explanation, safe retest guidance and remediation. Existing response checks retain their concrete remediation. The actual application stack is unavailable from these observations; remediation does not invent framework configuration paths. Context-dependent fixes require inspecting the owner's source/deployment.

All shipped outcomes are INFO hardening observations. No CVE, exploitable vulnerability, authenticated authorization failure or critical severity is inferred. There is no AI execution or AI promotion of hypotheses. The backend validates outputs against the trusted registry, rejects unknown/duplicate/missing results and unconsented Deep outcomes, and requires every finding to match an observed result. One result/finding per check deduplicates the current single-engine output; multi-tool fingerprint merging remains deferred with those integrations.

Posture is passed eligible checks divided by eligible applicable checks. NOT_TESTED earns no numerator credit; NOT_APPLICABLE is excluded. Pure inventories and metadata availability are excluded from posture. Coverage counts completed eligible observations, including a recorded warning/failure, rather than calling them passes. The backend recomputes metrics; it does not trust a guest-supplied score. A scope-limited redirect report has no full-profile score/coverage. The posture score is separate from CVSS and from the older confirmed-vulnerability scoring package. Legacy reports retain their versioned scoring behavior.

The UI and downloads expose unified statuses and limitations. Bodies, cookie values, source-map contents, script destinations and Git contents are omitted. HTML evidence remains escaped and exports retain owner isolation and no-store attachment headers.

## Exact implemented observations

Definitions: `packages/sandbox/src/security_registry.py` and its checked JSON export. Definitions declare authorization, scope, permitted methods/paths, budgets, evidence schema, severity/confidence rules and score eligibility. Registry parity is regression-tested.

| ID | Category | Observation | Mode |
| --- | --- | --- | --- |
| `https` | tls | Validated HTTPS connection | Standard and Deep |
| `https-redirect` | tls | HTTP upgrades to HTTPS | Standard and Deep |
| `hsts` | headers | HTTP Strict Transport Security | Standard and Deep |
| `csp` | headers | Content Security Policy | Standard and Deep |
| `framing` | headers | Framing restrictions | Standard and Deep |
| `nosniff` | headers | MIME sniffing restriction | Standard and Deep |
| `referrer` | headers | Referrer policy | Standard and Deep |
| `cookie-secure` | cookies | Cookie Secure attribute | Standard and Deep |
| `cookie-httponly` | cookies | Cookie HttpOnly attribute | Standard and Deep |
| `cookie-samesite` | cookies | Cookie SameSite attribute | Standard and Deep |
| `cors` | cors | CORS response observation | Standard and Deep |
| `error-disclosure` | configuration | Returned-page diagnostic markers | Standard and Deep |
| `http-response` | configuration | HTTP response received | Standard and Deep |
| `coop` | headers | Cross-Origin-Opener-Policy | Standard and Deep |
| `coep` | headers | Cross-Origin-Embedder-Policy | Standard and Deep |
| `corp` | headers | Cross-Origin-Resource-Policy | Standard and Deep |
| `permissions` | headers | Permissions Policy presence | Standard and Deep |
| `cache` | headers | Cache policy observation | Standard and Deep |
| `server-disclosure` | headers | Server version disclosure | Standard and Deep |
| `cookie-samesite-valid` | cookies | Cookie SameSite value | Standard and Deep |
| `cookie-domain` | cookies | Cookie domain scope | Standard and Deep |
| `cookie-path` | cookies | Cookie path scope | Standard and Deep |
| `cookie-lifetime` | cookies | Cookie lifetime observation | Standard and Deep |
| `cookie-prefix` | cookies | Cookie prefix requirements | Standard and Deep |
| `mixed-content` | frontend | Returned HTML insecure resource references | Standard and Deep |
| `script-inventory` | frontend | Returned HTML script inventory | Standard and Deep |
| `tls-expiry` | tls | Validated certificate expiry | Standard and Deep |
| `dns-public` | dns | Public DNS address validation | Standard and Deep |
| `security-txt` | metadata | Published security contact metadata | Standard and Deep |
| `robots-txt` | metadata | Published robots metadata | Standard and Deep |
| `sitemap-xml` | metadata | Published sitemap metadata | Standard and Deep |
| `library-inventory` | frontend | Returned HTML library version markers | Standard and Deep |
| `source-map` | frontend | Explicit returned-page source map reference | Standard and Deep |
| `dns-caa` | dns | DNS CAA record observation | Standard and Deep |
| `dns-spf` | dns | DNS SPF record observation | Standard and Deep |
| `dns-dmarc` | dns | DNS DMARC record observation | Standard and Deep |
| `dns-mx` | dns | DNS MX record observation | Standard and Deep |
| `deep-git-head` | configuration | Exposed Git HEAD signature | Verified Deep class |
| `deep-discovery` | discovery | Bounded same-host linked-page observation | Verified Deep class |
| `deep-cors` | cors | Uncredentialed Origin response observation | Verified Deep class |

The source-map check handles an explicit sourceMappingURL in returned HTML only. It does not fetch all linked JavaScript or guess map paths. Library marker counts are inventory, not reliable package attribution or CVE matching. Cookie scope and lifetime checks are attribute-review observations, not evidence of broken authentication. Narrow valid cookie paths and short expiry dates are not penalized. Compressed bodies that the collector cannot interpret receive NOT_TESTED for body analysis and discovery. Public metadata presence does not establish a vulnerability or improve posture.

## Explicitly deferred and unsupported capabilities

Every entry below is emitted as NOT_TESTED, never PASS. They have no approved executable methods/paths.

| ID | Capability |
| --- | --- |
| `dnssec` | DNSSEC chain validation |
| `certificate-transparency` | Certificate transparency history |
| `ocsp` | OCSP revocation status |
| `weak-tls` | Legacy TLS protocol negotiation |
| `tls-ciphers` | TLS cipher enumeration |
| `cve` | Maintained CVE feed correlation |
| `client-config` | Context-aware client configuration review |
| `injection` | Injection testing |
| `api` | API authorization and schema testing |
| `authentication` | Authentication and session testing |
| `jwt` | JWT validation testing |
| `csrf` | CSRF validation testing |
| `graphql` | GraphQL security testing |
| `zap` | OWASP ZAP integration |
| `nuclei` | Nuclei reviewed-template integration |

Also outside the implemented slice: HTTP-file/provider ownership verification, public subdomain/CT intelligence, complete certificate signature/chain diagnostics beyond the validated connection, full CSP semantic review, private API fixtures and multiple test identities, arbitrary configuration/backup/log/admin sweeps, directory-listing inference, complete browser-executed frontend analysis, persistent cross-tool finding history and stack-specific source patches. Trusted provider proof and HTTP verification need independent safe adapters. API/authentication/JWT/CSRF/GraphQL/business logic need reviewed fixtures and identities. Nuclei needs a pinned reviewed template allowlist; ZAP needs a controlled transport integration. No feed-backed CVE correlation is claimed.

Permanently excluded from the normal hosted scan path: DoS/resource exhaustion, brute force/password spraying/credential stuffing, destructive writes, RCE/persistence, data extraction, unrestricted crawling/port scans, unsafe protocol stress/races, and actions causing real payments/messages without isolated fixtures. Domain control does not enable these.

## Verification and release boundary

Run `bun run test`, `bun run typecheck`, `bun run test:security` and the web production build. Scanner tests use mocks and fixed owned loopback fixtures only. New tests cover proof/grant expiry, wrong host/ID, cross-owner access, revocation persistence and in-flight cancellation, DNS dispatch rechecks, class allowlists, report consistency, skipped-score handling, SSRF/redirect boundaries, response/resource limits and redaction. The same scanner suite ran in a network-disabled, read-only, resource-limited container on InstaBox, then verified container removal. No public target was scanned.

Browser verification exercised real local target preparation and DNS instructions, confirmed consent/start disabled before proof and zero queued scans, and checked desktop/mobile layout. Successful DNS consent and new public scanning were not exercised against a real target. The existing synthetic private-lab route remains separate and clearly labeled.

Cloudflare durable persistence/dispatch, production abuse controls, independent egress controls for general active tools and public multi-user deployment remain unfinished. This change is reviewable locally; it is not a deployment or a claim of complete vulnerability coverage.

Upstream references checked for scope: [OWASP WSTG](https://owasp.org/projects/web-security-testing-guide), [ZAP baseline behavior](https://www.zaproxy.org/docs/docker/baseline-scan/) and [Nuclei execution](https://docs.projectdiscovery.io/opensource/nuclei/running). ZAP's baseline starts a spider; its passive analyzer label does not make an unrestricted wrapper suitable for Standard Scan.
