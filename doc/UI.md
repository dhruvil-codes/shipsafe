# Current UI — URL-first scan flow

Local runtime follow-up (2026-10-16): the terminal follows real queued baseline jobs on the shared InstaBox VM. A bodyless private-lab action runs only the fixed owned fixture. Submitting a website URL immediately queues the URL baseline; a notice at the Scan action records the user's exact-host authorization attestation. There is no DNS setup form, consent checkbox, or ownership column. This is self-attestation rather than independent ownership proof. Reports show per-check outcomes, evidence, remediation, engine version, synthetic labeling, cleanup status and a versioned 13-check baseline score with coverage. Local file persistence restores browser-owned history, SSE reconnects/replays events, and completion focuses the report heading. Cloudflare deployment remains separate; see [LOCAL-RUNTIME.md](LOCAL-RUNTIME.md).

Updated 2026-10-16. This section supersedes the earlier route inventory below.

The landing URL field opens `components/InlineScan.tsx` in place. The browser
capability and internal target record are created behind the interface; no user
account, project name, environment or GitHub connection is requested. Submitting
the URL records exact-host authorization and immediately queues the baseline scan.
The notice at the field explains the attestation. Targets and recorded runs appear
in the scan tree.

The official Magic UI Terminal source and MIT license are in `components/magicui`.
The live view disables demo sequencing and renders received text immediately.
Preparation and server messages are labeled. No scanner results are
fabricated. Recorded results, evidence and fix prompts expand on the landing page.
Streams close on completion, cancellation, selection changes and unmount. An
interrupted stream never implies success; reconnection retrieves persisted status.

The scan tree groups exact hosts separately, including subdomains. Records persist
in the configured local file store, with memory as a fallback. There is no
cross-device identity or account recovery. `/?scan=ID#scan` restores an owned
recorded scan. Legacy `/scan/ID` redirects there; `/history` redirects to
`/#scan-tree`; projects, settings and login routes redirect to `/#scan`.

The configured local runtime uses a shared VM queue, bounded exact-host transport,
public-address validation, dispatch attestation checks and per-job cleanup. It
fails closed when the worker is unavailable. Cloudflare durable storage/dispatch
is not connected, so the current local worker is not a public production backend.

Archived samples remain separate exhibits and are labeled as historical examples.
URL-only coverage labels source, authenticated, database, payment and AI checks as
untested. The planned CLI promotion was removed from the landing page because it
is outside this flow.

---

# ShipSafe web interface

The application uses the Devin-derived reference system in Paper: https://app.paper.design/file/01M4ZRKJJBVEDQRJDHYFM0MT8E

## Visual rules

- Page `#FCFCFC`, wash `#F8F8F8`, elevated surfaces `#FFFFFF`, ink `#191919`, black primary actions.
- Inter regular for interface and marketing text; Geist Mono for technical content. Variable fonts are self-hosted with their OFL licenses in `apps/web/public/fonts/`.
- Display 64px; page titles 40px; body 16px; supporting text 14px. Mobile layouts reflow with 20px gutters and 44px controls.
- Fully rounded actions, 12px panels, light neutral borders. Functional color uses the reference system's darker accessible status mappings.
- Shared shell and controls: `apps/web/components/product-ui.tsx`. Product styling: `apps/web/styles/product.css`. The previous global stylesheet remains for compatibility with existing components.

## Routes

| Route | Purpose |
| --- | --- |
| `/` | Landing page with one-step URL scan, terminal, scan tree, coverage and archived report exhibit |
| `/projects`, `/projects/new`, `/projects/[id]` | Legacy routes redirect to the landing scan flow |
| `/projects/[id]/scan` | Legacy route redirects to the landing scan flow |
| `/scan/[id]` | Legacy route restores the recorded scan inline |
| `/report/[id]` | Recorded score, coverage, limitations, findings, JSON and browser printing |
| `/report/[id]/findings/[findingId]` | Evidence, remediation, copyable fix prompt and retest entry |
| `/report/sample` | Explicitly archived, log-backed example.com assessment |
| `/history` | Browser-owned scan history |
| `/settings` | Actual workspace capabilities, integration and storage status |
| `/login` | Browser-workspace entry; does not pretend to provide email authentication |
| `/data` | Operational data/storage disclosure for this build |

## Backend limits

Workspace capability cookies are random, HttpOnly and SameSite=Strict, with Secure on HTTPS. They identify a browser workspace, not a person. The local file store retains history when enabled; memory mode loses it on restart. Durable shared storage, account authentication and GitHub integration remain prerequisites for a hosted team product.

Each URL submission records a self-attested exact-host scope. This is not independent proof of ownership and is limited to the low-impact baseline. The API validates browser ownership of the internal target, records scope acceptance, applies queue and rate limits, and the worker rechecks that the stored target matches the attested hostname. The scanner restricts outbound requests to validated public addresses and same-host redirects.

The current live profile contains 13 bounded HTTP/TLS hardening checks. It does not invoke the prepared ZAP/Nuclei/Trivy/Gitleaks images for website submissions. Authenticated behavior, source/dependencies, data policies, payment flows and AI/MCP behavior remain untested without additional inputs. The local worker is not a Cloudflare storage/dispatch adapter; do not deploy this file-store/in-process queue as the public service.

## Verification

- Current URL-first changes pass the web TypeScript check, all 117 web tests and the optimized production build.
- Browser inspection of the local production preview confirms a single URL field and Scan action, no DNS challenge or separate consent checkbox, and the exact-host authorization notice. The historical sample is labeled static and separate from live results.
- No public target was submitted or scanned during this change. The local VM runner remains available only for targets the user is authorized to assess and for the fixed private lab fixture.

The landing-page inspector intentionally permits reference-system hairlines, technical mono, ordered workflow labels and one product exhibit on a short page. No footage was added because there is no honest product recording. Motion is limited to short entrances and control feedback, with a reduced-motion fallback. Small UI labels follow the reference system's 12px token; running prose stays at 16px.

## Site-wide UI polish (2026-10-16)

`styles/polish.css` loads after the compatibility styles and owns the current spacing, semantic color, responsive, and interaction refinements. It uses the reference's accessible blue for interaction and information, purple for source categories, green for completed checks, and amber for warnings; primary conversion actions remain black. Shared status badges apply the same mappings across pages.

`components/MotionEffects.tsx` observes visible regions once per route, including panels inserted after resource loading. It uses the native IntersectionObserver API and does not hide content before JavaScript runs. Grid entrances stagger by 55ms; region entrances last 300ms and feedback uses 150–200ms transitions. Reduced motion disables entrances, transitions, and smooth scrolling. Tab and accordion state correctness does not depend on animation completion.

The audit covered fifteen page states at desktop and mobile widths: landing, projects, project creation, DNS setup, project overview, scan configuration, archived report, finding detail, history, settings, workspace entry, data disclosure, missing scan/report, and 404 recovery. Live scan execution remains blocked; no live successful-scan UI was claimed or fabricated. Additional landing/report reflow checks passed at 320/768/1024. Final production screenshots and measured reduced-motion results are in ignored `.artifacts/full-ui-audit/production/`.

The hero includes the official React Bits `GradientASCII-JS-CSS` component, configured in `components/HeroASCII.tsx`. The native WebGL renderer is lazy-loaded; pixel ratio is capped at 1. The center mask preserves readable HTML content. The background runs automatically; reduced motion keeps a static rendering, and offscreen/hidden pages stop scheduling frames. The component's source, license, and local compatibility changes are documented in `components/react-bits/README.md`.
