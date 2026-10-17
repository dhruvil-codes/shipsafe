import Link from "next/link";
import HeroASCII from "@/components/HeroASCII";
import { Fingerprint, ScanLine, ShieldCheck } from "lucide-react";
import {
  Badge,
  ButtonLink,
  Logo,
  OraNav,
} from "@/components/product-ui";
import {
  FindingTabs,
  LimitsAccordion,
  ScanForm,
} from "@/components/landing";

type Grade = "Active Baseline" | "Deep Profile" | "Artifact Audit" | "Sandbox Test";

const GRADE_CLASS: Record<Grade, string> = {
  "Active Baseline": "g-green",
  "Deep Profile": "g-blue",
  "Artifact Audit": "g-blue",
  "Sandbox Test": "g-green",
};

const BOARD: { title: string; rows: { name: string; grade: Grade }[] }[] = [
  {
    title: "Perimeter & TLS",
    rows: [
      { name: "Security headers (CSP, HSTS, XFO)", grade: "Active Baseline" },
      { name: "TLS certificate & cipher suite", grade: "Active Baseline" },
      { name: "HTTPS redirect hygiene", grade: "Active Baseline" },
      { name: "MIME sniffing & framing defense", grade: "Active Baseline" },
      { name: "Referrer policy & COOP/COEP", grade: "Active Baseline" },
    ],
  },
  {
    title: "Cookies & Session",
    rows: [
      { name: "Secure & HttpOnly attributes", grade: "Active Baseline" },
      { name: "SameSite isolation (Strict/Lax)", grade: "Active Baseline" },
      { name: "__Host- & __Secure- prefixes", grade: "Active Baseline" },
      { name: "Session invalidation on logout", grade: "Deep Profile" },
      { name: "Session fixation & token replay", grade: "Deep Profile" },
    ],
  },
  {
    title: "API & Data Exposure",
    rows: [
      { name: "Stack trace & debug error leakage", grade: "Active Baseline" },
      { name: "CORS wildcard & origin reflection", grade: "Active Baseline" },
      { name: "Server banner & version disclosure", grade: "Active Baseline" },
      { name: "BOLA & Object authorization", grade: "Deep Profile" },
      { name: "Multi-tenant boundary isolation", grade: "Deep Profile" },
    ],
  },
  {
    title: "App & Integrations",
    rows: [
      { name: "Supabase / Postgres RLS review", grade: "Deep Profile" },
      { name: "Client-side secret & key leaks", grade: "Artifact Audit" },
      { name: "Payment webhook signature & replay", grade: "Sandbox Test" },
      { name: "Vulnerable dependencies & CVEs", grade: "Artifact Audit" },
      { name: "AI prompt injection & tool boundaries", grade: "Sandbox Test" },
    ],
  },
];

export default function HomePage() {
  return (
    <div className="ora">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <HeroASCII />
      <OraNav />
      <main id="main">
        <section className="ora-hero">
          <div className="hero-kicker"><ShieldCheck size={16} aria-hidden="true" /> Security, with evidence</div>
          <h1 className="ora-h1">
            <span className="reveal-line">
              <span>Ship fast.</span>
            </span>
            <span className="reveal-line hero-accent">
              <span>Know what&apos;s exposed.</span>
            </span>
          </h1>
          <p className="ora-sub">
            Security testing for SaaS developers. Scan your app, understand the
            risks, and verify your fixes.
          </p>
          <ScanForm variant="ora" />
          <hr className="ora-rule" />
          <div className="ora-stats mono">
            <span>
              <span className="n-ink">1</span> website URL
            </span>
            <span aria-hidden="true">·</span>
            <span>
              <span className="n-blue">0</span> integrations needed
            </span>
            <span aria-hidden="true">·</span>
            <span>
              <span className="n-green">100%</span> evidence first
            </span>
          </div>
          <p className="ora-note muted">
            Exact-host scope · Evidence with every finding
          </p>
        </section>

        <section id="coverage" className="ora-board-section">
          <div className="board-head">
            <h2>What a website scan can assess.</h2>
            <Link href="/#methodology" className="text-link">
              Methodology <span aria-hidden="true">→</span>
            </Link>
          </div>
          <div className="ora-board">
            {BOARD.map((column) => (
              <article key={column.title}>
                <h3>{column.title}</h3>
                <ol>
                  {column.rows.map((row, index) => (
                    <li key={row.name}>
                      <span className="mono">
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <span>{row.name}</span>
                      <span className={GRADE_CLASS[row.grade]}>
                        {row.grade}
                      </span>
                    </li>
                  ))}
                </ol>
              </article>
            ))}
          </div>
          <p className="small muted">
            ShipSafe verifies public perimeter resilience via zero-setup URL baseline scans, with deeper profiles for multi-tenant auth, database RLS, payment webhooks, and AI agent boundaries.
          </p>
        </section>

        <section id="live" className="ora-section">
          <h2>Inside a baseline assessment.</h2>
          <p>
            This static archived example shows the report format. It is separate
            from your target and is not a live scan.
          </p>
          <div className="transcript-label"><Badge tone="info">Static example</Badge><span className="mono">historical · URL baseline</span></div>
          <div
            className="terminal"
            role="log"
            aria-label="Recorded scan transcript"
          >
            <span className="stream-line">
              Example only · no live scan is running
            </span>
            <span className="stream-line">
              TLS · redirects · headers · cookies · CORS
            </span>
            <span className="stream-line">
              13 bounded HTTP/TLS checks in the URL baseline
            </span>
            <span className="stream-line">
              Exact hostname only · no exploits or subdomain discovery
            </span>
            <span className="stream-line stream-result">
              Live evidence and score appear here when your scan completes
            </span>
          </div>
          <ButtonLink href="/report/sample" secondary>
            See a sample report <span aria-hidden="true">→</span>
          </ButtonLink>
        </section>

        <section id="methodology" className="ora-section">
          <h2>A score without coverage is reassurance.</h2>
          <div className="metric-trio">
            <div className="metric">
              <ShieldCheck className="metric-icon" size={22} aria-hidden="true" />
              <h3>Score</h3>
              <p>
                Severity-weighted over assessed controls only. Any open
                Critical caps the display at 40.
              </p>
            </div>
            <div className="metric">
              <ScanLine className="metric-icon" size={22} aria-hidden="true" />
              <h3>Coverage</h3>
              <p>
                Assessed applicable controls ÷ applicable controls. Skipped or
                failed tests never raise it.
              </p>
            </div>
            <div className="metric">
              <Fingerprint className="metric-icon" size={22} aria-hidden="true" />
              <h3>Confidence</h3>
              <p>
                Quality and repeatability of the evidence behind each finding.
              </p>
            </div>
          </div>
          <LimitsAccordion
            items={[
              {
                q: "What counts as a pass?",
                a: "No weakness observed under the defined test — only after the check completes.",
              },
              {
                q: "What happens to skipped or failed tests?",
                a: "They remain untested and receive no coverage credit. This baseline does not assign an overall security score.",
              },
              {
                q: "Does this baseline test AI features?",
                a: "No. AI tool permissions, retrieval isolation and agent behavior require a separate authorized fixture and additional access.",
              },
              {
                q: "What authorizes a scan?",
                a: "Current domain-ownership verification plus explicit scope acceptance. Active testing needs separate approval.",
              },
            ]}
          />
        </section>

        <section className="ora-section ora-findings" aria-label="Sample findings">
          <h2>Sample findings.</h2>
          <p>Evidence and fixes from a recorded baseline.</p>
          <div className="finding-grid">
            <article className="finding-card panel">
              <Badge tone="warning">Medium</Badge>
              <h3>Content Security Policy is missing</h3>
              <p className="mono small muted">
                header content-security-policy · example.com
              </p>
              <FindingTabs
                href="/report/sample/findings/HEADER-CSP-MISSING"
                evidence="The recorded baseline found no Content-Security-Policy header. Historical summary; original response bytes unavailable."
                fix="Start with a report-only policy, review required resources, then enforce and retest."
              />
            </article>
            <article className="finding-card panel">
              <Badge tone="info">Low</Badge>
              <h3>X-Content-Type-Options header is missing</h3>
              <p className="mono small muted">
                header x-content-type-options · example.com
              </p>
              <FindingTabs
                href="/report/sample/findings/HEADER-XCTO-MISSING"
                evidence="The recorded baseline found no X-Content-Type-Options header. Historical summary; original response bytes unavailable."
                fix="Send X-Content-Type-Options: nosniff on HTML responses, then retest."
              />
            </article>
            <article className="finding-card panel">
              <Badge tone="warning">Medium</Badge>
              <h3>Strict-Transport-Security is missing</h3>
              <p className="mono small muted">
                header strict-transport-security · example.com
              </p>
              <FindingTabs
                href="/report/sample/findings/HEADER-HSTS-MISSING"
                evidence="The recorded baseline found no Strict-Transport-Security header. Historical summary; original response bytes unavailable."
                fix="Configure HSTS after verifying HTTPS coverage across the affected domains, then retest."
              />
            </article>
          </div>
        </section>

        <section className="ora-close">
          <h2>Not ready to ship?</h2>
          <p>Most teams aren&apos;t. Verify, scan, fix, retest.</p>
          <div className="hero-actions">
            <ButtonLink href="/#scan">Scan your app</ButtonLink>
            <ButtonLink href="/report/sample" secondary>
              See a sample report
            </ButtonLink>
          </div>
          <p className="small muted">
            Open your scan terminal. Keep every recorded result in view.
          </p>
        </section>
      </main>
      <footer className="ora-footer">
        <div>
          <Logo />
          <p>Security checks, with their limits in view.</p>
        </div>
        <nav aria-label="Footer">
          <Link href="/report/sample">Sample report</Link>
          <Link href="/data">Data &amp; privacy</Link>
          <Link href="/#scan-tree">Scan tree</Link>
        </nav>
        <p className="small muted">
          © 2026 ShipSafe · Scores are assessments, not certification. ·{" "}
          <a
            className="footer-credit"
            href="https://x.com/bydhruvil"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Built by @bydhruvil on X (opens in a new tab)"
          >
            Built by @bydhruvil
          </a>
        </p>
      </footer>
    </div>
  );
}
