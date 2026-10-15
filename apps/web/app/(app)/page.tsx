import type { Metadata } from "next";
import ScanBar from "../../components/ScanBar";

export const metadata: Metadata = {
  title: "ShipSafe — Ship fast. Know what's exposed.",
  description:
    "Security testing for SaaS developers. Scan your app, understand the risks, and verify your fixes.",
};

const FEATURES = [
  {
    tag: "F05 · BASELINE",
    title: "Passive web scan",
    body: "TLS, security headers, cookies, CORS and disclosure checks against your verified domain.",
  },
  {
    tag: "F06 · CODE AUDIT",
    title: "Evidence-backed findings",
    body: "Every finding ships with scanner output, severity, affected resource and a fix.",
  },
  {
    tag: "F04 · INSTABOX",
    title: "Disposable sandbox compute",
    body: "Each scan runs in an isolated micro-VM that is torn down when the run ends.",
  },
  {
    tag: "F13 · REPORTS",
    title: "Retest and verify",
    body: "Re-run the same controls after a fix and compare against the previous baseline.",
  },
];

const STEPS = [
  {
    tag: "01",
    title: "Submit your URL",
    body: "Enter your app URL. Ownership verification keeps testing authorized.",
  },
  {
    tag: "02",
    title: "Watch the live scan",
    body: "Follow the runner log, control checklist and sandbox telemetry in real time.",
  },
  {
    tag: "03",
    title: "Fix with evidence",
    body: "Read what is wrong, where, and what to change — then export the report.",
  },
];

/** Landing hero: headline, ScanBar, sample report, feature grid. */
export default function LandingPage() {
  return (
    <>
      <section className="ss-hero">
        <p className="ss-eyebrow">Baseline security assessment</p>
        <h1>Ship fast. Know what&apos;s exposed.</h1>
        <p className="ss-sub">
          Security testing for SaaS developers. Scan your app, understand the
          risks, and verify your fixes.
        </p>
        <div className="ss-scan-panel">
          <ScanBar />
        </div>
        <div className="ss-hero-ctas ss-no-print">
          <a className="ss-btn ss-btn-ghost" href="/scan/demo">
            See a sample report
          </a>
        </div>
      </section>

      <section aria-label="How it works">
        <div className="ss-steps">
          {STEPS.map((s) => (
            <div key={s.tag} className="ss-feature">
              <span className="ss-feature-tag">{s.tag}</span>
              <h3>{s.title}</h3>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section aria-label="Features">
        <div className="ss-feature-grid">
          {FEATURES.map((f) => (
            <div key={f.tag} className="ss-feature">
              <span className="ss-feature-tag">{f.tag}</span>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      <p className="ss-note">
        Demo build: with no API running, scans fall back to an offline sample
        report at <code>/scan/demo</code>. Scan compute is disposable — every
        sandbox is destroyed after the run, including on failure or cancel.
      </p>
    </>
  );
}
