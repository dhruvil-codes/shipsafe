import "../../styles/globals.css";

/** Route-group shell for the marketing + scan pages. Owns the top nav and footer. */
export default function AppGroupLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <header className="ss-nav ss-no-print">
        <div className="ss-container ss-nav-inner">
          <a className="ss-brand" href="/">
            <span className="ss-brand-mark" aria-hidden="true">
              S
            </span>
            ShipSafe
          </a>
          <nav className="ss-nav-links" aria-label="Primary">
            <a href="/">New scan</a>
            <a href="/scan/demo">Sample report</a>
          </nav>
        </div>
      </header>
      <main className="ss-main">
        <div className="ss-container">{children}</div>
      </main>
      <footer className="ss-footer ss-no-print">
        <div className="ss-container">
          ShipSafe — security testing for apps built at AI speed. Scores are
          assessments, not certifications.
        </div>
      </footer>
    </>
  );
}
