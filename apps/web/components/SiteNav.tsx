"use client";

/** Plain top bar: wordmark, three links, one action. No chrome. */
export default function SiteNav() {
  return (
    <header className="ds-nav">
      <a className="ds-brand" href="#top" aria-label="ShipSafe home">
        <svg width="30" height="30" viewBox="0 0 30 30" aria-hidden="true">
          <circle cx="15" cy="15" r="13.5" fill="none" stroke="currentColor" strokeWidth="2.4" />
          <text
            x="15"
            y="20.5"
            textAnchor="middle"
            fontSize="14"
            fontWeight="700"
            fill="currentColor"
            fontFamily="Georgia, serif"
          >
            S
          </text>
        </svg>
        <span>ShipSafe</span>
      </a>
      <nav className="ds-nav-links" aria-label="Primary">
        <a href="#how">How it works</a>
        <a href="#engines">Engines</a>
        <a href="/scan/demo">Sample report</a>
      </nav>
      <a className="ds-btn-dark" href="#scan">
        Run a scan
      </a>
    </header>
  );
}
