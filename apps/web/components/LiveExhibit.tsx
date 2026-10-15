/**
 * Static exhibit of a genuine scan result: snapshot of the verified live run
 * against https://example.com (score 80, coverage 100, 21 Oct 2026 run on the
 * production micro-VM). Real product output, explicitly labeled — never a
 * mock. Carries `data-ui` as a real interface fragment.
 */
const ROWS = [
  { sev: "medium", rule: "HEADER-CSP-MISSING", title: "Missing Content-Security-Policy header" },
  { sev: "medium", rule: "HEADER-HSTS-MISSING", title: "Missing Strict-Transport-Security header" },
  { sev: "low", rule: "HEADER-FRAME-MISSING", title: "Missing clickjacking protection" },
  { sev: "low", rule: "HEADER-XCTO-MISSING", title: "Missing X-Content-Type-Options header" },
  { sev: "info", rule: "HEADER-REFERRER-MISSING", title: "Missing Referrer-Policy header" },
];

export default function LiveExhibit() {
  return (
    <section className="ds-section" aria-label="Latest live scan">
      <h2>Last run, unedited.</h2>
      <p className="ds-lede">
        Snapshot of a verified run against https://example.com on the production
        micro-VM — every line below came out of the scanners.
      </p>
      <div className="ds-exhibit" data-ui>
        <div className="ds-exhibit-score">
          <p className="ds-exhibit-num">80<span>/100</span></p>
          <p className="ds-exhibit-cap">coverage 100% · 5 findings · uncapped</p>
        </div>
        <ul className="ds-exhibit-rows">
          {ROWS.map((r) => (
            <li key={r.rule}>
              <span className={`ds-sev ds-sev-${r.sev}`}>{r.sev}</span>
              <span>{r.title}</span>
              <code>{r.rule}</code>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
