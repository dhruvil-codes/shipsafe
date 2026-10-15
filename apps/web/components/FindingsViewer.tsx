"use client";

import { useMemo, useState } from "react";
import ScoreGauge from "./ScoreGauge";
import type { OsintSummary, UiFinding, UiSeverity } from "../lib/scan-flow";

type ViewerTab = "web" | "osint" | "raw";

const SEV_ORDER: UiSeverity[] = ["critical", "high", "medium", "low", "info"];

const SEV_BADGE: Record<UiSeverity, string> = {
  critical: "term-sev-critical",
  high: "term-sev-high",
  medium: "term-sev-medium",
  low: "term-sev-low",
  info: "term-sev-info",
};

function FindingRow({ finding }: { finding: UiFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <article className="term-finding">
      <button
        className="term-finding-head"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className={`term-sev ${SEV_BADGE[finding.severity]}`}>
          {finding.severity.toUpperCase()}
        </span>
        <span className="term-finding-title">{finding.title}</span>
        <span className="term-finding-toggle" aria-hidden="true">
          {open ? "[-]" : "[+]"}
        </span>
      </button>
      {open && (
        <div className="term-finding-body">
          <h4>Summary</h4>
          <p>{finding.summary}</p>
          <h4>Affected</h4>
          <p>
            <code>{finding.affected}</code>
          </p>
          {finding.cwe && (
            <>
              <h4>Reference</h4>
              <p>
                <code>{finding.cwe}</code>
              </p>
            </>
          )}
          <h4>Raw evidence</h4>
          <pre className="term-evidence">{finding.evidence}</pre>
          <h4>Recommended fix</h4>
          <pre className="term-fix">{finding.fix}</pre>
        </div>
      )}
    </article>
  );
}

interface FindingsViewerProps {
  scanId: string;
  target: string;
  score: number | null;
  coverage: number | null;
  capped: boolean;
  findings: UiFinding[];
  osint: OsintSummary | null;
}

function statusDot(status: "pass" | "fail" | "unknown"): string {
  return status === "pass" ? "term-osint-pass" : status === "fail" ? "term-osint-fail" : "term-osint-unknown";
}

/** COMPLETED-state tabs: web findings, OSINT recon, raw JSON. */
export default function FindingsViewer({
  scanId,
  target,
  score,
  coverage,
  capped,
  findings,
  osint,
}: FindingsViewerProps) {
  const [tab, setTab] = useState<ViewerTab>("web");

  const groups = useMemo(() => {
    const by: Record<UiSeverity, UiFinding[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: [],
    };
    for (const f of findings) by[f.severity].push(f);
    return SEV_ORDER.map((sev) => ({ sev, items: by[sev] })).filter((g) => g.items.length > 0);
  }, [findings]);

  function downloadJson() {
    const report = {
      scan_id: scanId,
      target,
      generated_at: new Date().toISOString(),
      score,
      coverage_percent: coverage,
      findings,
      osint,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shipsafe-report-${scanId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const rawJson = useMemo(
    () =>
      JSON.stringify(
        { scan_id: scanId, target, score, coverage_percent: coverage, findings, osint },
        null,
        2,
      ),
    [scanId, target, score, coverage, findings, osint],
  );

  return (
    <div className="term-viewer">
      <div className="term-tabs" role="tablist" aria-label="Results views">
        {(
          [
            { id: "web", label: "Web Vulnerabilities" },
            { id: "osint", label: "Attack Surface & OSINT Recon" },
            { id: "raw", label: "Raw Scan JSON" },
          ] as { id: ViewerTab; label: string }[]
        ).map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`term-tab${tab === t.id ? " term-tab-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "web" && (
        <div className="term-tabpanel">
          <div className="term-score-row">
            {score === null ? (
              <p className="term-empty">
                Score unavailable — the scan worker has not reported results yet.
                Failed or skipped checks never improve the score.
              </p>
            ) : (
              <ScoreGauge score={score} coverage={coverage ?? 0} capped={capped} />
            )}
          </div>
          {capped && (
            <div className="term-alert" role="alert">
              <strong>Critical finding open.</strong> The aggregate score is capped
              at 40 until it is resolved.
            </div>
          )}
          {groups.length === 0 && score !== null && (
            <p className="term-empty">No confirmed findings at any severity.</p>
          )}
          {groups.map((g) => (
            <div key={g.sev} className="term-sev-group">
              <h4 className="term-sev-head">
                {g.sev.toUpperCase()} ({g.items.length})
              </h4>
              {g.items.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          ))}
        </div>
      )}

      {tab === "osint" && (
        <div className="term-tabpanel">
          {!osint && (
            <p className="term-empty">
              No OSINT evidence returned for this scan yet. The osint-suite stage
              (subfinder, httpx, subzy, checkdmarc, whois) populates this view.
            </p>
          )}
          {osint && (
            <>
              <h4 className="term-osint-head">Discovered subdomains</h4>
              <div className="term-table-wrap">
                <table className="term-table">
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>HTTP</th>
                      <th>Technology</th>
                    </tr>
                  </thead>
                  <tbody>
                    {osint.subdomains.map((s) => (
                      <tr key={s.host}>
                        <td>
                          <code>{s.host}</code>
                        </td>
                        <td>{s.status ?? "—"}</td>
                        <td>{s.tech}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <h4 className="term-osint-head">Email spoofing defense</h4>
              <div className="term-osint-cards">
                <div className="term-osint-card">
                  <p className="term-osint-title">
                    <span className={`term-osint-dot ${statusDot(osint.dmarc.status)}`} aria-hidden="true" />
                    DMARC — {osint.dmarc.status.toUpperCase()}
                  </p>
                  <p className="term-osint-detail">{osint.dmarc.detail}</p>
                </div>
                <div className="term-osint-card">
                  <p className="term-osint-title">
                    <span className={`term-osint-dot ${statusDot(osint.spf.status)}`} aria-hidden="true" />
                    SPF — {osint.spf.status.toUpperCase()}
                  </p>
                  <p className="term-osint-detail">{osint.spf.detail}</p>
                </div>
              </div>
              <h4 className="term-osint-head">WHOIS & domain health</h4>
              <div className="term-osint-card">
                <p className="term-osint-detail">Registrar: {osint.whois.registrar}</p>
                <p className="term-osint-detail">Expiry: {osint.whois.expiry}</p>
                <p className="term-osint-detail">Privacy: {osint.whois.privacy}</p>
              </div>
            </>
          )}
        </div>
      )}

      {tab === "raw" && (
        <div className="term-tabpanel">
          <pre className="term-raw">{rawJson}</pre>
          <button type="button" className="term-ai-copy" onClick={downloadJson}>
            Download JSON Report
          </button>
        </div>
      )}
    </div>
  );
}
