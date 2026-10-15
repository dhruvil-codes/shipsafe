"use client";

import { useMemo, useState } from "react";
import { buildAiFixPrompt, type EngineCheck, type OsintSummary, type UiFinding } from "../lib/scan-flow";

type ResultsTab = "findings" | "osint" | "raw";

const SEV_CLASS: Record<UiFinding["severity"], string> = {
  critical: "ds-sev-critical",
  high: "ds-sev-high",
  medium: "ds-sev-medium",
  low: "ds-sev-low",
  info: "ds-sev-info",
};

function FindingItem({ finding }: { finding: UiFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <article className="ds-finding">
      <button className="ds-finding-head" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className={`ds-sev ${SEV_CLASS[finding.severity]}`}>{finding.severity}</span>
        <span className="ds-finding-title">{finding.title}</span>
        <span className="ds-finding-toggle" aria-hidden="true">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="ds-finding-body">
          <p>{finding.summary}</p>
          <p className="ds-finding-meta">
            <code>{finding.affected}</code>
            {finding.cwe && (
              <>
                {" · "}<code>{finding.cwe}</code>
              </>
            )}
          </p>
          <h4>Evidence</h4>
          <pre className="ds-code">{finding.evidence}</pre>
          <h4>Fix</h4>
          <pre className="ds-code">{finding.fix}</pre>
        </div>
      )}
    </article>
  );
}

export interface ScanResultsProps {
  target: string;
  scanId: string | null;
  sandboxLabel: string;
  vmLabel: string;
  lines: string[];
  engines: EngineCheck[];
  findings: UiFinding[];
  osint: OsintSummary | null;
  score: number | null;
  coverage: number | null;
  capped: boolean;
  error: string | null;
  scanning: boolean;
  onCancel: () => void;
}

const ENGINE_GLYPH: Record<EngineCheck["state"], string> = {
  pending: "○",
  running: "◌",
  passed: "●",
  warning: "▲",
};

/** Live results in the editorial language: stream, checklist, score, fixes, OSINT. */
export default function ScanResults(props: ScanResultsProps) {
  const {
    target, scanId, sandboxLabel, vmLabel, lines, engines,
    findings, osint, score, coverage, capped, error, scanning, onCancel,
  } = props;
  const [tab, setTab] = useState<ResultsTab>("findings");
  const [copied, setCopied] = useState(false);
  const prompt = useMemo(() => buildAiFixPrompt(target, score, findings), [target, score, findings]);

  const groups = useMemo(() => {
    const order: UiFinding["severity"][] = ["critical", "high", "medium", "low", "info"];
    return order
      .map((sev) => ({ sev, items: findings.filter((f) => f.severity === sev) }))
      .filter((g) => g.items.length > 0);
  }, [findings]);

  const rawJson = useMemo(
    () => JSON.stringify({ scan_id: scanId, target, score, coverage, findings, osint }, null, 2),
    [scanId, target, score, coverage, findings, osint],
  );

  function downloadJson() {
    const blob = new Blob([rawJson], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shipsafe-report-${scanId ?? "scan"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="ds-results" aria-label="Live scan results">
      <div className="ds-results-head">
        <div>
          <p className="ds-results-target">{target}</p>
          <p className="ds-results-meta">
            {sandboxLabel} · {vmLabel}
            {scanId ? ` · scan ${scanId}` : ""}
          </p>
        </div>
        {scanning && !error && (
          <button type="button" className="ds-btn-quiet" onClick={onCancel}>
            Cancel scan
          </button>
        )}
      </div>

      {error && (
        <div className="ds-alert" role="alert">
          {error}
        </div>
      )}

      <div className="ds-live-grid">
        <div className="ds-stream" role="log" aria-label="Live VM output">
          {lines.length === 0 && <p className="ds-stream-dim">Booting the micro-VM…</p>}
          {lines.map((line, i) => (
            <p key={i} className="ds-stream-line">{line}</p>
          ))}
        </div>
        <ul className="ds-engines" aria-label="Engine checklist">
          {engines.map((e) => (
            <li key={e.id} className={`ds-engine ds-engine-${e.state}`}>
              <span className="ds-engine-glyph" aria-hidden="true">{ENGINE_GLYPH[e.state]}</span>
              <div>
                <p className="ds-engine-label">{e.label}</p>
                <p className="ds-engine-detail">{e.detail}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div className="ds-score-row">
        <div>
          <p className="ds-score-kicker">Assessed security</p>
          {score === null ? (
            <p className="ds-score-empty">Score unavailable — the worker has not reported results yet.</p>
          ) : (
            <>
              <p className="ds-score">
                {score}
                <span className="ds-score-of">/100</span>
              </p>
              <p className="ds-score-sub">
                Coverage {coverage ?? 0}% of applicable controls
                {capped ? " · capped at 40 by an open critical finding" : ""}
              </p>
            </>
          )}
        </div>
        <div className="ds-ai">
          <p className="ds-ai-kicker">One-click AI fix prompt</p>
          <pre className="ds-code ds-ai-body">{prompt}</pre>
          <button type="button" className="ds-btn-dark" onClick={() => void copyPrompt()}>
            {copied ? "Copied" : "Copy AI prompt"}
          </button>
        </div>
      </div>

      <div className="ds-tabs" role="tablist" aria-label="Result views">
        {(
          [
            { id: "findings", label: `Findings (${findings.length})` },
            { id: "osint", label: "Attack surface & OSINT" },
            { id: "raw", label: "Raw JSON" },
          ] as { id: ResultsTab; label: string }[]
        ).map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`ds-tab${tab === t.id ? " ds-tab-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "findings" && (
        <div>
          {groups.length === 0 && (
            <p className="ds-empty">
              {score === null
                ? "Findings appear here when the scan completes."
                : "No confirmed findings at any severity."}
            </p>
          )}
          {groups.map((g) => (
            <div key={g.sev}>
              <h3 className="ds-group-head">{g.sev}</h3>
              {g.items.map((f) => (
                <FindingItem key={f.id} finding={f} />
              ))}
            </div>
          ))}
        </div>
      )}

      {tab === "osint" && (
        <div>
          {!osint && (
            <p className="ds-empty">
              No OSINT evidence yet — the osint-suite stage (subfinder, httpx, subzy, checkdmarc, whois)
              populates this view.
            </p>
          )}
          {osint && (
            <>
              <h3 className="ds-group-head">Discovered subdomains</h3>
              <table className="ds-table">
                <thead>
                  <tr><th>Host</th><th>HTTP</th><th>Technology</th></tr>
                </thead>
                <tbody>
                  {osint.subdomains.map((s) => (
                    <tr key={s.host}>
                      <td><code>{s.host}</code></td>
                      <td>{s.status ?? "—"}</td>
                      <td>{s.tech}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <h3 className="ds-group-head">Email spoofing defense</h3>
              <p>DMARC — {osint.dmarc.status.toUpperCase()}: {osint.dmarc.detail}</p>
              <p>SPF — {osint.spf.status.toUpperCase()}: {osint.spf.detail}</p>
              <h3 className="ds-group-head">Domain health</h3>
              <p>
                Registrar: {osint.whois.registrar} · Expiry: {osint.whois.expiry} · Privacy:{" "}
                {osint.whois.privacy}
              </p>
            </>
          )}
        </div>
      )}

      {tab === "raw" && (
        <div>
          <pre className="ds-code ds-raw">{rawJson}</pre>
          <button type="button" className="ds-btn-dark" onClick={downloadJson}>
            Download JSON report
          </button>
        </div>
      )}
    </section>
  );
}
