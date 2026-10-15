"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import TelemetryBar, { type SandboxStatus } from "../../../../components/TelemetryBar";
import Terminal from "../../../../components/Terminal";
import Checklist, { type CheckItem } from "../../../../components/Checklist";
import ScoreGauge from "../../../../components/ScoreGauge";
import FindingCard from "../../../../components/FindingCard";
import {
  MOCK_COVERAGE,
  MOCK_FINDINGS,
  MOCK_LOGS,
  MOCK_SANDBOX_ID,
  MOCK_SCORE,
  type MockFinding,
  type Severity,
} from "../../../../lib/mock";

type Tab = "all" | Severity;

const TABS: { id: Tab; label: string }[] = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "high", label: "High" },
  { id: "medium", label: "Medium" },
  { id: "low", label: "Low" },
  { id: "info", label: "Info" },
];

const INITIAL_CHECKS: CheckItem[] = [
  { id: "tls", name: "TLS configuration", detail: "queued", state: "pending" },
  { id: "headers", name: "Security headers", detail: "queued", state: "pending" },
  { id: "files", name: "Sensitive files", detail: "queued", state: "pending" },
  { id: "ports", name: "Port scan", detail: "queued", state: "pending" },
];

function formatElapsed(totalSeconds: number): string {
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/** Split-screen live scan: Terminal (SSE) + Checklist, TelemetryBar, executive report. */
export default function ScanPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const isDemo = id === "demo";

  const [lines, setLines] = useState<string[]>([]);
  const [checks, setChecks] = useState<CheckItem[]>(INITIAL_CHECKS);
  const [status, setStatus] = useState<SandboxStatus>("provisioning");
  const [sandboxId, setSandboxId] = useState(MOCK_SANDBOX_ID);
  const [offline, setOffline] = useState(isDemo);
  const [done, setDone] = useState(false);
  const [findings, setFindings] = useState<MockFinding[]>([]);
  const [tab, setTab] = useState<Tab>("all");
  const [elapsed, setElapsed] = useState(0);
  const timers = useRef<number[]>([]);

  // Elapsed clock.
  useEffect(() => {
    if (done) return;
    const t = window.setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => window.clearInterval(t);
  }, [done]);

  // Drive the mock/offline simulation: stream MOCK_LOGS, advance checks, finish with the mock report.
  useEffect(() => {
    function startMockSimulation() {
      setOffline(true);
      setStatus("provisioning");
      let i = 0;
      const step = () => {
        if (i === 1) setStatus("active");
        if (i === 3) {
          setStatus("executing");
          setChecks((c) =>
            c.map((x) =>
              x.id === "tls" ? { ...x, state: "running", detail: "probing :443" } : x,
            ),
          );
        }
        if (i === 5) {
          setChecks((c) =>
            c.map((x) =>
              x.id === "tls"
                ? { ...x, state: "passed", detail: "TLS 1.2+ only, cert valid" }
                : x.id === "headers"
                  ? { ...x, state: "running", detail: "GET / headers" }
                  : x,
            ),
          );
        }
        if (i === 7) {
          setChecks((c) =>
            c.map((x) =>
              x.id === "headers"
                ? { ...x, state: "failed", detail: "CSP missing, HSTS max-age=600" }
                : x.id === "files"
                  ? { ...x, state: "running", detail: "probing /.git/HEAD, /.env" }
                  : x,
            ),
          );
        }
        if (i === 10) {
          setChecks((c) =>
            c.map((x) =>
              x.id === "files"
                ? { ...x, state: "passed", detail: "3/3 probes 404" }
                : x.id === "ports"
                  ? { ...x, state: "running", detail: "top 100 ports" }
                  : x,
            ),
          );
        }
        if (i < MOCK_LOGS.length) {
          const line = MOCK_LOGS[i];
          if (line !== undefined) setLines((prev) => [...prev.slice(-500), line]);
          i += 1;
          timers.current.push(window.setTimeout(step, 420));
        } else {
          setChecks((c) =>
            c.map((x) =>
              x.id === "ports"
                ? { ...x, state: "passed", detail: "80, 443 + unexpected 8080" }
                : x,
            ),
          );
          setFindings(MOCK_FINDINGS);
          setStatus("torn-down");
          setDone(true);
        }
      };
      timers.current.push(window.setTimeout(step, 420));
    }

    if (isDemo) {
      startMockSimulation();
      return () => {
        timers.current.forEach((t) => window.clearTimeout(t));
        timers.current = [];
      };
    }

    // Live mode: stream server-sent events; any failure falls back to the offline demo.
    let source: EventSource | null = null;
    let settled = false;
    try {
      source = new EventSource(`/api/scans/${id}/stream`);
      source.onopen = () => setOffline(false);
      source.onmessage = (ev) => {
        settled = true;
        setOffline(false);
        const text = String(ev.data ?? "");
        if (text.startsWith("__sandbox:")) {
          setSandboxId(text.slice("__sandbox:".length).trim() || MOCK_SANDBOX_ID);
        } else if (text.startsWith("__status:")) {
          const s = text.slice("__status:".length).trim() as SandboxStatus;
          if (s === "provisioning" || s === "active" || s === "executing" || s === "torn-down")
            setStatus(s);
        } else if (text.startsWith("__done")) {
          setDone(true);
          source?.close();
        } else if (text) {
          setLines((prev) => [...prev.slice(-500), text]);
        }
      };
      source.onerror = () => {
        if (!settled) {
          source?.close();
          startMockSimulation();
        }
      };
    } catch {
      startMockSimulation();
    }
    return () => {
      source?.close();
      timers.current.forEach((t) => window.clearTimeout(t));
      timers.current = [];
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, isDemo]);

  const counts = useMemo(() => {
    const c: Record<Tab, number> = {
      all: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of findings) c[f.severity] += 1;
    return c;
  }, [findings]);

  const visible = tab === "all" ? findings : findings.filter((f) => f.severity === tab);
  const hasCritical = findings.some((f) => f.severity === "critical");

  function exportJson() {
    const report = {
      scan_id: id,
      generated_at: new Date().toISOString(),
      score: MOCK_SCORE,
      coverage_percent: MOCK_COVERAGE,
      sandbox_id: sandboxId,
      findings,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shipsafe-report-${id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function cancelScan() {
    if (isDemo || done) return;
    try {
      await fetch(`/api/scans/${id}/cancel`, { method: "POST" });
    } catch {
      // best effort; reconciler enforces teardown server-side
    }
  }

  return (
    <>
      <div className="ss-live-head">
        <h1>Live scan</h1>
        <p className="ss-target">scan {id}</p>
        <div className="ss-meta-row">
          <span>elapsed {formatElapsed(elapsed)}</span>
          <span>{done ? "completed" : "running"}</span>
          {!done && !isDemo && (
            <button
              type="button"
              className="ss-btn ss-btn-ghost ss-no-print"
              onClick={() => void cancelScan()}
            >
              Cancel scan
            </button>
          )}
        </div>
      </div>

      {offline && (
        <div className="ss-banner" role="status">
          <strong>Offline demo.</strong> The scan API is unreachable, so this
          page is rendering cached sample data with a simulated live stream.
        </div>
      )}

      <TelemetryBar sandboxId={sandboxId} status={status} />

      <div className="ss-split">
        <section className="ss-panel" aria-label="Execution log">
          <Terminal lines={lines} />
        </section>
        <section className="ss-panel" aria-label="Verification checklist">
          <div className="ss-panel-head">
            <span>Control checklist</span>
          </div>
          <Checklist items={checks} />
        </section>
      </div>

      {(done || findings.length > 0) && (
        <section className="ss-exec" aria-label="Executive report">
          {hasCritical && (
            <div className="ss-banner ss-banner-rose" role="alert">
              <strong>Critical finding open.</strong> The aggregate score is
              capped at 40 until it is resolved.
            </div>
          )}
          <div className="ss-exec-grid">
            <div className="ss-panel">
              <ScoreGauge
                score={MOCK_SCORE}
                coverage={MOCK_COVERAGE}
                capped={hasCritical}
              />
            </div>
            <div className="ss-panel">
              <div className="ss-tabs ss-no-print" role="tablist" aria-label="Severity filter">
                {TABS.map((t) => (
                  <button
                    key={t.id}
                    role="tab"
                    aria-selected={tab === t.id}
                    className={`ss-tab${tab === t.id ? " ss-tab-active" : ""}`}
                    onClick={() => setTab(t.id)}
                  >
                    {t.label} ({counts[t.id]})
                  </button>
                ))}
              </div>
              <div className="ss-findings">
                {visible.length === 0 && (
                  <p className="ss-empty">
                    No findings at this severity. Failed or skipped checks never
                    improve the score.
                  </p>
                )}
                {visible.map((f) => (
                  <FindingCard key={f.id} finding={f} />
                ))}
              </div>
            </div>
          </div>
          <div className="ss-exec-actions ss-no-print">
            <button type="button" className="ss-btn" onClick={exportJson}>
              Export JSON
            </button>
            <button
              type="button"
              className="ss-btn ss-btn-ghost"
              onClick={() => window.print()}
            >
              Print / PDF
            </button>
          </div>
        </section>
      )}
    </>
  );
}
