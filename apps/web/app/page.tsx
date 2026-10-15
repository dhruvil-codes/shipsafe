"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import TerminalWindow, { type VmStatus } from "../components/TerminalWindow";
import CommandBar from "../components/CommandBar";
import TerminalStream from "../components/TerminalStream";
import ScanChecklist from "../components/ScanChecklist";
import AIFixPromptCard from "../components/AIFixPromptCard";
import FindingsViewer from "../components/FindingsViewer";
import {
  advanceEngines,
  buildDemoOsint,
  finalizeEngines,
  initialEngines,
  mapApiFindings,
  parseStreamPayload,
  type ApiFindingRecord,
  type EngineCheck,
  type OsintSummary,
  type ScanPhase,
  type UiFinding,
} from "../lib/scan-flow";
import {
  MOCK_COVERAGE,
  MOCK_FINDINGS,
  MOCK_LOGS,
  MOCK_SANDBOX_ID,
  MOCK_SCORE,
} from "../lib/mock";

const MAX_LINES = 500;

function pushLine(setLines: React.Dispatch<React.SetStateAction<string[]>>, line: string) {
  setLines((prev) => [...prev.slice(-MAX_LINES), line]);
}

function mockToUi(): UiFinding[] {
  return MOCK_FINDINGS.map((f) => ({
    id: f.id,
    severity: f.severity,
    title: f.title,
    summary: f.summary,
    affected: f.affected,
    evidence: f.evidence,
    fix: f.fix,
    source: "web" as const,
  }));
}

/**
 * Single-screen terminal experience: IDLE -> SCANNING -> COMPLETED.
 * No route changes during scanning — everything happens in this window.
 */
export default function HomeTerminal() {
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [target, setTarget] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [engines, setEngines] = useState<EngineCheck[]>(initialEngines);
  const [findings, setFindings] = useState<UiFinding[]>([]);
  const [osint, setOsint] = useState<OsintSummary | null>(null);
  const [score, setScore] = useState<number | null>(null);
  const [coverage, setCoverage] = useState<number | null>(null);
  const [sandboxId, setSandboxId] = useState(MOCK_SANDBOX_ID);
  const [vmStatus, setVmStatus] = useState<VmStatus>("ready");
  const [offline, setOffline] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timers = useRef<number[]>([]);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    document.title = "ShipSafe — live terminal scan";
    return () => {
      sourceRef.current?.close();
      timers.current.forEach((t) => window.clearTimeout(t));
    };
  }, []);

  const clearTimers = useCallback(() => {
    timers.current.forEach((t) => window.clearTimeout(t));
    timers.current = [];
  }, []);

  const reset = useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
    clearTimers();
    setPhase("idle");
    setTarget("");
    setScanId(null);
    setLines([]);
    setEngines(initialEngines());
    setFindings([]);
    setOsint(null);
    setScore(null);
    setCoverage(null);
    setSandboxId(MOCK_SANDBOX_ID);
    setVmStatus("ready");
    setOffline(false);
    setError(null);
  }, [clearTimers]);

  /** Offline fallback: clearly-labeled simulated stream ending in the sample report. */
  const runOfflineDemo = useCallback(
    (url: string) => {
      setOffline(true);
      setVmStatus("provisioning");
      let i = 0;
      const step = () => {
        if (i === 1) setVmStatus("active");
        if (i === 3) setVmStatus("executing");
        if (i < MOCK_LOGS.length) {
          const line = MOCK_LOGS[i];
          if (line !== undefined) {
            pushLine(setLines, line);
            setEngines((prev) => advanceEngines(prev, "RUNNING", line));
          }
          i += 1;
          timers.current.push(window.setTimeout(step, 300));
        } else {
          setEngines((prev) => finalizeEngines(prev));
          setFindings(mockToUi());
          setOsint(buildDemoOsint(url));
          setScore(MOCK_SCORE);
          setCoverage(MOCK_COVERAGE);
          setVmStatus("torn-down");
          setPhase("completed");
        }
      };
      pushLine(setLines, `$ shipsafe scan ${url}`);
      timers.current.push(window.setTimeout(step, 300));
    },
    [],
  );

  const finishFromApi = useCallback(
    async (id: string) => {
      try {
        const res = await fetch(`/api/scans/${id}`);
        if (!res.ok) throw new Error(`fetch failed (${res.status})`);
        const data = (await res.json()) as {
          scan?: { score?: number | null; coverage?: number | null };
          findings?: ApiFindingRecord[];
        };
        setScore(typeof data.scan?.score === "number" ? data.scan.score : null);
        setCoverage(typeof data.scan?.coverage === "number" ? data.scan.coverage : null);
        setFindings(mapApiFindings(data.findings ?? []));
        setOsint(null);
      } catch {
        setScore(null);
        setCoverage(null);
        setFindings([]);
        setOsint(null);
      } finally {
        setEngines((prev) => finalizeEngines(prev));
        setVmStatus("torn-down");
        setPhase("completed");
      }
    },
    [],
  );

  const streamFromApi = useCallback(
    (id: string, url: string) => {
      let settled = false;
      let source: EventSource;
      try {
        source = new EventSource(`/api/scans/${id}/stream`);
      } catch {
        runOfflineDemo(url);
        return;
      }
      sourceRef.current = source;
      const close = () => {
        source.close();
        if (sourceRef.current === source) sourceRef.current = null;
      };
      const handlePayload = (data: string) => {
        const ev = parseStreamPayload(data);
        switch (ev.kind) {
          case "sandbox":
            if (ev.sandboxId) setSandboxId(ev.sandboxId);
            break;
          case "vmstatus":
            break;
          case "log":
            settled = true;
            setOffline(false);
            pushLine(setLines, `[${ev.stage.toLowerCase()}] ${ev.message}`);
            setEngines((prev) => advanceEngines(prev, ev.stage, ev.message));
            if (/provision/i.test(ev.stage)) setVmStatus("provisioning");
            else if (/process/i.test(ev.stage)) setVmStatus("executing");
            else setVmStatus("active");
            break;
          case "result":
            if (typeof ev.score === "number") setScore(ev.score);
            if (typeof ev.coverage === "number") setCoverage(ev.coverage);
            break;
          case "done":
            close();
            void finishFromApi(id);
            break;
          case "line":
            if (ev.text) {
              settled = true;
              setOffline(false);
              pushLine(setLines, ev.text);
              setEngines((prev) => advanceEngines(prev, "", ev.text));
            }
            break;
        }
      };
      source.onmessage = (msg) => handlePayload(String(msg.data ?? ""));
      source.addEventListener("done", () => {
        close();
        void finishFromApi(id);
      });
      source.onerror = () => {
        if (!settled) {
          close();
          runOfflineDemo(url);
        }
      };
    },
    [finishFromApi, runOfflineDemo],
  );

  const startScan = useCallback(
    async (url: string) => {
      reset();
      setTarget(url);
      setPhase("scanning");
      setVmStatus("provisioning");
      pushLine(setLines, `$ shipsafe scan ${url}`);
      try {
        const res = await fetch("/api/scans", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ url }),
        });
        if (!res.ok) throw new Error(`scan request failed (${res.status})`);
        const data = (await res.json()) as { scanId?: string; scan_id?: string };
        const id = data.scanId ?? data.scan_id;
        if (!id) throw new Error("scan request returned no id");
        setScanId(id);
        setSandboxId(`sbx_live_${id.replace(/[^a-z0-9]/gi, "").slice(-10)}`);
        streamFromApi(id, url);
      } catch (err) {
        setScanId(null);
        setError(null);
        void err;
        runOfflineDemo(url);
      }
    },
    [reset, streamFromApi, runOfflineDemo],
  );

  const cancelScan = useCallback(async () => {
    if (!scanId || phase !== "scanning" || offline) return;
    try {
      await fetch(`/api/scans/${scanId}/cancel`, { method: "POST" });
      pushLine(setLines, "[cancel] cancellation requested — sandbox teardown initiated");
    } catch {
      // best effort; reconciler enforces teardown server-side
    }
  }, [scanId, phase, offline]);

  const scanning = phase === "scanning";
  const capped = score !== null && score <= 40 && findings.some((f) => f.severity === "critical");

  return (
    <TerminalWindow
      sandboxId={sandboxId}
      vmStatus={vmStatus}
      onNewScan={reset}
      scanning={scanning}
    >
      {phase === "idle" && (
        <>
          <p className="term-hero">
            Ship fast. Know what&apos;s exposed.
            <span className="term-hero-sub">
              Baseline security assessment in a disposable micro-VM — watch every
              tool run, live.
            </span>
          </p>
          <CommandBar scanning={false} onSubmit={(url) => void startScan(url)} />
        </>
      )}

      {phase !== "idle" && (
        <>
          <div className="term-scan-head">
            <span className="term-target">{target}</span>
            {scanId && <span className="term-scanid">scan {scanId}</span>}
            {scanning && !offline && (
              <button type="button" className="term-cancel" onClick={() => void cancelScan()}>
                Cancel scan
              </button>
            )}
          </div>

          {offline && (
            <div className="term-banner" role="status">
              <strong>Offline demo.</strong> The scan API is unreachable, so this
              run replays cached sample data.
            </div>
          )}
          {error && (
            <div className="term-banner term-banner-err" role="alert">
              {error}
            </div>
          )}

          <div className="term-split">
            <section aria-label="Live VM output">
              <TerminalStream lines={lines} />
            </section>
            <section aria-label="Engine checklist">
              <ScanChecklist items={engines} />
            </section>
          </div>

          {phase === "completed" && (
            <>
              <AIFixPromptCard target={target} score={score} findings={findings} />
              <FindingsViewer
                scanId={scanId ?? "demo"}
                target={target}
                score={score}
                coverage={coverage}
                capped={capped}
                findings={findings}
                osint={osint}
              />
            </>
          )}
        </>
      )}
    </TerminalWindow>
  );
}
