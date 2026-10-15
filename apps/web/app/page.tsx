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

const MAX_LINES = 500;

function pushLines(
  setLines: React.Dispatch<React.SetStateAction<string[]>>,
  text: string,
) {
  const parts = text.split("\n");
  setLines((prev) => [...prev, ...parts.filter((p) => p.length > 0)].slice(-MAX_LINES));
}

/**
 * Single-screen terminal experience: IDLE -> SCANNING -> COMPLETED.
 * Pure Real Execution Mode: every scan runs on the live InstaBox micro-VM
 * via /api/scans + SSE. No mock generators, no demo replays — a failed VM
 * connection surfaces the exact error in the terminal.
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
  const [sandboxId, setSandboxId] = useState("sbx_pending");
  const [vmStatus, setVmStatus] = useState<VmStatus>("ready");
  const [error, setError] = useState<string | null>(null);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    document.title = "ShipSafe — live terminal scan";
    return () => {
      sourceRef.current?.close();
    };
  }, []);

  const reset = useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
    setPhase("idle");
    setTarget("");
    setScanId(null);
    setLines([]);
    setEngines(initialEngines());
    setFindings([]);
    setOsint(null);
    setScore(null);
    setCoverage(null);
    setSandboxId("sbx_pending");
    setVmStatus("ready");
    setError(null);
  }, []);

  /** Terminal failure: exact VM error in the stream, engines finalized, no replay. */
  const failScan = useCallback((message: string) => {
    setLines((prev) => [...prev.slice(-MAX_LINES), message]);
    setError(message);
    setEngines((prev) => finalizeEngines(prev));
    setVmStatus("torn-down");
  }, []);

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
      } catch (err) {
        failScan(
          `[ERROR] Failed to load scan results: ${(err as Error).message}`,
        );
        return;
      }
      setEngines((prev) => finalizeEngines(prev));
      setVmStatus("torn-down");
      setPhase("completed");
    },
    [failScan],
  );

  const streamFromApi = useCallback(
    (id: string) => {
      let settled = false;
      let source: EventSource;
      try {
        source = new EventSource(`/api/scans/${id}/stream`);
      } catch (err) {
        failScan(
          `[ERROR] Failed to connect to InstaBox Micro-VM: ${(err as Error).message}`,
        );
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
            setLines((prev) =>
              [...prev, `[${ev.stage.toLowerCase()}] ${ev.message}`].slice(-MAX_LINES),
            );
            setEngines((prev) => advanceEngines(prev, ev.stage, ev.message));
            if (/provision/i.test(ev.stage)) setVmStatus("provisioning");
            else if (/process/i.test(ev.stage)) setVmStatus("executing");
            else setVmStatus("active");
            break;
          case "stdout":
            if (ev.text) {
              settled = true;
              pushLines(setLines, ev.text);
              for (const line of ev.text.split("\n")) {
                if (line) setEngines((prev) => advanceEngines(prev, "", line));
              }
              setVmStatus("executing");
            }
            break;
          case "error":
            close();
            failScan(ev.message);
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
              setLines((prev) => [...prev, ev.text].slice(-MAX_LINES));
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
          failScan(
            `[ERROR] Failed to connect to InstaBox Micro-VM: event-stream to /api/scans/${id}/stream failed before any output`,
          );
        }
      };
    },
    [finishFromApi, failScan],
  );

  const startScan = useCallback(
    async (url: string) => {
      reset();
      setTarget(url);
      setPhase("scanning");
      setVmStatus("provisioning");
      setLines([`$ shipsafe scan ${url}`]);
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
        streamFromApi(id);
      } catch (err) {
        failScan(
          `[ERROR] Failed to connect to InstaBox Micro-VM: ${(err as Error).message}`,
        );
      }
    },
    [reset, streamFromApi, failScan],
  );

  const cancelScan = useCallback(async () => {
    if (!scanId || phase !== "scanning") return;
    try {
      await fetch(`/api/scans/${scanId}/cancel`, { method: "POST" });
      setLines((prev) =>
        [...prev, "[cancel] cancellation requested — sandbox teardown initiated"].slice(-MAX_LINES),
      );
    } catch {
      // best effort; reconciler enforces teardown server-side
    }
  }, [scanId, phase]);

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
              Baseline security assessment on a live disposable micro-VM — watch
              every tool run, line by line.
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
            {scanning && !error && (
              <button type="button" className="term-cancel" onClick={() => void cancelScan()}>
                Cancel scan
              </button>
            )}
          </div>

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
                scanId={scanId ?? "unknown"}
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
