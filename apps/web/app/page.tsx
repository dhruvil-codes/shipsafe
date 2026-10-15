"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import DitherBackground from "../components/DitherBackground";
import LiveExhibit from "../components/LiveExhibit";
import Reveal from "../components/Reveal";
import SiteNav from "../components/SiteNav";
import ScanConsole from "../components/ScanConsole";
import ScanResults from "../components/ScanResults";
import type { VmStatus } from "../components/TerminalWindow";
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

const VM_LABEL: Record<VmStatus, string> = {
  ready: "VM ready",
  provisioning: "Provisioning",
  active: "Micro-VM active",
  executing: "Agent executing",
  "torn-down": "Torn down",
};

const ENGINES = [
  {
    name: "subfinder",
    href: "https://github.com/projectdiscovery/subfinder",
    body: "Passive subdomain enumeration across certificate transparency and DNS sources. Every name is probed live — none is trusted blind.",
  },
  {
    name: "httpx",
    href: "https://github.com/projectdiscovery/httpx",
    body: "Live-host probing with technology fingerprinting, status codes and server banners for each discovered subdomain.",
  },
  {
    name: "subzy",
    href: "https://github.com/PentestPad/subzy",
    body: "Subdomain-takeover detection against dangling records. A match is a critical finding with the fingerprint as evidence.",
  },
  {
    name: "checkdmarc",
    href: "https://github.com/domainaware/checkdmarc",
    body: "SPF and DMARC validation. Missing enforcement is a high finding; a permissive p=none policy is medium.",
  },
  {
    name: "whois",
    href: "https://github.com/rfc1036/whois",
    body: "Registration age, registrar and expiry. A domain expiring within 30 days is flagged before it can lapse.",
  },
  {
    name: "TLS prober",
    href: "/scan/demo",
    body: "Certificate validity, negotiated protocol and cipher suites, plus security headers, cookies, CORS and sensitive-file probes.",
  },
];

/**
 * One-page landing in the editorial blueprint language. The scan console in
 * the hero runs a real micro-VM scan; results render in-flow below it.
 */
export default function LandingPage() {
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
  const resultsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    document.title = "ShipSafe — ship fast, know what's exposed";
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
        failScan(`[ERROR] Failed to load scan results: ${(err as Error).message}`);
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
        failScan(`[ERROR] Failed to connect to InstaBox Micro-VM: ${(err as Error).message}`);
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
            setLines((prev) => [...prev, `[${ev.stage.toLowerCase()}] ${ev.message}`].slice(-MAX_LINES));
            setEngines((prev) => advanceEngines(prev, ev.stage, ev.message));
            if (/provision/i.test(ev.stage)) setVmStatus("provisioning");
            else if (/process/i.test(ev.stage)) setVmStatus("executing");
            else setVmStatus("active");
            break;
          case "stdout":
            if (ev.text) {
              settled = true;
              setLines((prev) => [...prev, ...ev.text.split("\n").filter((p) => p.length > 0)].slice(-MAX_LINES));
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
      requestAnimationFrame(() => {
        resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
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
        failScan(`[ERROR] Failed to connect to InstaBox Micro-VM: ${(err as Error).message}`);
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
    <div className="ds-page" id="top">
      <DitherBackground />
      <div className="ds-frame">
        <SiteNav />
        <main>
          <section className="ds-hero" aria-label="Introduction">
            <p className="ds-badge">
              Live disposable micro-VM scan
              <a href="#scan">Try now →</a>
            </p>
            <h1>Ship fast. Know what&rsquo;s exposed.</h1>
            <p className="ds-sub">
              Every scan runs on an isolated Linux micro-VM that streams each tool&rsquo;s output
              live — then turns genuine evidence into fixes, not guesses.
            </p>
            <ScanConsole scanning={scanning} onSubmit={(url) => void startScan(url)} />
          </section>

          {phase !== "idle" && (
            <div ref={resultsRef} className="ds-results-anchor">
              <ScanResults
                target={target}
                scanId={scanId}
                sandboxLabel={sandboxId}
                vmLabel={VM_LABEL[vmStatus]}
                lines={lines}
                engines={engines}
                findings={findings}
                osint={osint}
                score={score}
                coverage={coverage}
                capped={capped}
                error={error}
                scanning={scanning}
                onCancel={() => void cancelScan()}
              />
              <button type="button" className="ds-btn-quiet" onClick={reset}>
                Start over
              </button>
            </div>
          )}

          <section className="ds-section" id="how" aria-label="How it works">
            <Reveal>
              <h2>From URL to verified fixes in one sitting.</h2>
            </Reveal>
            <div className="ds-how">
              <div>
                <h3>Submit a URL</h3>
                <p>
                  Enter your app&rsquo;s address. Scope checks block private ranges and metadata
                  endpoints before anything runs — a scan starts only against a public target.
                </p>
              </div>
              <div>
                <h3>Watch the micro-VM work</h3>
                <p>
                  The runner executes pinned open-source scanners inside a disposable sandbox and
                  streams every line. The machine is torn down when the run ends, pass or fail.
                </p>
              </div>
              <div>
                <h3>Fix with evidence</h3>
                <p>
                  Each finding carries scanner output, severity and a copy-paste fix, plus one AI
                  prompt that bundles the whole report for your coding assistant.
                </p>
              </div>
            </div>
          </section>

          <section className="ds-section ds-section-tone" id="engines" aria-label="Scan engines">
            <Reveal>
              <h2>Real tools, pinned versions, raw output.</h2>
              <p className="ds-lede">
                No black boxes. The same binaries run on every scan and their stdout ships with the
                report.
              </p>
            </Reveal>
            <ul className="ds-engines-list">
              {ENGINES.map((e) => (
                <li key={e.name}>
                  <a href={e.href}>{e.name}</a>
                  <p>{e.body}</p>
                </li>
              ))}
            </ul>
          </section>

          <LiveExhibit />

          <section className="ds-section" aria-label="Guarantees">            <Reveal>
              <h2>What a score never claims.</h2>
            </Reveal>
            <div className="ds-guarantees">
              <p>
                <strong>Evidence first.</strong> A finding without scanner output does not exist.
              </p>
              <p>
                <strong>No credit for unrun checks.</strong> Skipped or failed tools never raise
                a score.
              </p>
              <p>
                <strong>Disposable compute.</strong> At most 5 micro-VMs, 4 concurrent commands,
                10 minutes per command — then teardown, always.
              </p>
            </div>
          </section>
        </main>
        <footer className="ds-footer">
          <p className="ds-footer-mark">ShipSafe</p>
          <p>
            Security testing for apps built at AI speed. Scores are assessments, never
            certifications. <a href="/scan/demo">Sample report</a>
          </p>
        </footer>
      </div>
    </div>
  );
}
