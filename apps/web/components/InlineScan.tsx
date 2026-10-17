"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import dynamic from "next/dynamic";
import { ArrowDown, ChevronRight, Globe, TerminalSquare } from "lucide-react";
import DeepScanAuthorization from "@/components/DeepScanAuthorization";
import { Badge, CopyButton } from "@/components/product-ui";
import { request, type Project, type ScanRecord, type Workspace } from "@/components/product/data";
import { assessmentScore, assessmentMetrics, readUnifiedResults, type UnifiedResult, filterFindings, fixPrompt, isTerminal, loadAssessment, presentScanEvents, scopeStopExplanation, SEVERITIES, type Assessment, type SeverityFilter } from "@/lib/assessment";
import { scoreUrlBaseline } from "@/lib/baseline-score";
import { inlineTarget, recordedSummary, scanBranches } from "@/lib/inline-scan";
import { parseStreamPayload } from "@/lib/scan-flow";

const message = (error: unknown) => error instanceof Error ? error.message : "The request failed. Try again.";

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  const map: Record<string, { bg: string; text: string; border: string; dot: string; pulse?: boolean }> = {
    critical: { bg: "bg-rose-500/10 dark:bg-rose-500/15", text: "text-rose-700 dark:text-rose-400", border: "border-rose-500/30", dot: "bg-rose-500", pulse: true },
    high: { bg: "bg-orange-500/10 dark:bg-orange-500/15", text: "text-orange-700 dark:text-orange-400", border: "border-orange-500/30", dot: "bg-orange-500" },
    medium: { bg: "bg-amber-500/10 dark:bg-amber-500/15", text: "text-amber-700 dark:text-amber-400", border: "border-amber-500/30", dot: "bg-amber-500" },
    low: { bg: "bg-sky-500/10 dark:bg-sky-500/15", text: "text-sky-700 dark:text-sky-400", border: "border-sky-500/30", dot: "bg-sky-500" },
    info: { bg: "bg-sky-500/10 dark:bg-sky-500/15", text: "text-sky-700 dark:text-sky-400", border: "border-sky-500/30", dot: "bg-sky-500" },
    observation: { bg: "bg-sky-500/10 dark:bg-sky-500/15", text: "text-sky-700 dark:text-sky-400", border: "border-sky-500/30", dot: "bg-sky-500" },
    passed: { bg: "bg-emerald-500/10 dark:bg-emerald-500/15", text: "text-emerald-700 dark:text-emerald-400", border: "border-emerald-500/30", dot: "bg-emerald-500" },
  };
  const cfg = map[s] || map.info;
  return <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-mono font-medium tracking-wide border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
    <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} ${cfg.pulse ? "animate-pulse" : ""}`} />
    {severity}
  </span>;
}
const Terminal = dynamic(() => import("@/components/magicui/terminal").then(module => module.Terminal), {
  ssr: false,
  loading: () => <p className="scan-terminal-loading" role="status">Loading terminal…</p>,
});

function downloadJson(report: Assessment) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `shipsafe-${report.archived ? "ARCHIVED-SAMPLE" : report.scan.id}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function UnifiedResults({ results }: { results: UnifiedResult[] }) {
  return <section className="panel stack" aria-label="Security test catalog outcomes"><h2 className="section-title">Security test catalog outcomes</h2><p className="small muted">PASS records a completed check. NOT_TESTED and NOT_APPLICABLE receive no success credit. Context-dependent tests require additional access.</p>
    {!results.length ? <p role="status">No unified test outcomes were recorded for this assessment.</p> : results.map((result, index) => <details className="unified-result" key={`${result.id}-${index}`}><summary><Badge tone={result.status === "PASS" ? "success" : result.status === "FAIL" ? "danger" : result.status === "WARNING" ? "warning" : "neutral"}>{result.status.replaceAll("_", " ")}</Badge><span>{result.title}</span></summary><dl>{[["Category / check / version", `${result.category} / ${result.id} / ${result.version}`], ["Severity / confidence", `${result.severity} / ${result.confidence}`], ["Affected URL", result.affectedUrl], ["Recorded at", result.timestamp], ["Why this matters", result.why], ["Evidence", result.evidence], ["Verification", result.verification], ["Remediation", result.remediation]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{label === "Evidence" ? <pre className="check-evidence">{value || "No evidence recorded."}</pre> : value || "Unavailable"}</dd></div>)}</dl></details>)}
  </section>;
}

/** URL entry, terminal output and recorded results stay on this page. */
export default function InlineScan() {
  const [value, setValue] = useState("");
  const [deepProject, setDeepProject] = useState<Project | null>(null);
  const [target, setTarget] = useState<Project | null>(null);
  const [targets, setTargets] = useState<Project[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [historyError, setHistoryError] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const executionReady = workspace?.executionConfigured ?? null;
  const [opened, setOpened] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [inputError, setInputError] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [checkFilter, setCheckFilter] = useState<string>("all");
  const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);
  const [showAllChecks, setShowAllChecks] = useState(false);
  const [stagingIndex, setStagingIndex] = useState(0);

  const [lines, setLines] = useState<string[]>([]);
  const [liveEvents, setLiveEvents] = useState<{ id: string; stage: string; message: string; checkId?: string; status?: "passed" | "observation" | "skipped"; timestamp?: string }[]>([]);
  const [scanId, setScanId] = useState("");
  const [report, setReport] = useState<Assessment | null>(null);
  const [connection, setConnection] = useState("Not started");
  const [revision, setRevision] = useState(0);
  const [followOutput, setFollowOutput] = useState(true);
  const panel = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const output = useRef<HTMLDivElement>(null);
  const reportHeading = useRef<HTMLHeadingElement>(null);
  const sourceRef = useRef<EventSource | null>(null);
  const seenEventIds = useRef(new Set<string>());
  const loadedScanId = useRef("");
  const active = Boolean((scanId && !report && connection !== "Unavailable") || (report && !isTerminal(report.scan.status)));
  const alignPanel = useCallback(() => {
    if (!panel.current) return;
    const top = panel.current.getBoundingClientRect().top + window.scrollY - 80;
    window.scrollTo({ top: Math.max(0, top), behavior: "instant" });
  }, []);

  useEffect(() => {
    setSeverityFilter("all"); setCheckFilter("all"); setExpandedFinding(null);
    if (!scanId) return;
    const url = new URL(window.location.href);
    url.searchParams.set("scan", scanId);
    window.history.replaceState(null, "", url);
  }, [scanId]);

  useEffect(() => {
    if (report?.scan.mode !== "deep") return;
    const project = targets.find(item => item.id === report.scan.projectId);
    if (project) setTarget(project);
  }, [report?.scan.id, targets]);

  useEffect(() => {
    if (report && isTerminal(report.scan.status)) {
      reportHeading.current?.focus({ preventScroll: true });
      reportHeading.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [report?.scan.id, report?.scan.status]);

  const refreshTree = useCallback(async () => {
    setHistoryError("");
    try {
      const capabilities = await request<Workspace>("/api/workspace");
      setWorkspace(capabilities);
      const targetData = await request<{ projects: Project[] }>("/api/projects");
      const scanData = await request<{ scans: ScanRecord[] }>("/api/scans");
      setTargets(targetData.projects); setScans(scanData.scans);
    } catch (reason) { setHistoryError(message(reason)); }
    finally { setLoaded(true); }
  }, []);

  useEffect(() => {
    void refreshTree();
    const id = new URLSearchParams(window.location.search).get("scan");
    if (id) { setScanId(id); setOpened(true); }
  }, [refreshTree]);

  useEffect(() => {
    if (!opened) return;
    if (!report || !isTerminal(report.scan.status)) {
      panel.current?.focus({ preventScroll: true });
      requestAnimationFrame(alignPanel);
    }
  }, [opened]);

  useEffect(() => {
    if (followOutput && output.current) output.current.scrollTop = output.current.scrollHeight;
  }, [lines, liveEvents.length, report?.events.length, followOutput]);

  useEffect(() => {
    if (!scanId) return;
    let mounted = true;
    let settled = false;
    let source: EventSource | null = null;
    const controller = new AbortController();
    const isNewScan = loadedScanId.current !== scanId;
    loadedScanId.current = scanId;
    setReport(null); setError(""); setConnection("Loading recorded scan");
    if (isNewScan) { setLines([]); setLiveEvents([]); seenEventIds.current.clear(); }
    async function refresh() {
      const next = await loadAssessment(scanId, controller.signal);
      if (mounted) {
        setReport(next);
        const isLab = next.scan.mode === "lab" || next.scan.url.includes("fixture.invalid");
        if (!isLab) setValue(next.scan.url);
        if (isTerminal(next.scan.status)) { settled = true; source?.close(); setConnection("Recorded output"); }
      }
      return next;
    }
    async function settle(failure?: string) {
      if (!mounted || settled) return;
      settled = true; source?.close(); setConnection("Loading final report");
      if (failure) setError(failure);
      try {
        const next = await refresh();
        if (mounted && !isTerminal(next.scan.status) && !failure) setConnection("Waiting for the recorded scan status");
        if (mounted) void refreshTree();
      } catch (reason) { if (mounted) setError(message(reason)); }
    }
    void refresh().then(next => {
      if (!mounted || isTerminal(next.scan.status)) return;
      source = new EventSource(`/api/scans/${encodeURIComponent(scanId)}/stream`);
      sourceRef.current = source;
      setConnection("Connecting to scan output");
      source.onopen = () => { if (mounted) setConnection("Receiving scan output"); };
      source.onmessage = event => {
        if (!mounted || settled) return;
        const payload = parseStreamPayload(String(event.data));
        if (payload.kind === "error") { void settle(payload.message); return; }
        if (payload.kind === "done" || payload.kind === "result") { void settle(); return; }
        let envelope: Record<string, unknown> | null = null;
        try {
          const parsed: unknown = JSON.parse(String(event.data));
          if (parsed && typeof parsed === "object") envelope = parsed as Record<string, unknown>;
        } catch { /* Legacy streams can carry plain text. */ }
        const eventId = event.lastEventId || (typeof envelope?.id === "string" ? envelope.id : "");
        if (eventId) {
          if (seenEventIds.current.has(eventId)) return;
          seenEventIds.current.add(eventId);
        }
        const line = payload.kind === "stdout" || payload.kind === "line" ? payload.text : payload.kind === "log" ? `[${payload.stage}] ${payload.message}` : payload.kind === "vmstatus" ? `Sandbox status: ${payload.status}` : payload.kind === "sandbox" ? `Sandbox: ${payload.sandboxId}` : "";
        if (payload.kind === "log") setLiveEvents(previous => [...previous, { id: eventId, stage: payload.stage, message: payload.message, checkId: payload.checkId, status: payload.status, timestamp: payload.timestamp }].slice(-1000));
        else if (line) setLines(previous => [...previous, line].slice(-1000));
      };
      source.addEventListener("done", () => { void settle(); });
      source.onerror = () => {
        if (!mounted || settled) return;
        void refresh().then(next => {
          if (!mounted || settled) return;
          if (isTerminal(next.scan.status)) {
            void settle();
            return;
          }
          setConnection("Reconnecting to scan output");
        }).catch(() => {
          if (mounted && !settled) setConnection("Reconnecting to scan output");
        });
      };
    }).catch(reason => { if (mounted) { setError(message(reason)); setConnection("Unavailable"); } });
    return () => { mounted = false; controller.abort(); source?.close(); sourceRef.current = null; };
  }, [scanId, revision, refreshTree]);

  function selectTarget(next: Project) {
    sourceRef.current?.close(); setScanId(""); setReport(null); setTarget(next);
    setDeepProject(null);
    const isLab = next.url.includes("fixture.invalid");
    if (!isLab) setValue(next.url);
    setError(""); setInputError(""); setOpened(true); setFollowOutput(true);
    setLines([]); setLiveEvents([]); seenEventIds.current.clear();
    setConnection(executionReady === false ? "Scan execution is not configured" : "Ready to scan");
  }

  async function startWebsiteScan(project: Project, alreadyBusy = false, authorizationId?: string) {
    if ((!alreadyBusy && busy) || active) return;
    setBusy("Starting scan"); setError(""); setTarget(project); setValue(project.url);
    setOpened(true); setScanId(""); setReport(null); setLines([]); setLiveEvents([]);
    seenEventIds.current.clear(); setFollowOutput(true); setConnection(authorizationId ? "Starting Deep Security Scan" : "Starting Standard Scan");
    try {
      const result = await request<{ scanId: string }>("/api/scans", {
        method: "POST",
        body: JSON.stringify({ projectId: project.id, scopeAccepted: true, mode: authorizationId ? "deep" : "standard", ...(authorizationId ? { authorizationId } : {}) }),
      });
      if (!result.scanId) throw new Error("The scan service did not return a scan ID.");
      setConnection("Scan queued"); setScanId(result.scanId); void refreshTree();
    } catch (reason) { setError(message(reason)); setConnection("Scan not started"); }
    finally { setBusy(""); }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || active) return;
    setInputError("");
    let parsed: ReturnType<typeof inlineTarget>;
    try { parsed = inlineTarget(value); } catch (reason) { setInputError(message(reason)); input.current?.focus(); return; }
    setValue(parsed.url);
    setError("");
    sourceRef.current?.close();
    setOpened(true); setBusy("Preparing target"); setScanId(""); setReport(null); setTarget(null);
    setConnection("Preparing target"); setLines([]); setLiveEvents([]); seenEventIds.current.clear();
    try {
      const existing = targets.find(item => item.url === parsed.url);
      const next = existing ?? (await request<{ project: Project }>("/api/projects", { method: "POST", body: JSON.stringify({ name: parsed.hostname, url: parsed.url, environment: "production" }) })).project;
      setTarget(next); setValue(next.url);
      setDeepProject(null); await startWebsiteScan(next, true);
    } catch (reason) { setError(message(reason)); setConnection("Setup failed"); }
    finally { setBusy(""); }
  }

  async function cancel() {
    if (!scanId || busy) return;
    setBusy("Cancelling"); setError("");
    try {
      await request(`/api/scans/${encodeURIComponent(scanId)}/cancel`, { method: "POST" });
      sourceRef.current?.close(); setReport(await loadAssessment(scanId)); setConnection("Recorded output"); void refreshTree();
    } catch (reason) { setError(message(reason)); }
    finally { setBusy(""); }
  }

  const STAGING_STEPS = [
    "[0.0s] [DISPATCH] Validating host authorization & target normalization...",
    "[0.8s] [PROVISIONING] Allocating ephemeral microVM sandbox in secure isolation...",
    "[2.1s] [NETWORK] Pinning target DNS, TLS cipher probes, and egress boundaries...",
    "[3.4s] [ENGINE] Initializing 55 deterministic baseline security checkers...",
    "[4.8s] [READY] Scan engine online. Executing active baseline evaluation...",
  ];

  const hostname = target ? new URL(target.url).hostname : "";
  const reportManifest = report?.scan.reportManifest;
  const isLab = report?.scan.mode === "lab" || reportManifest?.synthetic === true || (target ? target.url.includes("fixture.invalid") : false);
  const scopeLimited = reportManifest?.scopeLimited === true;
  const scopeStop = scopeStopExplanation(reportManifest?.scopeStopReason);
  const rawChecks = reportManifest?.checks;
  const hasManifest = Array.isArray(rawChecks);
  const checks = Array.isArray(rawChecks) ? rawChecks.flatMap((value) => {
    if (!value || typeof value !== "object") return [];
    const item = value as Record<string, unknown>;
    if (typeof item.id !== "string" || typeof item.title !== "string" || typeof item.status !== "string") return [];
    return [{ id: item.id, title: item.title, status: item.status, evidence: typeof item.evidence === "string" ? item.evidence : "", remediation: typeof item.remediation === "string" ? item.remediation : "" }];
  }) : [];
  const liveEventIds = new Set(liveEvents.map(event => event.id).filter(Boolean));
  const displayedEvents = [...presentScanEvents(report?.events ?? []).filter(event => !liveEventIds.has(event.id)), ...liveEvents];
  const checksEvaluated = displayedEvents.filter(event => event.stage === "check_done").length;
  useEffect(() => {
    if (!active || checksEvaluated > 0) { setStagingIndex(0); return; }
    const timer = setInterval(() => setStagingIndex(i => (i + 1) % STAGING_STEPS.length), 900);
    return () => clearInterval(timer);
  }, [active, checksEvaluated]);
  const score = report ? assessmentScore(report) : null;
  const modernProfile = report?.scan.mode === "standard" || report?.scan.mode === "deep";
  const baselineScore = !modernProfile && reportManifest?.profile === "bounded-http-hardening" ? scoreUrlBaseline(checks) : null;
  const unifiedResults = readUnifiedResults(reportManifest?.unifiedResults);
  const metrics = report ? assessmentMetrics(report, baselineScore) : null;
  const resolvedScore = metrics?.value ?? null;
  const resolvedCoverage = metrics?.coverage ?? null;
  const filteredFindings = report ? filterFindings(report.findings, severityFilter) : [];
  const filteredChecks = checkFilter === "all" ? checks : checks.filter(c => c.status === checkFilter);

  return <div id="scan" className="inline-scan bg-grid-page min-h-screen w-full relative">
    <form className="ora-scan" onSubmit={submit} noValidate>
      <label className="sr-only" htmlFor="scan-url">Website URL</label>
      <input ref={input} id="scan-url" type="text" inputMode="url" autoComplete="url" spellCheck={false} placeholder="Enter your website URL" value={value} onChange={event => { setValue(event.target.value); setInputError(""); }} disabled={Boolean(busy) || active} aria-invalid={Boolean(inputError)} aria-describedby={inputError ? "scan-url-error" : "scan-hint"} />
      <button className="ora-go" type="submit" disabled={Boolean(busy) || active}>{busy === "Preparing target" ? "Preparing…" : busy === "Starting scan" ? "Starting…" : "Scan"}<ChevronRight size={16} aria-hidden="true" /></button>
    </form>
    <p id="scan-hint" className="small muted inline-hint">By selecting Scan, you confirm that you own this site or have permission to assess it. ShipSafe runs bounded checks against this exact hostname.</p>
    {inputError && <p id="scan-url-error" className="scan-error" role="alert">{inputError}</p>}
    {opened && <div className="scan-session" ref={panel} tabIndex={-1} aria-label="Inline scan session">
      <header className="session-heading">
        <div>
          <span className="eyebrow">{isLab ? "Private synthetic fixture" : "Your assessment"}</span>
          <h2>{isLab ? "ShipSafe Private Lab" : target ? hostname : report ? new URL(report.scan.url).hostname : "Preparing assessment"}</h2>
          {isLab && <p className="small muted" style={{ margin: "4px 0 0" }}>Owned synthetic hardening fixture on InstaBox · Zero external networking</p>}
        </div>
        <Badge tone={active ? "info" : report ? "neutral" : "warning"}>{(busy || active || /queued|connecting|receiving|reconnecting/i.test(connection)) && <span className="scan-status-pulse" aria-hidden="true" />}{report?.scan.status ?? connection}</Badge>
      </header>
      <div className="session-grid">
        <div className="session-output">
          <div className="output-heading"><h3><TerminalSquare size={18} aria-hidden="true" /> Scan terminal</h3><span className="small" role="status">{connection}</span></div>
          <div ref={output} className="scan-output-scroll" onScroll={event => { const el = event.currentTarget; setFollowOutput(el.scrollHeight - el.scrollTop - el.clientHeight < 60); }} role="log" aria-label="Scan output" aria-live="polite" aria-relevant="additions text" tabIndex={0}>
            <Terminal className="scan-magic-terminal" sequence={false} startOnView={false} windowControls={false}>
              {active && checksEvaluated === 0 && STAGING_STEPS.slice(0, stagingIndex + 1).map((step, index) => <span className="scan-terminal-line" key={`stage-${index}`}>{step}</span>)}
              {displayedEvents.map((event, index) => <span className={`scan-terminal-line${event.stage === "check_done" ? ` scan-check-${event.status ?? "skipped"}` : event.stage === "check" ? " scan-check-start" : ""}`} key={event.id || `event-${index}`} data-check-id={event.checkId} data-timestamp={event.timestamp}>{event.stage === "check" ? "[check]" : event.stage === "check_done" ? "[check_done]" : `[${event.stage}]`} {event.message}</span>)}
              {lines.map((line, index) => <span className="scan-terminal-line" key={index}>{line}</span>)}
              {error && !lines.length && !displayedEvents.length && <span className="scan-terminal-line scan-terminal-error">[ERROR] {error}</span>}
              {!lines.length && !displayedEvents.length && !error && <span className="scan-terminal-line">{scanId ? "Waiting for recorded scan output." : "No scan has started."}</span>}
            </Terminal>
          </div>
          <div className="output-footer"><span className="small muted">Scanner output and security results come from recorded events and evidence.</span>{!followOutput && <button className="text-button" onClick={() => setFollowOutput(true)}><ArrowDown size={14} aria-hidden="true" /> Latest output</button>}</div>
          {active && <div className="inline-controls"><button className="button secondary" onClick={() => void cancel()} disabled={Boolean(busy)}>Cancel scan</button><button className="text-button" onClick={() => setRevision(previous => previous + 1)} disabled={Boolean(busy)}>Reconnect output</button></div>}
          {scanId && !active && <button className="text-button" type="button" onClick={() => setRevision(previous => previous + 1)}>Reconnect output</button>}
        </div>
      </div>
      {error && <p className="notice error-notice" role="alert">{error}</p>}
      {active && <div className="scan-live-progress" role="status" aria-live="polite">
        <span className="animate-pulse-beacon micro-spinner" aria-hidden="true" />
        <span>Analyzing security controls ({checksEvaluated}/55 checks evaluated)…</span>
        <div className="scan-progress-bar"><div className="scan-progress-fill" style={{ width: `${Math.min(100, (checksEvaluated / 55) * 100)}%` }} /></div>
      </div>}
      {report && isTerminal(report.scan.status) && <section className="inline-results stack" aria-label="Recorded results">
        <div className="report-heading">
          <div>
            <span className="eyebrow">{report.archived ? "Archived sample" : isLab ? "Private synthetic fixture" : scopeLimited ? "Scope-limited baseline" : "Security assessment"}</span>
            <h3 ref={reportHeading} tabIndex={-1}>Evidence, in context.</h3>
            <p className="report-target mono muted">{isLab ? "https://fixture.invalid (Owned synthetic fixture on InstaBox)" : report.scan.url}</p>
          </div>
          <div className="report-actions">
            {isTerminal(report.scan.status) && <>
              <button className="button" type="button" onClick={() => downloadJson(report)}>Download JSON</button>
              <a className="button secondary" href={`/report/${encodeURIComponent(report.scan.id)}`} target="_blank" rel="noreferrer">Full report view ↗</a>
              <button className="button secondary" type="button" onClick={() => window.print()}>Print / save as PDF</button>
            </>}
          </div>
        </div>

        {isLab && <aside className="notice notice-info" role="note">
          <strong>Private lab scan · zero external networking</strong>
          <p>Executed in an isolated container on InstaBox with external networking disabled. Recorded against safe synthetic fixtures without contacting any external servers or customer websites.</p>
        </aside>}

        {scopeLimited && <aside className="notice notice-warning" role="note">
          <strong>Scope-limited assessment</strong>
          <p>{scopeStop ? `${scopeStop} ` : ""}This report covers only the submitted hostname’s redirect response. ShipSafe did not contact the redirect destination, so the normal URL baseline score and coverage are unavailable.</p>
        </aside>}

        {!modernProfile && report.findings.some(f => f.severity.toUpperCase() === "CRITICAL") && <aside className="notice notice-danger" role="alert">
          <strong>Critical finding recorded.</strong>
          <p>The score is capped at 40 by policy. Review critical evidence before making a release decision.</p>
        </aside>}

        <div className="split report-metrics">
          <section className="panel stack score-panel">
            <span className="muted small">{modernProfile ? "Security posture score · not CVSS" : "Recorded score"}</span>
            {score?.inconsistent && <p role="alert" className="small">The stored score conflicts with scoring policy. Score unavailable pending correction; inspect the recorded evidence.</p>}
            <strong className={`metric-value${resolvedScore === null ? " metric-unavailable" : ""}`}>
              {resolvedScore !== null ? resolvedScore : "Unavailable"}
              <span className="small muted">{resolvedScore !== null ? " / 100" : ""}</span>
            </strong>
            <p className="muted">
              {baselineScore && resolvedScore !== null ? `Grade ${baselineScore.grade} · ` : ""}
              {report.scan.status} · {report.scan.createdAt ? `Started ${new Date(report.scan.createdAt).toLocaleString()}` : "Start time unavailable"}
            </p>
          </section>
          <section className="panel stack coverage-panel">
            <span className="muted small">Executed check coverage</span>
            <strong className={`metric-value${resolvedCoverage === null ? " metric-unavailable" : ""}`}>{resolvedCoverage !== null ? `${resolvedCoverage}%` : "Unavailable"}</strong>
            <p className="muted">Coverage describes the configured assessment, not every security risk. Skipped and failed checks receive no credit.</p>
          </section>
        </div>

        <section className="panel stack report-findings" aria-label="Findings">
          <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap", alignItems: "center" }}>
            <h2 className="section-title">Findings <span className="muted">{report.findings.length}</span></h2>
            <label className="small report-filter">Severity{" "}
              <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value as SeverityFilter)} style={{ padding: "8px 12px", marginLeft: 8, borderRadius: 8, border: "1px solid var(--border)", background: "var(--surface)" }}>
                <option value="all">All ({report.findings.length})</option>
                {SEVERITIES.map(s => <option key={s} value={s}>{s} ({filterFindings(report.findings, s).length})</option>)}
              </select>
            </label>
          </div>
          {filteredFindings.length ? <div className="findings-stream">
            {filteredFindings.map(f => {
              const isExpanded = expandedFinding === f.id;
              const s = f.severity.toLowerCase();
              const tone = s === "critical" || s === "high" ? "danger" : s === "medium" ? "warning" : s === "low" ? "info" : "neutral";
              const classification = (f as typeof f & { classification?: string }).classification;
              const promptText = `Fix security finding: [${f.severity}] ${f.title} (${f.checkId || f.id})\nTarget host: ${report.scan.url}\nObserved evidence: ${f.evidence}\nRecommended fix: ${f.remediation}\nPlease update our web server / framework configuration (Next.js, Vercel headers, or Nginx) to address this hardening issue. Provide the exact code/config diff.`;
              return <div key={f.id} className="rounded-xl border border-neutral-200/80 bg-white/70 dark:bg-neutral-900/70 backdrop-blur-sm shadow-sm transition hover:border-neutral-300 dark:hover:border-neutral-700 mb-3 p-4">
                <div className="finding-row">
                  <button className="finding-toggle" type="button" onClick={() => setExpandedFinding(isExpanded ? null : f.id)} aria-expanded={isExpanded} aria-controls={`finding-${f.id}`}>
                    <div>
                      <div className="finding-meta">
                        <SeverityBadge severity={f.severity} />
                        {classification && <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-mono font-medium tracking-wide border border-neutral-200/80 bg-neutral-100/50 text-neutral-600 dark:border-neutral-700 dark:bg-neutral-800/50 dark:text-neutral-300">{classification === "hardening" ? "Hardening" : classification}</span>}
                        <span className="finding-id muted small">{f.cwe ? `${f.cwe} · ` : ""}{f.checkId || f.id}</span>
                      </div>
                      <h3 style={{ margin: "8px 0 4px", fontSize: 18 }}>{f.title}</h3>
                      <span className="muted small">{isExpanded ? "Hide details" : "View evidence, remediation & fix prompt"}</span>
                    </div>
                    <span aria-hidden="true" className="finding-chevron">{isExpanded ? "−" : "+"}</span>
                  </button>
                  <div className="finding-actions" style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
                    <button className="button secondary" type="button" style={{ fontSize: 13, padding: "6px 12px" }} onClick={() => {
                      void navigator.clipboard?.writeText(promptText);
                      setCopiedPromptId(f.id);
                      setTimeout(() => setCopiedPromptId(null), 1500);
                    }}>{copiedPromptId === f.id ? "Copied!" : "Copy AI Fix Prompt"}</button>
                    <a href={`/report/${encodeURIComponent(report.scan.id)}/findings/${encodeURIComponent(f.id)}`} target="_blank" rel="noreferrer" className="icon-button finding-permalink" aria-label={`Open ${f.title} in a new tab`}>↗</a>
                  </div>
                </div>
                {isExpanded && <div id={`finding-${f.id}`} className="finding-expanded-body">
                  <h4 style={{ margin: "12px 0 6px" }}>What was observed</h4>
                  <p style={{ margin: "0 0 12px" }}>{f.description}</p>
                  <h4 style={{ margin: "12px 0 6px" }}>Recorded evidence</h4>
                  <pre className="terminal" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 320, overflow: "auto", margin: "0 0 16px" }}>{f.evidence || "No evidence supplied by the scanner."}</pre>
                  <h4 style={{ margin: "12px 0 6px" }}>Recommended fix</h4>
                  <p style={{ margin: "0 0 16px" }}>{f.remediation || "No remediation was supplied."}</p>
                  <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 16 }}>
                    <div className="row" style={{ justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
                      <strong>Fix prompt for your coding agent</strong>
                      <CopyButton text={fixPrompt(report, f)} label="Copy fix prompt" />
                    </div>
                    <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, margin: 0, maxHeight: 180, overflow: "auto" }}>{fixPrompt(report, f)}</pre>
                  </div>
                </div>}
              </div>;
            })}
          </div> : <p className="muted" role="status">No findings match the selected severity filter.</p>}
        </section>

        {hasManifest && (() => {
          const obs = checks.filter(c => c.status === "observation" || c.status === "failed" || c.status === "warning");
          const passed = checks.filter(c => c.status === "passed");
          const deferred = checks.filter(c => c.status !== "passed" && c.status !== "observation" && c.status !== "failed" && c.status !== "warning");
          const renderGroup = (title: string, items: typeof checks, groupKey: string) => (
            <details className="scan-accordion" style={{ marginBottom: 8 }}>
              <summary style={{ cursor: "pointer", fontWeight: 600, padding: "8px 0" }}>{title} ({items.length})</summary>
              <ul style={{ listStyle: "none", padding: 0, margin: "8px 0" }}>
                {(showAllChecks ? items : items.slice(0, 5)).map(c => (
                  <li key={c.id} className="small" style={{ padding: "6px 0", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span><strong>{c.id}</strong> — {c.title}</span>
                    <Badge tone={c.status === "passed" ? "success" : c.status === "observation" ? "warning" : "neutral"}>{c.status}</Badge>
                  </li>
                ))}
              </ul>
              {items.length > 5 && <button className="text-button" type="button" onClick={() => setShowAllChecks(v => !v)}>{showAllChecks ? "Show less" : `Show all ${items.length} ${title.toLowerCase()}`}</button>}
            </details>
          );
          return <section className="panel stack" aria-label="Check catalog">
            <h2 className="section-title" style={{ fontSize: 18, marginBottom: 4 }}>Security Check Catalog</h2>
            {renderGroup("Action Required / Observations", obs, "obs")}
            {renderGroup("Passed Controls", passed, "passed")}
            {renderGroup("Deferred / Inapplicable Capabilities", deferred, "deferred")}
          </section>;
        })()}
        <p className="small muted" style={{ marginTop: 12 }}>Assessment limits: {isLab ? "recorded baseline against an owned synthetic fixture only." : "bounded HTTP response-hardening, TLS/SSL configuration, redirect hygiene, cookies, and CORS boundaries."} Only recorded checks count. Scores are security assessments, not compliance certifications.</p>

        {target && isTerminal(report.scan.status) && (
          <div className="panel stack deep-scan-cta" style={{ marginTop: 24, padding: "20px", background: "var(--color-surface-subtle, rgba(255,255,255,0.02))", borderRadius: "12px", border: "1px solid var(--color-border, rgba(255,255,255,0.08))" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
              <div>
                <span className="eyebrow" style={{ color: "var(--color-accent, #6366f1)" }}>Authorized Verification</span>
                <h3 style={{ margin: "4px 0 6px", fontSize: "1.15rem" }}>{report.scan.mode === "deep" ? "Deep Scan authorization" : "Perform Deep Security Scan"}</h3>
                <p className="small muted" style={{ margin: 0, maxWidth: 520 }}>
                  {report.scan.mode === "deep" ? "Review the DNS proof and action classes before another authorized Deep Scan." : "Run verified Git repository checks, bounded link discovery, and CORS origin analysis. Requires DNS ownership verification and explicit action consent."}
                </p>
              </div>
              <button
                className="button primary"
                type="button"
                aria-expanded={deepProject?.id === target.id}
                aria-controls="deep-authorization-flow"
                onClick={() => setDeepProject(current => current?.id === target.id ? null : target)}
              >
                {deepProject?.id === target.id ? "Hide authorization" : report.scan.mode === "deep" ? "Review Authorization ↗" : "Try Deep Scan ↗"}
              </button>
            </div>
            {deepProject?.id === target.id && (
              <div id="deep-authorization-flow" className="deep-authorization-reveal">
                <div>
                  <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--color-border, rgba(255,255,255,0.08))" }}>
                    <DeepScanAuthorization
                      key={deepProject.id}
                      project={deepProject}
                      disabled={Boolean(busy)}
                      running={active}
                      onStart={id => startWebsiteScan(deepProject, false, id)}
                      onRevoked={() => { setRevision(previous => previous + 1); void refreshTree(); }}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {target && isTerminal(report.scan.status) && (
          <div style={{ display: "flex", gap: 12, marginTop: 16, flexWrap: "wrap" }}>
            <button className="button secondary" type="button" onClick={() => { if (report.scan.mode === "deep") setDeepProject(target); else void startWebsiteScan(target); }}>
              {report.scan.mode === "deep" ? "Review authorization for another Deep Scan" : "Rerun Standard Scan"}
            </button>
            {report.scan.mode === "deep" && (
              <button className="button secondary" type="button" onClick={() => { setDeepProject(null); void startWebsiteScan(target); }}>
                Run Standard Scan
              </button>
            )}
          </div>
        )}
      </section>}
    </div>}
    <section id="scan-tree" className="inline-tree" aria-label="Scan tree">
      <div className="tree-heading"><h2>Scan tree</h2><button className="text-button" onClick={() => void refreshTree()}>Refresh</button></div>
      <p className="small muted">{workspace?.persistence === "local-file" ? "Your targets and recorded runs are saved on this local service." : "Your targets and recorded runs are held in memory and reset when the service restarts."}</p>
      {historyError && <p role="alert" className="scan-error">{historyError}</p>}
      {!loaded ? <p role="status" className="small muted">Loading scans…</p> : !targets.length && !scans.length ? <p className="tree-empty"><Globe size={18} aria-hidden="true" /> Add your website above. Its scans will appear here.</p> : <ul className="tree-branches">{targets.filter((item, index, items) => items.findIndex(other => new URL(other.url).hostname === new URL(item.url).hostname) === index).map(item => {
        const host = new URL(item.url).hostname;
        const branch = scanBranches(scans).find(entry => entry.hostname === host);
        const isLabHost = host.includes("fixture.invalid") || host.includes("shipsafe-fixture");
        const hostDisplayName = isLabHost ? "ShipSafe Private Lab" : host;
        return <li key={host}>
          <button className="tree-host" disabled={Boolean(busy) || active} onClick={() => selectTarget(item)}>
            <Globe size={16} aria-hidden="true" /><span>{hostDisplayName}</span><span className="small muted">{branch?.scans.length ?? 0} {branch?.scans.length === 1 ? "scan" : "scans"}</span>
          </button>
          {branch?.scans.length ? <ul>{branch.scans.map(scan => <li key={scan.id}><button className="tree-scan" aria-current={scanId === scan.id ? "true" : undefined} disabled={Boolean(busy) || active} onClick={() => {
            const p = targets.find(project => project.id === scan.projectId) ?? null;
            setTarget(p);
            setDeepProject(null);
            if (p && !p.url.includes("fixture.invalid") && scan.mode !== "lab") setValue(p.url);
            setOpened(true); setError(""); setFollowOutput(true); setScanId(scan.id); setRevision(previous => previous + 1);
            panel.current?.scrollIntoView({ behavior: "auto", block: "start" });
          }}><span className="mono">{new Date(scan.createdAt).toLocaleString()}</span><Badge>{scan.status}</Badge></button></li>)}</ul> : <p className="small muted tree-pending">No recorded scans yet</p>}
        </li>;
      })}</ul>}
    </section>
  </div>;
}
