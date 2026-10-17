"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell, Badge, ButtonLink, EmptyState, ErrorNotice, PageHeading } from "@/components/product-ui";
import { ARCHIVED_SAMPLE, assessmentScore, filterFindings, fixPrompt, loadAssessment, SEVERITIES, type Assessment, type SeverityFilter } from "@/lib/assessment";

/** Render recorded evidence as text, including hostile HTML and terminal escape strings. */
export function Evidence({ text }: { text: string }) {
  return <pre className="terminal" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 420, overflow: "auto" }}>{text || "No evidence supplied by the scanner."}</pre>;
}

export function FindingList({ report }: { report: Assessment }) {
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const findings = filterFindings(report.findings, severity);
  return <section className="panel stack" aria-label="Findings">
    <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}><h2 className="section-title">Findings <span className="muted">{report.findings.length}</span></h2><label className="small report-filter">Severity <select value={severity} onChange={e => setSeverity(e.target.value as SeverityFilter)} style={{ padding: 10, marginLeft: 8, borderRadius: 8 }}><option value="all">All ({report.findings.length})</option>{SEVERITIES.map(s => <option key={s} value={s}>{s} ({filterFindings(report.findings, s).length})</option>)}</select></label></div>
    {findings.length ? <div>{findings.map(f => <Link key={f.id} href={`/report/${encodeURIComponent(report.scan.id)}/findings/${encodeURIComponent(f.id)}`} className="row report-finding-row" style={{ padding: "20px 0", borderTop: "1px solid rgba(25,25,25,.08)", gap: 16, justifyContent: "space-between", textDecoration: "none", color: "inherit", flexWrap: "wrap" }}><div><Badge tone={f.severity.toLowerCase() === "critical" || f.severity.toLowerCase() === "high" ? "danger" : f.severity.toLowerCase() === "medium" ? "warning" : f.severity.toLowerCase() === "low" ? "info" : "neutral"}>{f.severity}</Badge><h3 style={{ margin: "12px 0 4px", fontSize: 18 }}>{f.title}</h3><span className="muted small">{f.cwe || "CWE unavailable"} · View evidence and remediation</span></div><span aria-hidden="true">↗</span></Link>)}</div> : <EmptyState title="No findings in this view" description="This does not establish that the application is secure. Only executed checks contribute evidence." />}
  </section>;
}

export function EventLog({ report }: { report: Assessment }) {
  return <section className="panel stack"><h2 className="section-title">Recorded event log</h2>{report.events.length ? <ol style={{ paddingLeft: 20 }}>{report.events.map(e => <li key={e.id} style={{ marginBottom: 16 }}><div className="small muted">{e.timestamp} · {e.stage}</div><p style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginTop: 4 }}>{e.message}</p></li>)}</ol> : <p className="muted">{report.archived ? "The original event log is unavailable in this archived exhibit." : "No events have been recorded."}</p>}</section>;
}

export function SampleNotice({ report }: { report: Assessment }) {
  return report.archived ? <aside className="notice notice-info" role="note"><strong>Archived sample · no fresh scan</strong><p>{report.provenance}</p></aside> : null;
}

function download(report: Assessment) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = `shipsafe-${report.archived ? "ARCHIVED-SAMPLE" : report.scan.id}.json`; anchor.click(); URL.revokeObjectURL(url);
}

export default function ReportView({ id, findingId }: { id: string; findingId?: string }) {
  const [storedReport, setReport] = useState<Assessment | null>(id === "sample" ? ARCHIVED_SAMPLE : null);
  const report = storedReport?.scan.id === id ? storedReport : null;
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [copyMessage, setCopyMessage] = useState("");
  useEffect(() => {
    if (id === "sample") { setReport(ARCHIVED_SAMPLE); return; }
    const controller = new AbortController(); setError(""); setReport(null);
    void loadAssessment(id, controller.signal).then(setReport).catch(e => { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "Unable to load report."); });
    return () => controller.abort();
  }, [id, attempt]);
  const finding = report?.findings.find(f => f.id === findingId);
  const score = report ? assessmentScore(report) : null;
  const prompt = report && finding ? fixPrompt(report, finding) : "";
  async function copyPrompt() {
    try { await navigator.clipboard.writeText(prompt); setCopyMessage("Fix prompt copied."); }
    catch { setCopyMessage("Clipboard unavailable. Select and copy the prompt below."); }
  }
  return <AppShell><div className="stack">
    <PageHeading eyebrow={report?.archived ? "Archived sample" : "Assessment report"} title={findingId ? finding?.title || "Finding details" : "Evidence, in context."} description={report ? report.scan.url : "Loading the recorded assessment."} action={<ButtonLink href={findingId ? `/report/${id}` : "/#scan"} secondary>{findingId ? "Back to report" : "Scan your app"}</ButtonLink>} />
    {error ? <ErrorNotice message={error} retry={() => setAttempt(n => n + 1)} /> : !report ? <p role="status">Loading report…</p> : <>
      <SampleNotice report={report} />
      {report.scan.reportManifest?.scopeLimited === true && <aside className="notice notice-warning" role="note"><strong>Scope-limited assessment</strong><p>Only the submitted hostname’s redirect response was assessed. ShipSafe did not contact the redirect destination, so the normal URL baseline score and coverage are unavailable.</p></aside>}
      {report.findings.some(f => f.severity.toUpperCase() === "CRITICAL") && <aside className="notice" role="alert"><strong>Critical finding recorded.</strong><p>The score is capped at 40 by policy. Review critical evidence before making a release decision.</p></aside>}
      {report.scan.status !== "COMPLETED" && <aside className="notice"><strong>{report.scan.status}</strong><p>This assessment is incomplete. Findings below may be partial; failed or skipped tests never improve the score.</p><ButtonLink href={`/scan/${id}`} secondary>View scan status</ButtonLink></aside>}
      {findingId ? finding ? <>
        <div className="row report-severity"><Badge tone={finding.severity.toLowerCase() === "critical" || finding.severity.toLowerCase() === "high" ? "danger" : finding.severity.toLowerCase() === "medium" ? "warning" : finding.severity.toLowerCase() === "low" ? "info" : "neutral"}>{finding.severity}</Badge><span className="muted small">{finding.cwe || "CWE unavailable"} · {finding.id}</span></div>
        <section className="panel stack"><h2 className="section-title">What was observed</h2><p>{finding.description}</p><h2 className="section-title">Recorded evidence</h2><Evidence text={finding.evidence} /><p className="small muted">Scanner output is untrusted data. A finding documents the observed condition; it does not prove every possible impact.</p></section>
        <section className="panel stack"><h2 className="section-title">Recommended fix</h2><p>{finding.remediation || "No remediation was supplied."}</p><h3>Verify the change</h3><p>Apply the change in your codebase, check for compatibility issues, then run a new authorized assessment within your verified project scope. This finding remains a historical record.</p><ButtonLink href="/#scan">Scan your app</ButtonLink></section>
        <section className="panel stack"><div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}><h2 className="section-title">Fix prompt for your coding agent</h2><button className="button secondary" onClick={() => void copyPrompt()}>Copy fix prompt</button></div>{copyMessage && <p role="status">{copyMessage}</p>}<textarea aria-label="Fix prompt, select to copy manually" readOnly value={prompt} rows={12} style={{ width: "100%", padding: 16, fontFamily: "monospace", fontSize: 13, borderRadius: 12, border: "1px solid rgba(25,25,25,.15)", resize: "vertical" }} /></section>
      </> : <EmptyState title="Finding not found" description="This finding is not part of the recorded assessment." /> : <>
        <div className="split report-metrics"><section className="panel stack score-panel"><span className="muted small">Recorded score</span>{score?.inconsistent && <p role="alert" className="small">The stored score conflicts with scoring policy. Score unavailable pending correction; inspect the recorded evidence.</p>}<strong className="metric-value">{score?.value ?? "Unavailable"}<span className="small muted">{score?.value !== null ? " / 100" : ""}</span></strong><p className="muted">{report.scan.status} · {report.scan.createdAt ? `Created ${report.scan.createdAt}` : "Exact scan time unavailable"}</p></section><section className="panel stack coverage-panel"><span className="muted small">Executed check coverage</span><strong className="metric-value">{report.scan.coverage !== null ? `${report.scan.coverage}%` : "Unavailable"}</strong><p className="muted">Coverage describes the configured assessment, not every security risk. Skipped and failed checks receive no credit.</p></section></div>
        <aside className="notice notice-warning"><strong>Assessment limits</strong><p>{report.archived ? "This exhibit represents the recorded baseline assessment only." : "The stored report does not provide a complete tool execution manifest."} Tool versions, per-tool coverage, confidence and execution duration are unavailable. A score is not a security guarantee or compliance certification.</p></aside>
        <div className="row" style={{ flexWrap: "wrap", gap: 12 }}><button className="button" onClick={() => download(report)}>Download {report.archived ? "archived sample " : ""}JSON</button><button className="button secondary" onClick={() => window.print()}>Print / save as PDF</button><span className="muted small">Uses your browser’s print dialog.</span></div>
        <FindingList report={report} /><EventLog report={report} />
      </>}
    </>}
  </div></AppShell>;
}

