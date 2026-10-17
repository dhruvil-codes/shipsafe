import type { Assessment } from "./assessment";
import { fixPrompt, presentScanEvents, assessmentMetrics, readUnifiedResults } from "./assessment";
import { hasCompleteBaselineOutcomes, scoreUrlBaseline } from "./baseline-score";

const CHECK_STATUSES = ["passed", "observation", "skipped", "failed"] as const;
type CheckStatus = typeof CHECK_STATUSES[number];
type ReportCheck = { id: string; title: string; status: CheckStatus; evidence: string; remediation: string | null };
type ReportFinding = { id: string; severity: string; title: string; description: string; evidence: string; remediation: string; classification: string | null; cwe: string | null; fixPrompt: string };

const BASELINE_LIMITATIONS = [
  "This URL baseline does not assess authenticated access, source code, dependencies, database rules, payment flows, or AI tools.",
  "A completed check describes only the recorded observation; it does not establish that the application is secure.",
];

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function str(value: unknown, max = 12_000): string | null {
  return typeof value === "string" ? value.slice(0, max) : null;
}
function readChecks(value: unknown): ReportCheck[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item): ReportCheck[] => {
    const check = record(item);
    const status = str(check?.status, 20);
    const id = str(check?.id, 80);
    const title = str(check?.title, 300);
    const evidence = str(check?.evidence);
    if (!check || !id || !title || !evidence || !CHECK_STATUSES.includes(status as CheckStatus)) return [];
    return [{ id, title, status: status as CheckStatus, evidence, remediation: str(check.remediation, 4_000) }];
  });
}
function readFindings(report: Assessment): ReportFinding[] {
  if (!Array.isArray(report.findings)) return [];
  return report.findings.flatMap((item): ReportFinding[] => {
    const finding = record(item);
    const id = str(finding?.id, 300), severity = str(finding?.severity, 40), title = str(finding?.title, 300);
    const description = str(finding?.description, 4_000), evidence = str(finding?.evidence), remediation = str(finding?.remediation, 4_000);
    if (!finding || !id || !severity || !title || description === null || evidence === null || remediation === null) return [];
    return [{ id, severity, title, description, evidence, remediation, classification: str(finding.classification, 100), cwe: str(finding.cwe, 100), fixPrompt: fixPrompt(report, item) }];
  });
}

export function buildReportDocument(report: Assessment) {
  const manifest = record(report.scan.reportManifest);
  const checks = readChecks(manifest?.checks);
  const findings = readFindings(report);
  const modernProfile = report.scan.mode === "standard" || report.scan.mode === "deep";
  const unifiedResults = readUnifiedResults(manifest?.unifiedResults);
  const postureMetrics = assessmentMetrics(report, null);
  const baselineScore = !modernProfile && manifest?.profile === "bounded-http-hardening" ? scoreUrlBaseline(checks) : null;
  const baselineProfileIncomplete = manifest?.profile === "bounded-http-hardening" && !hasCompleteBaselineOutcomes(checks);
  const checkCounts = Object.fromEntries(CHECK_STATUSES.map(status => [status, checks.filter(check => check.status === status).length])) as Record<CheckStatus, number>;
  const synthetic = report.scan.mode === "lab" || manifest?.synthetic === true;
  const scopeLimited = manifest?.scopeLimited === true;
  const invalidChecks = Array.isArray(manifest?.checks) ? manifest.checks.length - checks.length : 0;
  const partial = scopeLimited || report.scan.status.toUpperCase() !== "COMPLETED" || !Array.isArray(manifest?.checks) || checks.length === 0 || checkCounts.failed > 0 || checkCounts.skipped > 0 || invalidChecks > 0 || baselineProfileIncomplete || manifest?.cleanupState === "unverified";
  const limitations = [...BASELINE_LIMITATIONS];
  if (Array.isArray(manifest?.limitations)) limitations.push(...manifest.limitations.filter((value): value is string => typeof value === "string").slice(0, 30).map(value => value.slice(0, 2000)));
  if (invalidChecks) limitations.push(`${invalidChecks} malformed check outcomes were omitted and receive no coverage credit.`);
  if (!Array.isArray(manifest?.checks) || checks.length === 0) limitations.unshift("No valid per-check outcomes were recorded; check coverage and successful results are unavailable.");
  if (checkCounts.failed) limitations.push(`${checkCounts.failed} recorded check${checkCounts.failed === 1 ? "" : "s"} failed.`);
  if (checkCounts.skipped) limitations.push(`${checkCounts.skipped} recorded check${checkCounts.skipped === 1 ? " was" : "s were"} skipped and received no coverage credit.`);
  if (baselineProfileIncomplete) limitations.push("The URL baseline requires exactly one valid outcome for each of its 13 defined check IDs; duplicate, unknown or missing outcomes make this assessment incomplete.");
  if (scopeLimited) limitations.push("The submitted hostname returned a redirect outside the approved follow policy. Its destination was not requested; checks and observations describe only the submitted hostname's redirect response.");
  return {
    formatVersion: 1 as const,
    scan: {
      id: report.scan.id,
      url: report.scan.url,
      status: report.scan.status,
      createdAt: report.scan.createdAt,
      mode: report.scan.mode ?? null,
      manifest: manifest ? {
        engine: str(manifest.engine, 300), version: str(manifest.version, 100),
        profile: str(manifest.profile, 100), scope: str(manifest.scope, 2048), cleanupState: str(manifest.cleanupState, 100), scopeLimited,
      } : null,
    },
    summary: { findingCount: findings.length, checkCounts, partial, synthetic, baselineScore, postureMetrics: modernProfile ? postureMetrics : null },
    unifiedResults,
    checks,
    findings,
    events: Array.isArray(report.events) ? presentScanEvents(report.events).flatMap(event => {
      const value = record(event);
      const id = str(value?.id, 300), stage = str(value?.stage, 300), message = str(value?.message);
      const timestamp = str(value?.timestamp, 300);
      return value && id !== null && stage !== null && message !== null && timestamp !== null ? [{ id, stage, message, timestamp }] : [];
    }) : [],
    limitations,
  };
}

const escapeHtml = (value: unknown): string => String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);
const esc = (value: unknown) => escapeHtml(value);

export function renderReportHtml(report: Assessment): string {
  const doc = buildReportDocument(report);
  const statusClass = doc.scan.status.toLowerCase().replace(/[^a-z0-9_-]/g, "-");
  const checks = doc.checks.length ? doc.checks.map(check => `<tr><td><strong>${esc(check.title)}</strong><br><small>${esc(check.id)}</small></td><td><span class="badge ${esc(check.status)}">${esc(check.status)}</span></td><td class="text">${esc(check.evidence)}</td><td class="text">${check.remediation ? esc(check.remediation) : "Not recorded"}</td></tr>`).join("") : `<tr><td colspan="4">No valid check outcomes were recorded.</td></tr>`;
  const findings = doc.findings.length ? doc.findings.map(finding => `<article class="finding"><header><span class="badge ${esc(finding.severity.toLowerCase())}">${esc(finding.severity)}</span>${finding.classification ? `<span class="badge">${esc(finding.classification)}</span>` : ""}<h3>${esc(finding.title)}</h3><small>${esc(finding.id)}${finding.cwe ? ` · ${esc(finding.cwe)}` : ""}</small></header><p>${esc(finding.description)}</p><h4>Evidence</h4><pre>${esc(finding.evidence)}</pre><h4>Recommended remediation</h4><p>${esc(finding.remediation)}</p><h4>Ready-to-copy fix prompt</h4><p class="copy-note">Select and copy this text with Ctrl+C (or Command+C on Mac).</p><pre class="prompt">${esc(finding.fixPrompt)}</pre></article>`).join("") : `<p>No recorded findings. This does not establish that the target is secure.</p>`;
  const events = doc.events.length ? `<ol class="events">${doc.events.map(event => `<li><time>${esc(event.timestamp)}</time> <strong>${esc(event.stage)}</strong><p>${esc(event.message)}</p></li>`).join("")}</ol>` : `<p>No event timestamps were recorded.</p>`;
  const manifest = doc.scan.manifest;
  const profile = manifest?.profile ?? "URL baseline";
  const engine = [manifest?.engine, manifest?.version ? `version ${manifest.version}` : null].filter(Boolean).join(" · ") || "Engine details unavailable";
  const unified = doc.unifiedResults.map(result => `<article class="finding"><span class="badge">${esc(result.status)}</span><h3>${esc(result.title)}</h3><p>${esc(result.category)} · ${esc(result.id)} · ${esc(result.version)} · ${esc(result.severity)} · Confidence ${esc(result.confidence)}</p><p>${esc(result.affectedUrl)} · ${esc(result.timestamp)}</p><p>${esc(result.why)}</p><h4>Evidence</h4><pre>${esc(result.evidence || "No evidence recorded")}</pre><h4>Verification</h4><p>${esc(result.verification)}</p><h4>Remediation</h4><p>${esc(result.remediation)}</p></article>`).join("");
  const scorePanel = doc.summary.postureMetrics ? `<aside class="notice"><strong>Security posture score · not CVSS: ${doc.summary.postureMetrics.value === null ? "Unavailable" : `${doc.summary.postureMetrics.value}/100`}</strong><p>Executed coverage: ${doc.summary.postureMetrics.coverage === null ? "Unavailable" : `${doc.summary.postureMetrics.coverage}%`}. Unavailable tests receive no success credit.</p></aside>` : doc.summary.baselineScore ? `<section class="scoreboard" aria-label="URL baseline score"><div class="score-ring"><svg viewBox="0 0 120 120" role="img" aria-label="Baseline score ${doc.summary.baselineScore.value} out of 100, grade ${esc(doc.summary.baselineScore.grade)}"><circle class="track" cx="60" cy="60" r="50"/><circle class="progress" cx="60" cy="60" r="50" style="stroke-dasharray:${Math.PI * 100};stroke-dashoffset:${Math.PI * 100 * (1-doc.summary.baselineScore.value/100)}"/><text x="60" y="58">${doc.summary.baselineScore.value}</text><text class="unit" x="60" y="77">/ 100</text></svg><strong>Grade ${esc(doc.summary.baselineScore.grade)}</strong></div><div class="score-copy"><span class="topline">URL baseline score · ${esc(doc.summary.baselineScore.version)}</span><h2>${doc.summary.baselineScore.passed} of ${doc.summary.baselineScore.assessed} assessed checks passed</h2><p>${doc.summary.baselineScore.observed} hardening observations; ${doc.summary.baselineScore.skipped} skipped; ${doc.summary.baselineScore.failed} failed. Skipped and failed checks receive no score or coverage credit.</p><p class="score-coverage">Coverage ${doc.summary.baselineScore.assessed}/${doc.summary.baselineScore.applicable} profile checks · ${doc.summary.baselineScore.coverage}%</p><p class="muted">This score describes the URL response-hardening profile only. It is not an overall application security score.</p></div></section>` : `<aside class="notice"><strong>Score unavailable.</strong> No score is available for this assessment profile.</aside>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ShipSafe report · ${esc(doc.scan.id)}</title><style>
    :root{color-scheme:light;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#172b4d;background:#fff;font-synthesis:none}*{box-sizing:border-box}body{margin:0 auto;padding:36px 28px;max-width:1100px;line-height:1.55}h1,h2,h3,h4{line-height:1.25}h1{font-size:2rem;margin:.2rem 0}h2{font-size:1.35rem;margin:2rem 0 .8rem;border-bottom:1px solid #d9e2f0;padding-bottom:.45rem}h3{display:inline-block;margin:.5rem .5rem .25rem;font-size:1.08rem}small,.muted{color:#52647b}.topline{color:#2463a6;font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:.76rem}.target{overflow-wrap:anywhere;background:#f2f7fd;border-left:4px solid #3977b8;padding:12px 16px;margin:20px 0}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}.meta div{border:1px solid #d9e2f0;border-radius:8px;padding:12px}.meta strong{display:block;font-size:.78rem;color:#52647b;text-transform:uppercase;letter-spacing:.04em}.notice{padding:12px 16px;border-radius:7px;background:#fff7e5;border:1px solid #f2d491;margin:16px 0}.notice.synthetic{background:#edf5ff;border-color:#bed8f2}.scoreboard{display:flex;align-items:center;gap:28px;padding:24px;background:#f2f7fd;border:1px solid #d9e2f0;border-radius:12px;margin:20px 0}.score-ring{flex:0 0 150px;text-align:center}.score-ring svg{display:block;width:130px;height:130px;margin:auto}.score-ring circle{fill:none;stroke-width:9}.score-ring .track{stroke:#dce5ef}.score-ring .progress{stroke:#d48b16;stroke-linecap:round;transform:rotate(-90deg);transform-origin:60px 60px}.score-ring text{fill:#172b4d;text-anchor:middle;font-size:31px;font-weight:700}.score-ring text.unit{fill:#52647b;font-size:12px;font-weight:400}.score-ring strong{display:block;margin-top:5px}.score-copy h2{margin:7px 0;border:0;padding:0}.score-coverage{font-weight:700;color:#2463a6}.score-copy .muted{font-size:.9rem}.badge{display:inline-block;padding:2px 9px;margin:2px 4px 2px 0;border-radius:99px;background:#edf1f6;color:#35475e;font-size:.78rem;font-weight:700;text-transform:capitalize}.badge.passed{background:#e4f4ea;color:#176b39}.badge.observation,.badge.medium,.badge.low{background:#fff1d6;color:#805300}.badge.failed,.badge.critical,.badge.high{background:#fde8e7;color:#a52620}.badge.skipped,.badge.info{background:#eaf1f9;color:#345e8a}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #d9e2f0;overflow-wrap:anywhere}th{background:#f2f6fb}.text,pre{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}pre{font: .88rem/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;padding:12px;background:#f5f7fa;border:1px solid #dce3ec;border-radius:6px;margin:8px 0}.prompt{border-left:3px solid #3977b8}.finding{padding:14px 0;border-bottom:1px solid #d9e2f0;break-inside:avoid}.finding header small{display:block}.copy-note{font-size:.85rem;color:#52647b;margin:.2rem 0}.events{padding-left:1.4rem}.events li{margin:12px 0}.events p{margin:.2rem 0}.events time{font-variant-numeric:tabular-nums;color:#52647b}.limitations li{margin:.4rem 0}footer{margin-top:32px;padding-top:12px;border-top:1px solid #d9e2f0;color:#52647b;font-size:.85rem}@media(max-width:650px){body{padding:22px 14px}.scoreboard{align-items:flex-start;gap:14px;padding:16px}.score-ring{flex-basis:122px}.score-ring svg{width:112px;height:112px}table{font-size:.86rem}th,td{padding:7px}}@media print{body{max-width:none;padding:0;color:#111}h2,.finding,.meta div,table,pre{break-inside:avoid}.notice{print-color-adjust:exact;-webkit-print-color-adjust:exact}a{color:inherit;text-decoration:none}}
  </style></head><body><header><div class="topline">ShipSafe · Security assessment report</div><h1>Assessment report</h1><p class="muted">Recorded data for scan ${esc(doc.scan.id)}</p></header><div class="target"><strong>Target</strong><br>${esc(doc.scan.url)}</div><section class="meta"><div><strong>Status</strong><span class="badge ${esc(statusClass)}">${esc(doc.scan.status)}</span></div><div><strong>Profile</strong>${esc(profile)}</div><div><strong>Engine</strong>${esc(engine)}</div><div><strong>Started</strong>${doc.scan.createdAt ? esc(doc.scan.createdAt) : "Timestamp unavailable"}</div>${manifest?.cleanupState ? `<div><strong>Job cleanup</strong>${esc(manifest.cleanupState)}</div>` : ""}</section>${doc.summary.synthetic ? `<aside class="notice synthetic"><strong>Synthetic demonstration.</strong> This report describes a private fixture and does not describe a customer website.</aside>` : ""}${doc.summary.partial ? `<aside class="notice"><strong>${manifest?.scopeLimited === true ? "Scope-limited assessment." : "Partial assessment."}</strong> ${manifest?.scopeLimited === true ? "Only the submitted hostname’s redirect response was assessed; its destination was not contacted." : `The recorded status is ${esc(doc.scan.status)}. Failed, skipped, or unrecorded checks are not successful results.`}</aside>` : ""}<h2>Assessment summary</h2>${scorePanel}<p>${doc.summary.findingCount} recorded findings across ${doc.checks.length} valid check outcomes.</p><h2>Check outcomes</h2><table><thead><tr><th>Check</th><th>Status</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>${checks}</tbody></table>${unified ? `<h2>Security test catalog outcomes</h2>${unified}` : ""}<h2>Findings</h2>${findings}<h2>Limitations</h2><ul class="limitations">${doc.limitations.map(item => `<li>${esc(item)}</li>`).join("")}</ul><h2>Assessment events</h2>${events}<footer>Generated from persisted assessment records. The baseline score applies only to the tested URL response-hardening checks.</footer></body></html>`;
}
