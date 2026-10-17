import { describe, expect, it } from "vitest";
import type { Assessment } from "./assessment";
import { buildReportDocument, renderReportHtml } from "./report";
import { BASELINE_CHECK_IDS } from "./baseline-score";

function assessment(overrides: Partial<Assessment> = {}): Assessment {
  return {
    scan: { id: "scan-1", projectId: "p1", projectName: "Example", url: "https://example.test", status: "COMPLETED", score: 99, coverage: 100, createdAt: "2026-10-16T12:00:00Z", mode: "website", reportManifest: { profile: "bounded-http-hardening", engine: "ShipSafe baseline", version: "1.0", cleanupState: "verified", checks: BASELINE_CHECK_IDS.map((id, index) => ({ id, title: id, status: index === 0 ? "passed" : "observation", evidence: "Recorded outcome", remediation: "Configure a policy" })) } },
    findings: [{ id: "F-1", scanId: "scan-1", severity: "info", title: "Missing CSP", description: "Observed absence", evidence: "Header absent", remediation: "Configure a policy", cwe: "CWE-693", classification: "hardening" }],
    events: [{ id: "e1", scanId: "scan-1", stage: "COMPLETED", message: "Report saved", timestamp: "2026-10-16T12:01:00Z" }],
    ...overrides,
  };
}

describe("exportable assessment report", () => {
  it("exports corrected terminal copy when the recorded job cleanup succeeded", () => {
    const input = assessment({ events: [
      { id: "cleanup", scanId: "scan-1", stage: "CLEANUP", message: "Temporary job files removed", timestamp: "now" },
      { id: "failed", scanId: "scan-1", stage: "FAILED", message: "The worker could not complete or verify cleanup.", timestamp: "now" },
    ] });
    expect(buildReportDocument(input).events[1]?.message).toContain("cleanup was verified");
  });

  it("exports recorded checks, a scoped score, metadata, events, findings, and an evidence-backed fix prompt", () => {
    const doc = buildReportDocument(assessment());
    expect(doc).toMatchObject({ formatVersion: 1, summary: { findingCount: 1, checkCounts: { observation: 12, failed: 0, skipped: 0 }, partial: false, synthetic: false, baselineScore: { value: 8, grade: "F", passed: 1, observed: 12, assessed: 13, coverage: 100, applicable: 13, version: "url-baseline-pass-ratio-v1" } } });
    expect(doc.scan.manifest).toMatchObject({ profile: "bounded-http-hardening", engine: "ShipSafe baseline", version: "1.0", cleanupState: "verified" });
    expect(renderReportHtml(assessment())).toContain("URL baseline score");
    expect(doc.findings[0]?.fixPrompt).toContain('"id": "F-1"');
    expect(doc.findings[0]?.fixPrompt).toContain('"severity": "info"');
    expect(doc.findings[0]?.fixPrompt).toContain("Header absent");
    expect(doc.findings[0]?.fixPrompt).toContain("Configure a policy");
    expect(JSON.stringify(doc)).not.toContain('"overallSecurityScore"');
    expect(doc.limitations.join(" ")).toContain("does not assess authenticated access");
  });

  it("escapes every captured string and emits no executable or external content", () => {
    const attack = `<script src="https://evil.test/x.js">alert('x')</script>&`;
    const input = assessment({
      scan: { ...assessment().scan, id: attack, url: `https://safe.test/?q=${attack}`, status: attack, createdAt: attack, mode: "lab", reportManifest: { engine: attack, version: attack, profile: attack, cleanupState: attack, synthetic: true, checks: [{ id: attack, title: attack, status: "failed", evidence: attack, remediation: attack }] } },
      findings: [{ id: attack, scanId: "scan-1", severity: attack, title: attack, description: attack, evidence: attack, remediation: attack, cwe: attack, classification: "hardening" }],
      events: [{ id: attack, scanId: "scan-1", stage: attack, message: attack, timestamp: attack }],
    });
    const html = renderReportHtml(input);
    expect(html).not.toContain(attack);
    expect(html).toContain("&lt;script src=&quot;https://evil.test/x.js&quot;&gt;");
    expect(html).not.toMatch(/<script\b/i);
    expect(html).not.toMatch(/<img\b|<iframe\b|<link\b/i);
    expect(html).not.toMatch(/<(?:script|img|iframe|link)\b/i);
    expect(html).toContain("Synthetic demonstration.");
    expect(html).toContain("Partial assessment.");
  });

  it("does not imply success when outcomes are absent, malformed, skipped, or failed", () => {
    const missing = buildReportDocument(assessment({ scan: { ...assessment().scan, reportManifest: undefined } }));
    expect(missing.summary).toMatchObject({ partial: true, checkCounts: { passed: 0, observation: 0, skipped: 0, failed: 0 } });
    const invalid = buildReportDocument(assessment({ scan: { ...assessment().scan, reportManifest: { checks: [{ id: "x", title: "Unknown", status: "passed" }, null, { id: "f", title: "Failed", status: "failed", evidence: "Could not run" }, { id: "s", title: "Skipped", status: "skipped", evidence: "Not applicable" }] } } }));
    expect(invalid.checks).toHaveLength(2);
    expect(invalid.summary).toMatchObject({ partial: true, checkCounts: { passed: 0, failed: 1, skipped: 1 } });
    const html = renderReportHtml(assessment({ scan: { ...assessment().scan, reportManifest: undefined } }));
    expect(html).toContain("No valid check outcomes were recorded.");
    expect(html).not.toContain("99/100");
    expect(html).not.toContain("Score 99");
  });

  it("keeps an out-of-scope redirect report visibly partial and unscored", () => {
    const input = assessment({
      scan: { ...assessment().scan, coverage: null, reportManifest: {
        profile: "bounded-http-redirect-response", scopeLimited: true, scopeStopReason: "REDIRECT_HOST",
        checks: [{ id: "redirect-scope", title: "Redirect stays within approved scope", status: "observation", evidence: "Redirect response observed; destination omitted", remediation: "Submit an authorized canonical hostname" }],
      } },
      findings: [{ id: "redirect", scanId: "scan-1", severity: "info", title: "Redirect destination outside approved scope", description: "Scope limitation; destination not contacted", evidence: "HTTP redirect response", remediation: "Submit an authorized canonical hostname", classification: "hardening" }],
    });
    const doc = buildReportDocument(input);
    expect(doc.summary).toMatchObject({ partial: true, baselineScore: null, findingCount: 1 });
    expect(doc.scan.manifest).toMatchObject({ scopeLimited: true, profile: "bounded-http-redirect-response" });
    expect(doc.limitations.join(" ")).toContain("destination was not requested");
    const html = renderReportHtml(input);
    expect(html).toContain("Scope-limited assessment.");
    expect(html).toContain("destination was not contacted");
    expect(html).toContain("No score is available for this assessment profile.");
    expect(html).not.toContain("URL baseline score");
  });

  it("is deterministic for the same persisted report", () => {
    expect(renderReportHtml(assessment())).toBe(renderReportHtml(assessment()));
  });
  it("marks omitted malformed check outcomes as incomplete even beside valid passes", () => {
    const input = assessment();
    input.scan.reportManifest!.checks = [{ id: "ok", title: "Recorded check", status: "passed", evidence: "Recorded evidence" }, { id: "broken", status: "passed" }];
    expect(buildReportDocument(input).summary.partial).toBe(true);
    expect(buildReportDocument(input).limitations.join(" ")).toContain("malformed check outcomes");
  });
});
