import { describe, expect, it } from "vitest";
import { securityPosture, validateSecurityReport } from "./security-report";
import type { ScanRecord } from "./store";

const definitions = [
  { id: "https", category: "tls", title: "HTTPS", version: "1.0.0", implemented: true, severity: "info" },
  { id: "cookie", category: "cookies", title: "Cookie", version: "1.0.0", implemented: true, severity: "info" },
  { id: "api", category: "api", title: "API", version: "1.0.0", implemented: false, severity: "info" },
  { id: "inventory", category: "frontend", title: "Inventory", version: "1.0.0", implemented: true, severity: "info", scoreEligible: false },
];
const scan: ScanRecord = { id: "scn_fixture", projectId: "project", url: "https://owned.example.com/", mode: "standard", status: "RUNNING", createdAt: new Date().toISOString() };
function fixture() {
  const results = definitions.map(d => ({ id: d.id, category: d.category, title: d.title, version: d.version, severity: "info" as const, confidence: "none" as const, status: "NOT_TESTED" as const, evidence: "No evidence available", timestamp: new Date().toISOString(), affectedUrl: scan.url, why: "Bounded check", verification: "Retest only after authorization", remediation: "Review actual server configuration" }));
  return { checks: results.map(r => ({ id: r.id, title: r.title, status: "skipped", evidence: r.evidence })), findings: [] as { checkId: string; title: string; severity: string; classification: string; description: string; evidence: string; remediation: string }[], manifest: { engine: "shipsafe-security", profile: "standard-security-v1", scope: "owned.example.com", scopeLimited: false, requests: 1, unifiedResults: results, posture: { value: 100 } } };
}

describe("untrusted security report validation", () => {
  it("replaces claimed scores and gives unavailable and inventory checks no success credit", () => {
    const report = fixture();
    validateSecurityReport(report, scan, definitions);
    expect(report.manifest.posture).toMatchObject({ value: undefined, coverage: 0, passed: 0, eligible: 2 });
    const results: Record<string, unknown>[] = report.manifest.unifiedResults;
    results[0].status = "PASS";
    results[0].confidence = "high";
    results[3].status = "PASS";
    expect(securityPosture(results, definitions, "standard")).toMatchObject({ value: 50, coverage: 50, passed: 1 });
    results[1].status = "NOT_APPLICABLE";
    expect(securityPosture(results, definitions, "standard")).toMatchObject({ value: 100, eligible: 1 });
  });

  it("rejects missing, duplicate, unknown and invented results", () => {
    for (const mutate of [
      (r: ReturnType<typeof fixture>) => r.manifest.unifiedResults.pop(),
      (r: ReturnType<typeof fixture>) => { r.manifest.unifiedResults[1].id = "https"; },
      (r: ReturnType<typeof fixture>) => { r.manifest.unifiedResults[1].id = "unknown"; },
      (r: ReturnType<typeof fixture>) => { Object.assign(r.manifest.unifiedResults[2], { status: "PASS", confidence: "high" }); },
      (r: ReturnType<typeof fixture>) => { r.manifest.unifiedResults[0].affectedUrl = "https://other.example.com/"; },
      (r: ReturnType<typeof fixture>) => { r.manifest.requests = 21; },
    ]) {
      const report = fixture(); mutate(report);
      expect(() => validateSecurityReport(report, scan, definitions)).toThrow();
    }
  });

  it("rejects findings without a matching observed result", () => {
    const report = fixture();
    report.findings.push({ checkId: "https", title: "HTTPS", severity: "critical", classification: "vulnerability", description: "Invented exploit", evidence: "No evidence", remediation: "Review" });
    expect(() => validateSecurityReport(report, scan, definitions)).toThrow();
  });
});
