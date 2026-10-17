import { describe, expect, it } from "vitest";
import { ARCHIVED_SAMPLE, assessmentMetrics, readUnifiedResults, type Assessment } from "./assessment";
import { scoreUrlBaseline } from "./baseline-score";
import { buildReportDocument, renderReportHtml } from "./report";

const result = { id: "config.git", title: "Git metadata", category: "Configuration", severity: "INFO", confidence: "high", status: "NOT_TESTED", evidence: "Configuration consent was not granted.", timestamp: "2026-10-17T00:00:00Z", affectedUrl: "https://example.test/", why: "Metadata can reveal application details.", verification: "Authorize this test to collect evidence.", remediation: "Restrict metadata access.", version: "1.0" };
function modern(mode: "standard" | "deep", score: number | null = null): Assessment {
  return { ...ARCHIVED_SAMPLE, archived: false, scan: { ...ARCHIVED_SAMPLE.scan, mode, score, coverage: null, reportManifest: { unifiedResults: [result] } } };
}

describe("security catalog presentation", () => {
  it("keeps new-profile metrics unavailable when only a baseline subset could be calculated", () => {
    const subset = scoreUrlBaseline([{ id: "https", status: "passed" }]);
    for (const mode of ["standard", "deep"] as const) {
      expect(assessmentMetrics(modern(mode), subset)).toMatchObject({ value: null, coverage: null });
      expect(assessmentMetrics(modern(mode, 0), subset).value).toBe(0);
    }
  });
  it("keeps the posture pass ratio separate from the legacy critical finding cap", () => {
    const report = modern("deep", 82);
    report.findings = [{ ...ARCHIVED_SAMPLE.findings[0]!, severity: "critical" }];
    expect(assessmentMetrics(report, null)).toMatchObject({ value: 82, inconsistent: false });
  });
  it("retains explicit untested outcomes without interpreting missing data as a pass", () => {
    expect(readUnifiedResults([result])[0]).toMatchObject({ status: "NOT_TESTED", evidence: result.evidence });
    expect(readUnifiedResults([null, {}, { ...result, status: "passed" }])).toEqual([]);
    expect(readUnifiedResults(undefined)).toEqual([]);
  });
  it("includes unified evidence and posture metrics in structured and HTML exports", () => {
    const report = modern("deep", 82);
    expect(buildReportDocument(report)).toMatchObject({ unifiedResults: [result], summary: { baselineScore: null, postureMetrics: { value: 82, coverage: null } } });
    const html = renderReportHtml(report);
    expect(html).toContain("Security posture score · not CVSS: 82/100");
    expect(html).toContain("NOT_TESTED");
    expect(html).toContain(result.evidence);
  });
  it("escapes captured evidence in printable results", () => {
    const report = modern("standard");
    report.scan.reportManifest!.unifiedResults = [{ ...result, evidence: "<script>alert(1)</script>" }];
    const html = renderReportHtml(report);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
  });
});
