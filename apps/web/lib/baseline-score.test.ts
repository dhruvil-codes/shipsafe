import { describe, expect, it } from "vitest";
import { BASELINE_CHECK_IDS, hasCompleteBaselineOutcomes, scoreUrlBaseline } from "./baseline-score";

describe("URL baseline score", () => {
  it("scores only checks that completed and reports fixed-profile coverage", () => {
    const checks = BASELINE_CHECK_IDS.map((id, index) => ({ id, status: index < 3 ? "passed" : index < 12 ? "observation" : "skipped" }));
    expect(scoreUrlBaseline(checks)).toEqual({ value: 25, grade: "F", passed: 3, observed: 9, assessed: 12, skipped: 1, failed: 0, coverage: 92.3, applicable: 13, version: "url-baseline-pass-ratio-v1" });
  });
  it("does not grant score or coverage credit for skipped and failed checks", () => {
    expect(scoreUrlBaseline([{ id: "https", status: "skipped" }, { id: "csp", status: "failed" }])).toBeNull();
    expect(scoreUrlBaseline([{ id: "https", status: "passed" }, { id: "csp", status: "failed" }, { id: "hsts", status: "skipped" }])).toMatchObject({ value: 100, assessed: 1, coverage: 7.7, failed: 1, skipped: 1 });
  });
  it("uses the baseline grade thresholds", () => {
    expect(scoreUrlBaseline([{ id: "https", status: "passed" }, { id: "csp", status: "observation" }])).toMatchObject({ value: 50, grade: "C" });
  });
  it("ignores duplicate and unknown control IDs to prevent score padding", () => {
    const invalid = [{ id: "https", status: "passed" }, { id: "https", status: "passed" }, { id: "injected", status: "passed" }, { id: "http-response", status: "passed" }];
    expect(scoreUrlBaseline(invalid)).toMatchObject({ value: 100, assessed: 1, coverage: 7.7 });
    expect(hasCompleteBaselineOutcomes(invalid)).toBe(false);
    expect(hasCompleteBaselineOutcomes(BASELINE_CHECK_IDS.map(id => ({ id, status: "passed" })))).toBe(true);
  });
});
