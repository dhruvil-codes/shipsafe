import { describe, expect, it } from "vitest";
import { inlineTarget, recordedSummary, scanBranches } from "./inline-scan";

describe("URL-first inline assessments", () => {
  it("accepts a bare domain and normalizes to its origin", () => {
    expect(inlineTarget(" app.company.com/start ")).toEqual({ url: "https://app.company.com/", hostname: "app.company.com" });
  });
  it("strips paths, queries, and fragments to the origin", () => {
    expect(inlineTarget("https://company.com/path?q=1#token")).toEqual({ url: "https://company.com/", hostname: "company.com" });
  });
  it.each(["", "localhost", "ftp://company.com", "https://user:secret@company.com", "https://company.com:8443"])("rejects unsupported browser input %s", raw => {
    expect(() => inlineTarget(raw)).toThrow();
  });
  it("keeps a subdomain distinct from its parent in the scan tree", () => {
    const scan = (id: string, url: string) => ({ id, url, projectId: "internal", status: "FAILED", createdAt: "2026-10-16T00:00:00Z" });
    const result = scanBranches([scan("one", "https://company.com"), scan("two", "https://app.company.com"), scan("three", "https://company.com/path")]);
    expect(result.map(branch => [branch.hostname, branch.scans.map(item => item.id)])).toEqual([["company.com", ["one", "three"]], ["app.company.com", ["two"]]]);
  });
  it("does not turn failed, cancelled, or interrupted runs into clean reports", () => {
    expect(recordedSummary("FAILED", 0)).toContain("Partial evidence");
    expect(recordedSummary("CANCELLED", 0)).toContain("Partial evidence");
    expect(recordedSummary("RUNNING", 0)).toContain("No successful outcome");
    expect(recordedSummary("COMPLETED", 0)).toContain("Review coverage");
  });
});
