import { describe, expect, it } from "vitest";
import {
  advanceEngines,
  buildAiFixPrompt,
  finalizeEngines,
  initialEngines,
  mapApiFindings,
  normalizeUrlInput,
  parseStreamPayload,
  type UiFinding,
} from "./scan-flow";

describe("normalizeUrlInput", () => {
  it("accepts full https URLs", () => {
    const r = normalizeUrlInput("https://example.com/a?b=c");
    expect(r.ok).toBe(true);
  });

  it("auto-prepends https://", () => {
    const r = normalizeUrlInput("example.com");
    expect(r).toEqual({ ok: true, url: "https://example.com/" });
  });

  it("rejects empty and malformed input", () => {
    expect(normalizeUrlInput("   ").ok).toBe(false);
    expect(normalizeUrlInput("not a url !!!").ok).toBe(false);
    expect(normalizeUrlInput("ftp://example.com").ok).toBe(false);
  });
});

describe("parseStreamPayload", () => {
  it("parses JSON log envelopes", () => {
    const ev = parseStreamPayload(
      JSON.stringify({ type: "log", stage: "RUNNING", message: "tls-check: ok" }),
    );
    expect(ev).toEqual({ kind: "log", stage: "RUNNING", message: "tls-check: ok" });
  });

  it("preserves structured live check fields and full text", () => {
    const timestamp = "2026-10-17T12:34:56.789+00:00";
    const message = "[OBSERVATION] Content Security Policy — " + "detail ".repeat(240);
    expect(parseStreamPayload(JSON.stringify({ type: "event", stage: "check_done", checkId: "csp", status: "observation", timestamp, message }))).toEqual({ kind: "log", stage: "check_done", checkId: "csp", status: "observation", timestamp, message });
  });

  it("parses JSON result envelopes", () => {
    const ev = parseStreamPayload(
      JSON.stringify({ type: "result", status: "COMPLETED", score: 84, coverage: 100, findingsCount: 3 }),
    );
    expect(ev).toEqual({ kind: "result", status: "COMPLETED", score: 84, coverage: 100, findingsCount: 3 });
  });

  it("handles legacy control lines", () => {
    expect(parseStreamPayload("__sandbox: sbx_live_1")).toEqual({
      kind: "sandbox",
      sandboxId: "sbx_live_1",
    });
    expect(parseStreamPayload("__status: active")).toEqual({ kind: "vmstatus", status: "active" });
    expect(parseStreamPayload("__done")).toEqual({ kind: "done" });
  });

  it("parses live VM stdout and error envelopes", () => {
    expect(
      parseStreamPayload(JSON.stringify({ type: "stdout", scanId: "s", text: "[tls] OK\n" })),
    ).toEqual({ kind: "stdout", text: "[tls] OK\n" });
    expect(
      parseStreamPayload(JSON.stringify({ type: "error", message: "[ERROR] boom" })),
    ).toEqual({ kind: "error", message: "[ERROR] boom" });
  });

  it("falls back to raw lines", () => {
    expect(parseStreamPayload("[tls] OK")).toEqual({ kind: "line", text: "[tls] OK" });
  });
});

describe("advanceEngines", () => {
  it("routes tool lines to the matching engine", () => {
    let checks = initialEngines();
    checks = advanceEngines(checks, "RUNNING", "subfinder: enumerating subdomains via crt.sh");
    expect(checks.find((c) => c.id === "attack-surface")?.state).toBe("running");
    expect(checks.find((c) => c.id === "tls")?.state).toBe("pending");
  });

  it("escalates warnings and never downgrades them", () => {
    let checks = initialEngines();
    checks = advanceEngines(checks, "RUNNING", "headers: WARN content-security-policy missing");
    expect(checks.find((c) => c.id === "headers")?.state).toBe("warning");
    checks = advanceEngines(checks, "RUNNING", "headers: complete OK");
    expect(checks.find((c) => c.id === "headers")?.state).toBe("warning");
  });

  it("marks clean completions passed", () => {
    let checks = initialEngines();
    checks = advanceEngines(checks, "RUNNING", "tls handshake OK, certificate valid");
    expect(checks.find((c) => c.id === "tls")?.state).toBe("passed");
  });

  it("finalizeEngines passes running engines and keeps pending pending", () => {
    const checks = finalizeEngines([
      { id: "a", label: "A", state: "running", detail: "x" },
      { id: "b", label: "B", state: "pending", detail: "queued" },
      { id: "c", label: "C", state: "warning", detail: "y" },
    ]);
    expect(checks.find((c) => c.id === "a")?.state).toBe("passed");
    expect(checks.find((c) => c.id === "b")?.state).toBe("pending");
    expect(checks.find((c) => c.id === "c")?.state).toBe("warning");
  });
});

const SAMPLE_FINDINGS: UiFinding[] = [
  {
    id: "f1",
    severity: "medium",
    title: "Missing Content-Security-Policy (CSP) Header",
    summary: "No CSP header.",
    affected: "GET /",
    evidence: "headers: no csp",
    fix: "Add CSP header to next.config.js or server response headers.",
    source: "web",
  },
  {
    id: "f2",
    severity: "high",
    title: "Missing DMARC Record",
    summary: "No DMARC.",
    affected: "example.com",
    evidence: "checkdmarc: dmarc null",
    fix: "Add TXT record: _dmarc.example.com -> 'v=DMARC1; p=reject; rua=mailto:security@example.com'",
    source: "osint",
    cwe: "CWE-358",
  },
];

describe("buildAiFixPrompt", () => {
  it("orders by severity and includes fixes with CWE", () => {
    const prompt = buildAiFixPrompt("https://example.com", 84, SAMPLE_FINDINGS);
    expect(prompt).toContain("https://example.com");
    expect(prompt).toContain("[HIGH] Missing DMARC Record (CWE-358)");
    expect(prompt).toContain("[MEDIUM] Missing Content-Security-Policy (CSP) Header");
    expect(prompt.indexOf("[HIGH]")).toBeLessThan(prompt.indexOf("[MEDIUM]"));
    expect(prompt).toContain("Please generate the exact configuration code");
  });

  it("handles the no-findings case without inventing issues", () => {
    const prompt = buildAiFixPrompt("https://example.com", 100, []);
    expect(prompt).toContain("No confirmed findings");
    expect(prompt).not.toContain("[HIGH]");
  });
});

describe("mapApiFindings", () => {
  it("normalizes severities and defaults unknowns to info", () => {
    const mapped = mapApiFindings([
      {
        id: "a",
        scanId: "s",
        severity: "CRITICAL",
        title: "T",
        description: "D",
        evidence: "E",
        remediation: "R",
        cwe: "CWE-1",
      },
      {
        id: "b",
        scanId: "s",
        severity: "bogus",
        title: "T2",
        description: "D2",
        evidence: "E2",
        remediation: "R2",
      },
    ]);
    expect(mapped[0]?.severity).toBe("critical");
    expect(mapped[1]?.severity).toBe("info");
  });
});
