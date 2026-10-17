import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SandboxLike } from "@shipsafe/sandbox/live-runner";
import { apiStore, type ScanRecord } from "./store";

const dependencies = vi.hoisted(() => ({ connect: vi.fn() }));
vi.mock("@shipsafe/sandbox/live-runner", () => ({ getLiveSandbox: dependencies.connect }));
import { kickQueue, runBaseline } from "./baseline-runtime";

const queueState = globalThis as typeof globalThis & { shipSafeQueue?: Promise<void> };
function report() {
  return { type: "report", checks: [{ id: "CSP", title: "Content security policy", status: "observation", evidence: "Header absent", remediation: "Configure CSP" }], findings: [{ checkId: "CSP", title: "Missing CSP", severity: "info", classification: "hardening", description: "A hardening observation", evidence: "Header absent", remediation: "Configure CSP" }], manifest: { engine: "fixture transport test", synthetic: true } };
}

function fakeVm(options: { lines?: unknown[]; cleanupFailure?: boolean; beforePoll?: () => void | Promise<void>; chunk?: { data: string; bytes: number } } = {}) {
  const commands: string[] = [];
  const writes: [string, string][] = [];
  const run = vi.fn(async (command: string) => {
    commands.push(command);
    if (command.includes("f.seek(")) {
      await options.beforePoll?.();
      const data = (options.lines ?? [report()]).map(line => JSON.stringify(line)).join("\n") + "\n";
      return { exitCode: 0, stdout: JSON.stringify(options.chunk ?? { data, bytes: Buffer.byteLength(data) }) };
    }
    if (command.includes("left=subprocess.run") && options.cleanupFailure) return { exitCode: 1, stdout: "" };
    return { exitCode: 0, stdout: "" };
  });
  const vm = { commands: { run }, files: { write: vi.fn(async (file: string, value: string) => { writes.push([file, value]); }) } } as unknown as SandboxLike;
  return { vm, commands, writes, run };
}

function scan(mode: "lab" | "website" = "lab"): ScanRecord {
  const target = apiStore.createProject("test-owner", { name: "Runtime fixture", url: "https://example.test/", environment: "development" });
  return apiStore.createScan({ projectId: target.id, url: target.url, scopeAccepted: true, mode });
}

beforeEach(() => {
  apiStore.reset();
  dependencies.connect.mockReset();
});
afterEach(async () => {
  await queueState.shipSafeQueue;
  apiStore.reset();
});

describe("baseline VM transport", () => {
  it("accepts a validated report and always verifies cleanup", async () => {
    const fixture = fakeVm({ lines: [{ type: "stage", stage: "analysis", message: "Observed fixture response" }, report()] });
    const emit = vi.fn();
    const result = await runBaseline(scan(), new AbortController().signal, emit, async () => fixture.vm);
    expect(result.findings[0].classification).toBe("hardening");
    expect(emit).toHaveBeenCalledWith("analysis", "Observed fixture response");
    expect(emit).toHaveBeenCalledWith("CLEANUP", expect.stringContaining("shared VM remains"));
    expect(fixture.commands.at(-1)).toContain("shutil.rmtree");
    expect(fixture.commands.join("\n")).toContain("--network");
    expect(fixture.commands.join("\n")).toContain("none");
  });

  it("rejects malformed scanner reports and still cleans up", async () => {
    const invalid = report();
    invalid.findings[0].severity = "invented";
    const fixture = fakeVm({ lines: [invalid] });
    await expect(runBaseline(scan(), new AbortController().signal, vi.fn(), async () => fixture.vm)).rejects.toThrow();
    expect(fixture.commands.at(-1)).toContain("shutil.rmtree");
  });

  it("rejects scanner errors without synthesizing a successful report", async () => {
    const fixture = fakeVm({ lines: [{ type: "error", code: "SCOPE_REJECTED" }] });
    await expect(runBaseline(scan(), new AbortController().signal, vi.fn(), async () => fixture.vm)).rejects.toThrow(/request was rejected by the approved scan scope/i);
  });

  it("keeps allowlisted failure reasons and translates them to safe event copy", async () => {
    const failed = scan("website");
    const next = scan();
    dependencies.connect.mockResolvedValueOnce(fakeVm({ lines: [{ type: "error", code: "SCOPE_REJECTED", reason: "REDIRECT_POLICY", message: "do not reveal this" }] }).vm).mockResolvedValueOnce(fakeVm().vm);
    kickQueue();
    await queueState.shipSafeQueue;
    const events = apiStore.listEvents(failed.id);
    expect(events.find(event => event.stage === "SCAN_FAILED")?.message).toContain("submit its final canonical HTTPS hostname directly");
    expect(events.some(event => event.message.includes("do not reveal this"))).toBe(false);
    expect(apiStore.getScan(next.id)?.status).toBe("COMPLETED");
  });

  it("reports specific redirect causes without storing the redirect destination", async () => {
    const cases = [
      ["REDIRECT_HOST", "different hostname"],
      ["HTTPS_DOWNGRADE", "redirected from HTTPS to HTTP"],
      ["REDIRECT_MISSING", "without a Location destination"],
      ["REDIRECT_AMBIGUOUS", "multiple redirect destinations"],
      ["REDIRECT_INVALID", "destination that is invalid"],
    ] as const;
    for (const [reason, expected] of cases) {
      apiStore.reset();
      const job = scan("website");
      dependencies.connect.mockResolvedValueOnce(fakeVm({ lines: [{ type: "error", code: "SCOPE_REJECTED", reason, destination: "secret.example" }] }).vm);
      kickQueue();
      await queueState.shipSafeQueue;
      const event = apiStore.listEvents(job.id).find(item => item.stage === "SCAN_FAILED");
      expect(event?.message).toContain(expected);
      expect(event?.message).not.toContain("secret.example");
      expect(JSON.stringify(apiStore.listEvents(job.id))).not.toContain("secret.example");
    }
  });

  it("saves a scope-limited redirect report without a baseline score or coverage claim", async () => {
    const job = scan("website");
    const partial = {
      ...report(),
      checks: [{ id: "redirect-scope", title: "Redirect stays within approved scope", status: "observation", evidence: "Redirect observed; destination omitted", remediation: "Submit the authorized canonical hostname" }],
      findings: [{ checkId: "redirect-scope", title: "Redirect destination outside approved scope", severity: "info", classification: "hardening", description: "Scope limitation; destination not contacted", evidence: "HTTP redirect response", remediation: "Submit the authorized canonical hostname" }],
      manifest: { engine: "fixture transport test", profile: "bounded-http-redirect-response", scopeLimited: true, scopeStopReason: "REDIRECT_HOST" },
    };
    dependencies.connect.mockResolvedValueOnce(fakeVm({ lines: [partial] }).vm);
    kickQueue();
    await queueState.shipSafeQueue;
    expect(apiStore.getScan(job.id)).toMatchObject({ status: "COMPLETED", reportManifest: { scopeLimited: true, profile: "bounded-http-redirect-response", cleanupState: "verified" } });
    expect(apiStore.getScan(job.id)?.coverage).toBeUndefined();
    expect(apiStore.listFindings(job.id)).toHaveLength(1);
    const completed = apiStore.listEvents(job.id).find(event => event.stage === "COMPLETED")?.message ?? "";
    expect(completed).toContain("redirect destination was not contacted");
    expect(completed).toContain("different hostname");
  });

  it("fails rather than returning a report when cleanup cannot be verified", async () => {
    const fixture = fakeVm({ cleanupFailure: true });
    await expect(runBaseline(scan(), new AbortController().signal, vi.fn(), async () => fixture.vm)).rejects.toThrow(/cleanup could not be verified/i);
  });

  it("rejects excessive aggregate output before processing report content", async () => {
    const fixture = fakeVm({ chunk: { data: "x".repeat(1_000_001), bytes: 1_000_001 } });
    await expect(runBaseline(scan(), new AbortController().signal, vi.fn(), async () => fixture.vm)).rejects.toThrow(/output exceeded/);
    expect(fixture.commands.at(-1)).toContain("shutil.rmtree");
  });

  it("sends the website URL only as a JSON file, never in command text", async () => {
    const fixture = fakeVm();
    const target = { ...scan("website"), url: "https://example.test/?marker=UNTRUSTED_URL_$(whoami)'" };
    await runBaseline(target, new AbortController().signal, vi.fn(), async () => fixture.vm);
    expect(fixture.commands.join("\n")).not.toContain("UNTRUSTED_URL");
    const input = fixture.writes.find(([file]) => file.endsWith("input.json"));
    expect(JSON.parse(input![1])).toEqual({ mode: "website", url: target.url });
  });

  it("uses the fixed owned fixture input for lab mode, ignoring supplied URLs", async () => {
    const fixture = fakeVm();
    await runBaseline({ ...scan(), url: "https://unrelated.invalid/" }, new AbortController().signal, vi.fn(), async () => fixture.vm);
    expect(JSON.parse(fixture.writes.find(([file]) => file.endsWith("input.json"))![1])).toEqual({ mode: "lab", url: "https://fixture.invalid/" });
  });
});

describe("local single worker queue", () => {
  it("drains FIFO once despite repeated kicks and processes one job at a time", async () => {
    const first = scan();
    const second = scan();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const firstVm = fakeVm({ beforePoll: () => gate });
    const secondVm = fakeVm();
    dependencies.connect.mockResolvedValueOnce(firstVm.vm).mockResolvedValueOnce(secondVm.vm);
    kickQueue();
    kickQueue();
    await vi.waitFor(() => expect(firstVm.run.mock.calls.some(([command]) => command.includes("f.seek("))).toBe(true));
    expect(dependencies.connect).toHaveBeenCalledTimes(1);
    expect(apiStore.getScan(second.id)?.status).toBe("QUEUED");
    release();
    await queueState.shipSafeQueue;
    expect(dependencies.connect).toHaveBeenCalledTimes(2);
    expect(apiStore.getScan(first.id)?.status).toBe("COMPLETED");
    expect(apiStore.getScan(second.id)?.status).toBe("COMPLETED");
    expect(apiStore.listFindings(first.id)).toHaveLength(1);
    expect(apiStore.getScan(first.id)?.score).toBeUndefined();
    expect(apiStore.getScan(first.id)?.reportManifest).toMatchObject({ checks: [{ id: "CSP" }] });
  });

  it("does not complete or persist findings when cleanup fails", async () => {
    const job = scan();
    const next = scan();
    dependencies.connect.mockResolvedValue(fakeVm({ cleanupFailure: true }).vm);
    kickQueue();
    await queueState.shipSafeQueue;
    expect(apiStore.getScan(job.id)?.status).toBe("FAILED");
    expect(apiStore.listFindings(job.id)).toHaveLength(0);
    expect(apiStore.getScan(job.id)?.reportManifest).toEqual({ cleanupState: "unverified" });
    expect(apiStore.getScan(next.id)?.status).toBe("QUEUED");
    expect(apiStore.hasCleanupFailure()).toBe(true);
    expect(dependencies.connect).toHaveBeenCalledOnce();
  });

  it("distinguishes a failed baseline request from a cleanup failure", async () => {
    const failed = scan("website");
    const next = scan();
    const failedVm = fakeVm({ lines: [{ type: "error", code: "BASELINE_FAILED", message: "untrusted detail" }] });
    dependencies.connect.mockResolvedValueOnce(failedVm.vm).mockResolvedValueOnce(fakeVm().vm);
    kickQueue();
    await queueState.shipSafeQueue;
    const events = apiStore.listEvents(failed.id);
    expect(apiStore.getScan(failed.id)?.status).toBe("FAILED");
    expect(apiStore.getScan(failed.id)?.reportManifest).toBeUndefined();
    expect(apiStore.hasCleanupFailure()).toBe(false);
    expect(events.find(event => event.stage === "SCAN_FAILED")?.message).toContain("cleanup was verified");
    expect(events.find(event => event.stage === "FAILED")?.message).toMatch(/No score or finding/i);
    expect(events.some(event => event.message.includes("untrusted detail"))).toBe(false);
    expect(apiStore.getScan(next.id)?.status).toBe("COMPLETED");
  });

  it("keeps cancelled jobs cancelled even if an in-flight poll returns a report", async () => {
    const job = scan();
    const fixture = fakeVm({ beforePoll: () => {
      apiStore.updateScan(job.id, { status: "CANCELLED" });
      apiStore.abortExecution(job.id);
    } });
    dependencies.connect.mockResolvedValue(fixture.vm);
    kickQueue();
    await queueState.shipSafeQueue;
    expect(apiStore.getScan(job.id)?.status).toBe("CANCELLED");
    expect(apiStore.listFindings(job.id)).toHaveLength(0);
    expect(fixture.commands.at(-1)).toContain("shutil.rmtree");
  });

  it("never connects or executes if dispatch authorization is missing", async () => {
    const target = apiStore.createProject("test-owner", { name: "Runtime fixture", url: "https://example.test/", environment: "development" });
    const job = apiStore.createScan({ projectId: target.id, url: target.url, mode: "website", scopeAccepted: false });
    kickQueue();
    await queueState.shipSafeQueue;
    expect(dependencies.connect).not.toHaveBeenCalled();
    expect(apiStore.getScan(job.id)?.status).toBe("FAILED");
  });

  it("quarantines the worker and warns explicitly if cancellation cleanup fails", async () => {
    const job = scan();
    const next = scan();
    dependencies.connect.mockResolvedValue(fakeVm({ cleanupFailure: true, beforePoll: () => {
      apiStore.updateScan(job.id, { status: "CANCELLED" });
      apiStore.abortExecution(job.id);
    } }).vm);
    kickQueue();
    await queueState.shipSafeQueue;
    expect(apiStore.getScan(job.id)?.status).toBe("CANCELLED");
    expect(apiStore.getScan(job.id)?.reportManifest).toEqual({ cleanupState: "unverified" });
    expect(apiStore.listEvents(job.id).some(event => event.stage === "CLEANUP_FAILED" && event.message.includes("including after cancellation"))).toBe(true);
    expect(apiStore.getScan(next.id)?.status).toBe("QUEUED");
    expect(apiStore.hasCleanupFailure()).toBe(true);
  });

  it("rejects a mismatched queued hostname before VM activity", async () => {
    const target = apiStore.createProject("test-owner", { name: "Runtime fixture", url: "https://example.test/", environment: "development" });
    const job = apiStore.createScan({ projectId: target.id, url: "https://other.example/", scopeAccepted: true, mode: "website" });
    kickQueue();
    await queueState.shipSafeQueue;
    expect(dependencies.connect).not.toHaveBeenCalled();
    expect(apiStore.getScan(job.id)?.status).toBe("FAILED");
  });
});
