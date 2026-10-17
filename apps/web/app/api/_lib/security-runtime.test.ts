import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SandboxLike } from "@shipsafe/sandbox/live-runner";
import { apiStore, type ScanRecord } from "./store";

const mocks = vi.hoisted(() => ({ connect: vi.fn(), resolveTxt: vi.fn() }));
vi.mock("@shipsafe/sandbox/live-runner", () => ({ getLiveSandbox: mocks.connect }));
vi.mock("node:dns/promises", () => ({ Resolver: vi.fn(function () { return { resolveTxt: mocks.resolveTxt, cancel: vi.fn() }; }) }));
import { kickQueue, runBaseline } from "./baseline-runtime";
const queue = globalThis as typeof globalThis & { shipSafeQueue?: Promise<void> };
const registry = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), "../../packages/sandbox/src/security_registry.json"), "utf8")) as { id: string; category: string; title: string; version: string; implemented: boolean }[];

function setup(mode: "standard" | "deep") {
  const project = apiStore.createProject("owner", { name: "Fixture", url: "https://owned.example.com/", environment: "staging" });
  apiStore.setVerification(project.id, true);
  const grant = mode === "deep" ? apiStore.authorizeDeep("owner", project.id, ["cors"])! : undefined;
  const scan = apiStore.createScan({ projectId: project.id, url: project.url, mode, scopeAccepted: true, authorizationId: grant?.id });
  mocks.resolveTxt.mockResolvedValue([[`shipsafe-verification=${project.verificationToken}`]]);
  return { project, scan, grant };
}
function report(scan: ScanRecord) {
  const results = registry.map(d => ({ id: d.id, category: d.category, title: d.title, version: d.version, status: d.id === "https" ? "PASS" : "NOT_TESTED", confidence: d.id === "https" ? "high" : "none", severity: "info", evidence: "Synthetic transport-contract evidence", timestamp: new Date().toISOString(), affectedUrl: scan.url, why: "Synthetic observation", verification: "Retest with authorization", remediation: "Review the deployed configuration" }));
  return { type: "report", checks: results.map(r => ({ id: r.id, title: r.title, status: r.status === "PASS" ? "passed" : "skipped", evidence: r.evidence, remediation: r.remediation })), findings: [], manifest: { engine: "shipsafe-security", version: "1.0.0", profile: `${scan.mode}-security-v1`, mode: scan.mode, scope: new URL(scan.url).hostname, scopeLimited: false, requests: 1, unifiedResults: results, posture: { value: 100 }, synthetic: true } };
}
function vm(scan: ScanRecord, beforePoll?: () => void, beforeLaunch?: () => void, streamEvents: Record<string, unknown>[] = []) {
  const writes = new Map<string, string>();
  const commands: string[] = [];
  const instance = { files: { write: vi.fn(async (file: string, value: string) => { writes.set(file, value); }) }, commands: { run: vi.fn(async (command: string) => {
    commands.push(command);
    if (command.includes("subprocess.Popen")) beforeLaunch?.();
    if (command.includes("f.seek(")) {
      beforePoll?.();
      const data = [...streamEvents, report(scan)].map(value => JSON.stringify(value)).join("\n") + "\n";
      return { exitCode: 0, stdout: JSON.stringify({ data, bytes: Buffer.byteLength(data) }) };
    }
    return { exitCode: 0, stdout: "" };
  }) } } as unknown as SandboxLike;
  return { instance, writes, commands };
}
beforeEach(() => { apiStore.reset(); mocks.connect.mockReset(); mocks.resolveTxt.mockReset(); });
afterEach(async () => { await queue.shipSafeQueue; apiStore.reset(); });

describe("registered engine dispatch", () => {
  it("stages the allowlist and modules with process limits and never embeds target data into shell text", async () => {
    const { scan } = setup("standard");
    const fake = vm(scan);
    const result = await runBaseline(scan, new AbortController().signal, vi.fn(), async () => fake.instance);
    expect(fake.writes.size).toBe(6);
    expect(fake.writes.has(`${[...fake.writes.keys()].find(key => key.endsWith("security_engine.py"))!.replace(/security_engine\.py$/, "")}baseline.py`)).toBe(true);
    const input = JSON.parse([...fake.writes.entries()].find(([file]) => file.endsWith("input.json"))![1]);
    expect(input).toEqual({ mode: "standard", url: scan.url });
    expect(fake.commands.join("\n")).toContain("--as=268435456");
    expect(fake.commands.join("\n")).not.toContain(scan.url);
    expect(fake.commands.at(-1)).toContain("Process cleanup was not verified");
    expect(result.manifest.posture).toMatchObject({ passed: 1, untestedCredit: 0 });
    expect((result.manifest.posture as { value: number }).value).toBeLessThan(100);
  });

  it("relays check lifecycle metadata and timestamps without truncating messages", async () => {
    const { scan } = setup("standard");
    const timestamp = "2026-10-17T12:34:56.789+00:00";
    const message = "[OBSERVATION] Content Security Policy — " + "recorded detail ".repeat(100);
    const fake = vm(scan, undefined, undefined, [
      { type: "stage", stage: "check", checkId: "csp", message: "Evaluating Content Security Policy...", timestamp },
      { type: "stage", stage: "check_done", checkId: "csp", status: "observation", message, timestamp },
    ]);
    const emit = vi.fn();
    await runBaseline(scan, new AbortController().signal, emit, async () => fake.instance);
    expect(emit).toHaveBeenCalledWith("check", "Evaluating Content Security Policy...", { checkId: "csp", timestamp });
    expect(emit).toHaveBeenCalledWith("check_done", message, { checkId: "csp", status: "observation", timestamp });
  });

  it("rechecks TXT ownership when dispatching a queued Deep job", async () => {
    const { scan } = setup("deep");
    mocks.resolveTxt.mockResolvedValue([]);
    kickQueue(); await queue.shipSafeQueue;
    expect(mocks.resolveTxt).toHaveBeenCalledOnce();
    expect(mocks.connect).not.toHaveBeenCalled();
    expect(apiStore.getScan(scan.id)?.status).toBe("FAILED");
    expect(apiStore.listFindings(scan.id)).toEqual([]);
  });

  it("rejects revocation during an in-flight poll and still verifies cleanup", async () => {
    const { project, scan } = setup("deep");
    const controller = apiStore.claimExecution(scan.id)!;
    const fake = vm(scan, () => { apiStore.revokeDeep("owner", project.id); });
    await expect(runBaseline(scan, controller.signal, vi.fn(), async () => fake.instance)).rejects.toThrow();
    expect(fake.commands.at(-1)).toContain("shutil.rmtree");
    expect(apiStore.getScan(scan.id)?.status).toBe("CANCELLED");
    expect(apiStore.listFindings(scan.id)).toEqual([]);
  });

  it("keeps cancellation terminal when revocation races the VM launch response", async () => {
    const { project, scan } = setup("deep");
    const fake = vm(scan, undefined, () => { apiStore.revokeDeep("owner", project.id); });
    mocks.connect.mockResolvedValue(fake.instance);
    kickQueue(); await queue.shipSafeQueue;
    expect(apiStore.getScan(scan.id)?.status).toBe("CANCELLED");
    expect(apiStore.listEvents(scan.id).some(event => event.stage === "RUNNING")).toBe(false);
    expect(fake.commands.at(-1)).toContain("shutil.rmtree");
  });

  it("dispatches a fresh Deep grant and saves posture only after validated cleanup", async () => {
    const { scan, grant } = setup("deep");
    const fake = vm(scan); mocks.connect.mockResolvedValue(fake.instance);
    kickQueue(); await queue.shipSafeQueue;
    expect(apiStore.getScan(scan.id)).toMatchObject({ status: "COMPLETED", reportManifest: { cleanupState: "verified", profile: "deep-security-v1" } });
    expect(mocks.resolveTxt).toHaveBeenCalledOnce();
    const input = JSON.parse([...fake.writes.entries()].find(([file]) => file.endsWith("input.json"))![1]);
    expect(input.authorization).toEqual({ hostname: grant!.hostname, classes: ["cors"], expiresAt: grant!.expiresAt });
  });
});
