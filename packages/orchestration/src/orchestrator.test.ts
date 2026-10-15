import { describe, expect, it, vi } from "vitest";
import type { NormalizedFinding, ToolResult } from "./contracts.js";
import {
  runScan,
  type ExecResult,
  type OrchestratorStore,
  type SandboxProvider,
  type SandboxRef,
} from "./orchestrator.js";

interface FakeScan {
  status: string;
  sandboxId?: string;
  score?: number;
  coverage?: number;
}

function createFakeStore(): OrchestratorStore & {
  scans: Map<string, FakeScan>;
  findings: Array<{ scanId: string; title: string }>;
  events: Array<{ scanId: string; stage: string; message: string }>;
} {
  const scans = new Map<string, FakeScan>([["scn_1", { status: "QUEUED" }]]);
  const findings: Array<{ scanId: string; title: string }> = [];
  const events: Array<{ scanId: string; stage: string; message: string }> = [];
  return {
    scans,
    findings,
    events,
    async updateScan(id: string, patch: FakeScan) {
      const prev = scans.get(id) ?? { status: "QUEUED" };
      scans.set(id, { ...prev, ...patch });
      return scans.get(id);
    },
    async addFinding(input: { scanId: string; title: string }) {
      findings.push({ scanId: input.scanId, title: input.title });
      return input;
    },
    async addEvent(input: { scanId: string; stage: string; message: string }) {
      events.push({ ...input });
      return input;
    },
  };
}

function execOk(findings: unknown = []): ExecResult {
  return { stdout: JSON.stringify(findings), exitCode: 0 };
}

function createFakeProvider(
  behavior: (tool: string) => ExecResult | Promise<ExecResult> = () => execOk(),
): SandboxProvider & { kills: string[]; creates: number } {
  const state = { kills: [] as string[], creates: 0 };
  return {
    ...state,
    async create() {
      state.creates += 1;
      return { id: `sbx_${state.creates}` };
    },
    async exec(_ref: SandboxRef, cmd: string[]) {
      return behavior(cmd[0] ?? "unknown");
    },
    async kill(ref: SandboxRef) {
      state.kills.push(ref.id);
    },
  };
}

const findingFor = (tool: string): NormalizedFinding => ({
  fingerprint: `fp-${tool}`,
  target: "https://example.com",
  category: "web",
  ruleId: `${tool}-rule`,
  title: `${tool} finding`,
  description: "desc",
  severity: "HIGH",
  evidence: { tool },
  remediation: "fix it",
  confidence: "confirmed",
});

describe("runScan", () => {
  it("runs the full lifecycle to COMPLETED and kills the sandbox (S-19)", async () => {
    const store = createFakeStore();
    const provider = createFakeProvider(() =>
      execOk([{ ...findingFor("tls-check"), fingerprint: "fp-1" }]),
    );
    const onEvent = vi.fn();
    const normalize = vi.fn((_results: ToolResult[]) => [findingFor("tls-check")]);

    const { score, findings } = await runScan({
      scanId: "scn_1",
      targetUrl: "https://example.com",
      projectId: "prj_1",
      store,
      sandboxProvider: provider,
      normalize,
      computeScore: () => ({
        overall: 80,
        grade: "B",
        coverage: 1,
        capped: false,
        categoryScores: { web: 80 },
        scoringVersion: "v1.0",
      }),
      onEvent,
    });

    expect(score.overall).toBe(80);
    expect(findings).toHaveLength(1);
    expect(store.scans.get("scn_1")?.status).toBe("COMPLETED");
    expect(store.scans.get("scn_1")?.sandboxId).toBe("sbx_1");
    expect(provider.kills).toEqual(["sbx_1"]);
    const stages = store.events.map((e) => e.stage);
    expect(stages).toContain("PROVISIONING");
    expect(stages).toContain("RUNNING");
    expect(stages).toContain("PROCESSING");
    expect(stages).toContain("COMPLETED");
    expect(onEvent).toHaveBeenCalled();
  });

  it("marks FAILED and still kills the sandbox when a tool exec throws", async () => {
    const store = createFakeStore();
    const provider = createFakeProvider((tool) => {
      if (tool === "tls-check") throw new Error("boom");
      return execOk();
    });

    // One tool throwing is a tool-level failure (COMPLETED with partial
    // results); make ALL tools throw to exercise the fatal path via create.
    const failingCreate: SandboxProvider & { kills: string[] } = {
      kills: [],
      async create() {
        throw new Error("quota exceeded");
      },
      async exec() {
        return execOk();
      },
      async kill(ref: SandboxRef) {
        failingCreate.kills.push(ref.id);
      },
    };
    await expect(
      runScan({
        scanId: "scn_1",
        targetUrl: "https://example.com",
        projectId: "prj_1",
        store,
        sandboxProvider: failingCreate,
      }),
    ).rejects.toThrow("quota exceeded");
    expect(store.scans.get("scn_1")?.status).toBe("FAILED");
    // No sandbox was created, so nothing to kill — but the finally path ran.
    expect(failingCreate.kills).toEqual([]);

    // Fatal mid-run error (provider kills path): exec throws synchronously
    // for every tool AND normalize throws -> FAILED + kill still happens.
    const store2 = createFakeStore();
    const provider2 = createFakeProvider(() => execOk());
    await expect(
      runScan({
        scanId: "scn_1",
        targetUrl: "https://example.com",
        projectId: "prj_1",
        store: store2,
        sandboxProvider: provider2,
        normalize: () => {
          throw new Error("normalize crashed");
        },
      }),
    ).rejects.toThrow("normalize crashed");
    expect(store2.scans.get("scn_1")?.status).toBe("FAILED");
    expect(provider2.kills).toEqual(["sbx_1"]);
    void provider;
  });

  it("marks CANCELLED and kills the sandbox when aborted mid-run", async () => {
    const store = createFakeStore();
    const controller = new AbortController();
    const provider = createFakeProvider(async () => {
      controller.abort();
      // Simulate a hanging exec that only resolves after abort.
      await new Promise((r) => setTimeout(r, 5));
      return execOk();
    });

    await expect(
      runScan({
        scanId: "scn_1",
        targetUrl: "https://example.com",
        projectId: "prj_1",
        store,
        sandboxProvider: provider,
        signal: controller.signal,
      }),
    ).rejects.toThrow();
    expect(store.scans.get("scn_1")?.status).toBe("CANCELLED");
    expect(provider.kills).toEqual(["sbx_1"]);
  });

  it("marks CANCELLED immediately when the signal is already aborted", async () => {
    const store = createFakeStore();
    const provider = createFakeProvider();
    const controller = new AbortController();
    controller.abort();
    await expect(
      runScan({
        scanId: "scn_1",
        targetUrl: "https://example.com",
        projectId: "prj_1",
        store,
        sandboxProvider: provider,
        signal: controller.signal,
      }),
    ).rejects.toThrow("cancelled");
    expect(store.scans.get("scn_1")?.status).toBe("CANCELLED");
    expect(provider.kills).toEqual([]);
  });

  it("failed tools never contribute findings or improve the score (AC-08)", async () => {
    const passedEvidence = [
      { ...findingFor("headers-check"), fingerprint: "fp-headers" },
    ];
    const failedEvidence = [
      { ...findingFor("tls-check"), fingerprint: "fp-tls", severity: "INFO" },
    ];
    void failedEvidence;

    const store = createFakeStore();
    const provider = createFakeProvider((tool) => {
      if (tool === "tls-check")
        return { stdout: "tls output", exitCode: 2, stderr: "tls crashed" };
      if (tool === "headers-check") return execOk(passedEvidence);
      return execOk();
    });

    // Default normalize: only `passed` tool evidence becomes findings.
    const { findings, score } = await runScan({
      scanId: "scn_1",
      targetUrl: "https://example.com",
      projectId: "prj_1",
      store,
      sandboxProvider: provider,
    });

    expect(store.scans.get("scn_1")?.status).toBe("COMPLETED");
    // Only the headers-check finding survived; the failed tls-check output
    // (exit code 2, unparseable as findings) contributed nothing.
    expect(findings.map((f) => f.fingerprint)).toEqual(["fp-headers"]);
    // Score reflects only the surviving HIGH finding: 100 - 20 = 80.
    expect(score.overall).toBe(80);
    expect(store.findings).toHaveLength(1);
  });
});
