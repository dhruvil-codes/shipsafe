import type {
  NormalizedFinding,
  ScanEvent,
  SecurityScore,
  ToolResult,
} from "./contracts.js";

/**
 * Minimal sandbox provider surface used by the orchestrator.
 * Duck-type compatible with the Agent 1 sandbox package
 * (`create` / `exec` / `kill`); accept an injected fake in tests so this
 * package never imports a sibling workspace package directly.
 */
export interface SandboxRef {
  id: string;
}

export interface ExecResult {
  stdout: string;
  stderr?: string;
  exitCode: number;
}

export interface SandboxProvider {
  create(opts: { labels: Record<string, string> }): Promise<SandboxRef>;
  exec(
    ref: SandboxRef,
    cmd: string[],
    opts?: { timeoutMs?: number },
  ): Promise<ExecResult>;
  kill(ref: SandboxRef): Promise<void>;
}

/** Structural store surface (compatible with `ScanStore` in `@shipsafe/db`). */
export interface OrchestratorStore {
  updateScan(
    id: string,
    patch: {
      status: string;
      sandboxId?: string;
      score?: number;
      coverage?: number;
    },
  ): Promise<unknown>;
  addFinding(input: {
    scanId: string;
    severity: string;
    title: string;
    description: string;
    evidence: string;
    remediation: string;
    cwe?: string;
  }): Promise<unknown>;
  addEvent(input: {
    scanId: string;
    stage: string;
    message: string;
    timestamp?: Date;
  }): Promise<unknown>;
}

export type NormalizeFn = (results: ToolResult[]) => NormalizedFinding[];
export type ComputeScoreFn = (findings: NormalizedFinding[]) => SecurityScore;
export type OnEventFn = (event: ScanEvent) => void;

export interface RunScanOpts {
  scanId: string;
  targetUrl: string;
  projectId: string;
  store: OrchestratorStore;
  sandboxProvider: SandboxProvider;
  normalize?: NormalizeFn;
  computeScore?: ComputeScoreFn;
  onEvent?: OnEventFn;
  signal?: AbortSignal;
}

export class ScanCancelledError extends Error {
  constructor(scanId: string) {
    super(`scan cancelled: ${scanId}`);
    this.name = "ScanCancelledError";
  }
}

const PENALTY: Record<string, number> = {
  CRITICAL: 40,
  HIGH: 20,
  MEDIUM: 8,
  LOW: 2,
  INFO: 0,
};

function gradeFor(overall: number): SecurityScore["grade"] {
  if (overall >= 90) return "A";
  if (overall >= 75) return "B";
  if (overall >= 50) return "C";
  return "F";
}

/**
 * Default normalize: only `passed` tool runs contribute findings.
 * Failed/skipped tools never improve the score (invariant AC-08) — their
 * output is dropped and only surfaced via events, never as findings.
 */
export function defaultNormalize(results: ToolResult[]): NormalizedFinding[] {
  const out: NormalizedFinding[] = [];
  for (const r of results) {
    if (r.status !== "passed") continue;
    const items = Array.isArray(r.evidence) ? r.evidence : [];
    for (const item of items) {
      const f = item as Partial<NormalizedFinding>;
      if (
        typeof f?.fingerprint === "string" &&
        typeof f?.title === "string"
      ) {
        out.push({
          fingerprint: f.fingerprint,
          target: typeof f.target === "string" ? f.target : "",
          category: (
            ["auth", "api", "source", "storage", "web", "logging"] as const
          ).includes(f.category as NormalizedFinding["category"])
            ? (f.category as NormalizedFinding["category"])
            : "web",
          ruleId: typeof f.ruleId === "string" ? f.ruleId : r.tool,
          title: f.title,
          description: typeof f.description === "string" ? f.description : "",
          severity: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const
          ).includes(f.severity as NormalizedFinding["severity"])
            ? (f.severity as NormalizedFinding["severity"])
            : "INFO",
          evidence: f.evidence ?? null,
          remediation:
            typeof f.remediation === "string" ? f.remediation : "",
          confidence: f.confidence === "suspected" ? "suspected" : "confirmed",
          ...(typeof f.cwe === "string" ? { cwe: f.cwe } : {}),
          ...(typeof f.owasp === "string" ? { owasp: f.owasp } : {}),
        });
      }
    }
  }
  return out;
}

/** Default score: PRD Section 15 starting formula (v1.0, tunable). */
export function defaultComputeScore(
  findings: NormalizedFinding[],
): SecurityScore {
  const confirmed = findings.filter((f) => f.confidence === "confirmed");
  const penalty = confirmed.reduce((sum, f) => sum + (PENALTY[f.severity] ?? 0), 0);
  const raw = Math.max(0, 100 - penalty);
  const hasCritical = confirmed.some((f) => f.severity === "CRITICAL");
  const capped = hasCritical && raw > 40;
  const overall = capped ? 40 : raw;
  return {
    overall,
    grade: gradeFor(overall),
    coverage: 1,
    capped,
    ...(capped
      ? { banner: "Confirmed critical finding caps the score at 40." }
      : {}),
    categoryScores: { overall },
    scoringVersion: "v1.0",
  };
}

function toToolResult(
  tool: string,
  startedAt: number,
  result: ExecResult,
): ToolResult {
  const endedAt = Date.now();
  let parsed: unknown = null;
  try {
    parsed = result.stdout ? JSON.parse(result.stdout) : null;
  } catch {
    parsed = { raw: result.stdout.slice(0, 2000) };
  }
  return {
    tool,
    toolVersion: "1.0.0",
    status: result.exitCode === 0 ? "passed" : "failed",
    startedAt: new Date(startedAt).toISOString(),
    endedAt: new Date(endedAt).toISOString(),
    durationMs: endedAt - startedAt,
    checksAttempted: 1,
    evidence: parsed,
    ...(result.exitCode === 0
      ? {}
      : { error: (result.stderr ?? `exit code ${result.exitCode}`).slice(0, 1000) }),
  };
}

function throwIfAborted(signal: AbortSignal | undefined, scanId: string): void {
  if (signal?.aborted) throw new ScanCancelledError(scanId);
}

/**
 * Coordinate one scan: QUEUED -> PROVISIONING -> RUNNING -> PROCESSING ->
 * COMPLETED (or FAILED / CANCELLED). The sandbox is ALWAYS torn down
 * (S-19 Mandatory Teardown) via try/finally, including on failure and
 * cancellation. Failed tool steps never contribute findings, so they can
 * never improve the score (AC-08).
 */
export async function runScan(
  opts: RunScanOpts,
): Promise<{ score: SecurityScore; findings: NormalizedFinding[] }> {
  const {
    scanId,
    targetUrl,
    projectId,
    store,
    sandboxProvider,
    normalize = defaultNormalize,
    computeScore = defaultComputeScore,
    onEvent,
    signal,
  } = opts;

  const emit = async (stage: string, message: string): Promise<void> => {
    const event: ScanEvent = {
      scanId,
      stage,
      message,
      timestamp: new Date().toISOString(),
    };
    await store.addEvent({
      scanId,
      stage,
      message,
      timestamp: new Date(event.timestamp),
    });
    onEvent?.(event);
  };

  let sandbox: SandboxRef | undefined;
  try {
    throwIfAborted(signal, scanId);
    await store.updateScan(scanId, { status: "QUEUED" });
    await emit("QUEUED", `Scan ${scanId} queued for ${targetUrl}`);

    throwIfAborted(signal, scanId);
    await store.updateScan(scanId, { status: "PROVISIONING" });
    await emit("PROVISIONING", "Provisioning sandbox");
    sandbox = await sandboxProvider.create({
      labels: {
        scan_id: scanId,
        workspace_id: projectId,
        expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
      },
    });
    await store.updateScan(scanId, {
      status: "PROVISIONING",
      sandboxId: sandbox.id,
    });
    await emit("PROVISIONING", `Sandbox ${sandbox.id} ready`);

    throwIfAborted(signal, scanId);
    await store.updateScan(scanId, { status: "RUNNING" });
    await emit("RUNNING", `Running checks against ${targetUrl}`);

    const jobs: Array<{ tool: string; cmd: string[] }> = [
      { tool: "tls-check", cmd: ["tls-check", targetUrl] },
      { tool: "headers-check", cmd: ["headers-check", targetUrl] },
      { tool: "ports-check", cmd: ["ports-check", targetUrl] },
    ];
    const toolResults: ToolResult[] = [];
    for (const job of jobs) {
      throwIfAborted(signal, scanId);
      await emit("RUNNING", `Starting ${job.tool}`);
      const startedAt = Date.now();
      try {
        const execPromise = sandboxProvider.exec(sandbox, job.cmd, {
          timeoutMs: 10 * 60 * 1000,
        });
        const result =
          signal !== undefined
            ? await Promise.race([
                execPromise,
                new Promise<never>((_, reject) => {
                  signal.addEventListener("abort", () =>
                    reject(new ScanCancelledError(scanId)),
                  );
                }),
              ])
            : await execPromise;
        const toolResult = toToolResult(job.tool, startedAt, result);
        toolResults.push(toolResult);
        await emit(
          "RUNNING",
          `${job.tool} ${toolResult.status} (${toolResult.durationMs}ms)`,
        );
      } catch (err) {
        if (err instanceof ScanCancelledError) throw err;
        if (signal?.aborted) throw new ScanCancelledError(scanId);
        // Tool-level failure: record it, keep partial results, continue.
        // The failed step contributes no findings (AC-08).
        toolResults.push({
          tool: job.tool,
          toolVersion: "1.0.0",
          status: "failed",
          startedAt: new Date(startedAt).toISOString(),
          endedAt: new Date().toISOString(),
          durationMs: Date.now() - startedAt,
          checksAttempted: 0,
          evidence: null,
          error: err instanceof Error ? err.message.slice(0, 1000) : String(err),
        });
        await emit(
          "RUNNING",
          `${job.tool} failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    throwIfAborted(signal, scanId);
    await store.updateScan(scanId, { status: "PROCESSING" });
    await emit("PROCESSING", "Normalizing findings and computing score");
    const findings = normalize(toolResults);
    const score = computeScore(findings);
    for (const f of findings) {
      await store.addFinding({
        scanId,
        severity: f.severity,
        title: f.title,
        description: f.description,
        evidence: JSON.stringify(f.evidence ?? null),
        remediation: f.remediation,
        ...(f.cwe ? { cwe: f.cwe } : {}),
      });
    }
    await store.updateScan(scanId, {
      status: "COMPLETED",
      score: score.overall,
      coverage: score.coverage,
    });
    await emit("COMPLETED", `Scan completed: score ${score.overall}`);
    return { score, findings };
  } catch (err) {
    if (err instanceof ScanCancelledError || signal?.aborted) {
      await store.updateScan(scanId, { status: "CANCELLED" });
      await emit("CANCELLED", `Scan ${scanId} cancelled`);
      throw err instanceof Error ? err : new ScanCancelledError(scanId);
    }
    await store.updateScan(scanId, { status: "FAILED" });
    await emit(
      "FAILED",
      `Scan ${scanId} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    throw err;
  } finally {
    // S-19 Mandatory Teardown: always kill the sandbox.
    if (sandbox !== undefined) {
      try {
        await sandboxProvider.kill(sandbox);
      } catch {
        // Best-effort: teardown failure must not mask the scan outcome.
      }
    }
  }
}
