import type {
  CreateOpts,
  ExecResult,
  OutputChunkHandler,
  SandboxRef,
  SandboxStatus,
} from "./types.js";

/** Quota / capacity limits (doc/INSTABOX.md §2). */
export const MAX_MACHINES = 5;
export const MAX_CONCURRENT_EXECS = 4;
/** 10-minute command timeout (doc/INSTABOX.md §2). */
export const DEFAULT_TIMEOUT_MS = 600_000;

/**
 * Error raised when the InstaBox account quota is exhausted.
 * Surfaces the upstream `429 quota_exceeded` condition.
 */
export class SandboxQuotaError extends Error {
  readonly code = "quota_exceeded";
  readonly statusCode = 429;
  constructor(message = "InstaBox quota exceeded (429 quota_exceeded)") {
    super(message);
    this.name = "SandboxQuotaError";
  }
}

/** Returns true when an error represents quota exhaustion. */
export function isQuotaError(err: unknown): boolean {
  if (err instanceof SandboxQuotaError) return true;
  if (err && typeof err === "object") {
    const e = err as Record<string, unknown>;
    if (e.code === "quota_exceeded") return true;
    if (e.statusCode === 429 || e.status === 429) return true;
    const msg = String(
      (e.message as string | undefined) ?? (err as Error).message ?? err,
    );
    if (/quota_exceeded/i.test(msg)) return true;
    if (/429/.test(msg) && /quota/i.test(msg)) return true;
  }
  return false;
}

/** Options for {@link SandboxProvider.exec}. */
export interface ExecOptions {
  timeoutMs: number;
  env?: Record<string, string>;
  stdin?: string;
}

/**
 * Single vendor-neutral interface for all scan compute (PRD Appendix A.4).
 *
 * Pull model (S-09): implementations drive the VM through the InstaBox API.
 * The VM never calls back to the control plane and never receives
 * control-plane credentials.
 *
 * Mandatory teardown (S-19): callers MUST invoke `kill` (or `delete`) when a
 * scan finishes, fails, times out, or is cancelled. The reconciler lists
 * machines by `scan_id` / `workspace_id` / `expires_at` labels to reap
 * orphans.
 */
export interface SandboxProvider {
  create(opts: CreateOpts): Promise<SandboxRef>;
  exec(
    ref: SandboxRef,
    cmd: string[],
    o: { timeoutMs: number; env?: Record<string, string>; stdin?: string },
  ): Promise<ExecResult>;
  /**
   * Run a command addressed by sandbox id, streaming stdout/stderr chunks
   * through `onOutputChunk` as they arrive.
   */
  executeCommand(
    sandboxId: string,
    cmd: string[] | string,
    onOutputChunk?: OutputChunkHandler,
  ): Promise<ExecResult>;
  get(ref: SandboxRef): Promise<SandboxStatus>;
  suspend(ref: SandboxRef): Promise<void>;
  stop(ref: SandboxRef): Promise<void>;
  delete(ref: SandboxRef): Promise<void>;
  kill(ref: SandboxRef): Promise<void>;
  list(labels?: Record<string, string>): Promise<SandboxRef[]>;
}
