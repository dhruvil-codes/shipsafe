import {
  DEFAULT_TIMEOUT_MS,
  MAX_CONCURRENT_EXECS,
  MAX_MACHINES,
  SandboxQuotaError,
  type SandboxProvider,
} from "./provider.js";
import type {
  CreateOpts,
  ExecResult,
  OutputChunkHandler,
  SandboxRef,
  SandboxStatus,
} from "./types.js";

interface FakeRecord extends SandboxRef {
  createdAt: number;
}

const STREAM_DELAY_MS = 20;

function normalizeCmd(cmd: string[] | string): string[] {
  if (Array.isArray(cmd)) return cmd;
  return ["sh", "-c", cmd];
}

/** Deterministic fake output for well-known probe commands. */
function fakeOutput(cmd: string[]): {
  stdout: string;
  stderr: string;
  exitCode: number;
} {
  const head = (cmd[0] ?? "").toLowerCase();
  const rest = cmd.slice(1);
  if (head === "echo") {
    return { stdout: rest.join(" ") + "\n", stderr: "", exitCode: 0 };
  }
  if (head === "tls-probe") {
    return {
      stdout: JSON.stringify({
        tool: "tls-probe",
        certValid: true,
        expiresInDays: 90,
        ciphers: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        evidence: { raw: "fake-tls-handshake", argv: cmd },
      }),
      stderr: "",
      exitCode: 0,
    };
  }
  if (head === "headers") {
    return {
      stdout: JSON.stringify({
        tool: "headers",
        headers: {
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY",
        },
        evidence: { raw: "fake-http-headers", argv: cmd },
      }),
      stderr: "",
      exitCode: 0,
    };
  }
  if (head === "ports") {
    return {
      stdout: JSON.stringify({
        tool: "ports",
        open: [80, 443],
        evidence: { raw: "fake-port-scan", argv: cmd },
      }),
      stderr: "",
      exitCode: 0,
    };
  }
  return {
    stdout: `fake-exec: ${cmd.join(" ")}\n`,
    stderr: "",
    exitCode: 0,
  };
}

/**
 * In-memory SandboxProvider for unit/integration tests.
 *
 * - Deterministic exec outputs for `echo`, `tls-probe`, `headers`, `ports`.
 * - Streams output via `onOutputChunk` in {@link executeCommand}.
 * - Simulates quota: max 5 machines, max 4 concurrent execs; excess raises
 *   a `quota_exceeded` (429) {@link SandboxQuotaError}.
 * - `kill` / `delete` remove the record (S-19 teardown).
 */
export class FakeSandboxProvider implements SandboxProvider {
  private boxes = new Map<string, FakeRecord>();
  private activeExecs = 0;
  private seq = 0;

  readonly maxMachines: number;
  readonly maxConcurrentExecs: number;
  readonly streamDelayMs: number;

  constructor(
    opts: {
      maxMachines?: number;
      maxConcurrentExecs?: number;
      streamDelayMs?: number;
    } = {},
  ) {
    this.maxMachines = opts.maxMachines ?? MAX_MACHINES;
    this.maxConcurrentExecs = opts.maxConcurrentExecs ?? MAX_CONCURRENT_EXECS;
    this.streamDelayMs = opts.streamDelayMs ?? STREAM_DELAY_MS;
  }

  /** Number of live (non-deleted) sandboxes. */
  get size(): number {
    return this.boxes.size;
  }

  private liveCount(): number {
    return this.boxes.size;
  }

  private idempotencyKey(labels: Record<string, string>): string | null {
    if (!labels.scan_id) return null;
    return `${labels.scan_id}:${labels.step ?? "create"}`;
  }

  async create(opts: CreateOpts): Promise<SandboxRef> {
    // Idempotency: same scan_id+step returns the existing box.
    const key = this.idempotencyKey(opts.labels);
    if (key) {
      for (const rec of this.boxes.values()) {
        const k = this.idempotencyKey(rec.labels);
        if (k === key) return { ...rec };
      }
    }
    if (this.liveCount() >= this.maxMachines) {
      throw new SandboxQuotaError(
        `quota_exceeded: at most ${this.maxMachines} machines (429 quota_exceeded)`,
      );
    }
    this.seq += 1;
    const id = `sbx_fake_${Date.now().toString(36)}_${this.seq}`;
    const template = opts.template ?? opts.snapshotId ?? "universal";
    const rec: FakeRecord = {
      id,
      template,
      status: "running",
      labels: { ...opts.labels },
      createdAt: Date.now(),
    };
    this.boxes.set(id, rec);
    return { ...rec };
  }

  async exec(
    ref: SandboxRef,
    cmd: string[],
    o: { timeoutMs: number; env?: Record<string, string>; stdin?: string },
  ): Promise<ExecResult> {
    const rec = this.boxes.get(ref.id);
    if (!rec) throw new Error(`sandbox not found: ${ref.id}`);
    if (rec.status === "deleted") throw new Error(`sandbox deleted: ${ref.id}`);
    void o;
    if (this.activeExecs >= this.maxConcurrentExecs) {
      throw new SandboxQuotaError(
        `quota_exceeded: at most ${this.maxConcurrentExecs} concurrent execs (429 quota_exceeded)`,
      );
    }
    this.activeExecs += 1;
    const started = Date.now();
    try {
      // Hold the concurrency slot across an async boundary so overlapping
      // `Promise.all` execs genuinely contend for it.
      await new Promise((r) => setTimeout(r, this.streamDelayMs));
      const out = fakeOutput(cmd);
      return {
        stdout: out.stdout,
        stderr: out.stderr,
        exitCode: out.exitCode,
        durationMs: Math.max(0, Date.now() - started),
      };
    } finally {
      this.activeExecs -= 1;
    }
  }

  async executeCommand(
    sandboxId: string,
    cmd: string[] | string,
    onOutputChunk?: OutputChunkHandler,
  ): Promise<ExecResult> {
    const rec = this.boxes.get(sandboxId);
    if (!rec) throw new Error(`sandbox not found: ${sandboxId}`);
    const argv = normalizeCmd(cmd);
    const res = await this.exec(rec, argv, {
      timeoutMs: DEFAULT_TIMEOUT_MS,
    });
    if (onOutputChunk) {
      for (const line of res.stdout.split("\n")) {
        if (line.length === 0) continue;
        onOutputChunk({ stream: "stdout", data: line + "\n" });
      }
      if (res.stderr) {
        for (const line of res.stderr.split("\n")) {
          if (line.length === 0) continue;
          onOutputChunk({ stream: "stderr", data: line + "\n" });
        }
      }
    }
    return res;
  }

  async get(ref: SandboxRef): Promise<SandboxStatus> {
    const rec = this.boxes.get(ref.id);
    if (!rec) return "deleted";
    return rec.status;
  }

  async suspend(ref: SandboxRef): Promise<void> {
    const rec = this.boxes.get(ref.id);
    if (!rec) throw new Error(`sandbox not found: ${ref.id}`);
    rec.status = "suspended";
  }

  async stop(ref: SandboxRef): Promise<void> {
    const rec = this.boxes.get(ref.id);
    if (!rec) throw new Error(`sandbox not found: ${ref.id}`);
    rec.status = "stopped";
  }

  async delete(ref: SandboxRef): Promise<void> {
    this.boxes.delete(ref.id);
  }

  async kill(ref: SandboxRef): Promise<void> {
    // S-19: permanent teardown, releases the quota slot.
    this.boxes.delete(ref.id);
  }

  async list(labels?: Record<string, string>): Promise<SandboxRef[]> {
    const out: SandboxRef[] = [];
    for (const rec of this.boxes.values()) {
      if (labels) {
        let match = true;
        for (const [k, v] of Object.entries(labels)) {
          if (rec.labels[k] !== v) {
            match = false;
            break;
          }
        }
        if (!match) continue;
      }
      const { createdAt: _createdAt, ...ref } = rec;
      void _createdAt;
      out.push({ ...ref });
    }
    return out;
  }
}
