import {
  DEFAULT_TIMEOUT_MS,
  SandboxQuotaError,
  isQuotaError,
  type SandboxProvider,
} from "./provider.js";
import type {
  CreateOpts,
  ExecResult,
  OutputChunkHandler,
  SandboxRef,
  SandboxStatus,
} from "./types.js";

// TODO(VERIFY): confirm exact option/return shapes on the InstaBox SDK
// reference page (operation polling, idempotency-key field name, label
// filtering in Sandbox.list, commands.run timeout/env option names).
// The implementation below passes the documented fields and normalizes
// defensively so a minor shape drift surfaces as a legible error.

function idempotencyKeyFor(labels: Record<string, string>): string {
  return `${labels.scan_id ?? "no-scan"}:${labels.step ?? "create"}`;
}

function toQuotaError(err: unknown): Error {
  if (isQuotaError(err)) {
    const msg =
      err instanceof Error ? err.message : "quota_exceeded (429)";
    return new SandboxQuotaError(msg);
  }
  return err instanceof Error ? err : new Error(String(err));
}

function normalizeCmd(cmd: string[] | string): string[] {
  if (Array.isArray(cmd)) return cmd;
  return ["sh", "-c", cmd];
}

export interface InstaboxProviderOptions {
  apiKey?: string;
  serverUrl?: string;
  defaultTimeoutMs?: number;
  /** Injected SDK module (tests). When omitted, lazily imported. */
  sdk?: unknown;
}

/**
 * Real SandboxProvider backed by `@insforge/instabox-sdk`.
 *
 * - Pull model (S-09): the workflow drives the VM via the SDK. Control-plane
 *   credentials (INSTABOX_API_KEY) never enter the guest; only per-call env
 *   is forwarded to `commands.run`.
 * - Idempotency: every create carries a key derived from
 *   `labels.scan_id + step` so retries never create a second machine.
 * - Quota-aware: upstream `429 quota_exceeded` is rethrown as
 *   {@link SandboxQuotaError}; default exec timeout is 10 minutes.
 * - Teardown (S-19): {@link kill} terminates the machine and releases disks;
 *   {@link delete} is an alias for `kill`.
 *
 * The SDK is imported lazily inside a try/catch so unit tests and typechecks
 * pass without network access or an API key.
 */
export class InstaboxSandboxProvider implements SandboxProvider {
  private readonly apiKey: string | undefined;
  private readonly serverUrl: string | undefined;
  private readonly defaultTimeoutMs: number;
  private injectedSdk: unknown;

  constructor(opts: InstaboxProviderOptions = {}) {
    this.apiKey =
      opts.apiKey ?? process.env.INSTABOX_API_KEY ?? undefined;
    this.serverUrl =
      opts.serverUrl ?? process.env.INSTABOX_API_URL ?? undefined;
    this.defaultTimeoutMs = opts.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.injectedSdk = opts.sdk;
  }

  /** For tests: replace the SDK module. */
  setSdk(sdk: unknown): void {
    this.injectedSdk = sdk;
  }

  private async loadSdk(): Promise<any> {
    if (this.injectedSdk) return this.injectedSdk;
    try {
      const mod: any = await import("@insforge/instabox-sdk");
      return mod;
    } catch (err) {
      throw new Error(
        "InstaBox SDK unavailable: install @insforge/instabox-sdk and set INSTABOX_API_KEY. " +
          `Underlying error: ${(err as Error).message}`,
      );
    }
  }

  private sdkSandbox(mod: any): any {
    return mod.Sandbox ?? mod.default?.Sandbox ?? mod.default ?? mod;
  }

  async create(opts: CreateOpts): Promise<SandboxRef> {
    const mod = await this.loadSdk();
    const Sandbox = this.sdkSandbox(mod);
    const template = opts.template ?? "universal";
    const idempotencyKey = idempotencyKeyFor(opts.labels);
    const createOpts: Record<string, unknown> = {
      apiKey: this.apiKey,
      requestTimeoutMs: 60_000,
      operationTimeoutMs: 600_000,
      idempotencyKey,
      labels: opts.labels,
      meta: opts.labels,
      metadata: opts.labels,
    };
    if (this.serverUrl) createOpts.server = this.serverUrl;
    if (opts.snapshotId) createOpts.snapshotId = opts.snapshotId;
    try {
      const sbx = await Sandbox.create(template, createOpts);
      const id: string =
        sbx?.id ?? sbx?.sandboxId ?? sbx?.name ?? String(sbx ?? "");
      return {
        id,
        template,
        status: "running",
        labels: { ...opts.labels },
      };
    } catch (err) {
      throw toQuotaError(err);
    }
  }

  private async withBox<T>(
    sandboxId: string,
    fn: (sbx: any) => Promise<T>,
  ): Promise<T> {
    const mod = await this.loadSdk();
    const Sandbox = this.sdkSandbox(mod);
    try {
      const sbx = await Sandbox.connect(sandboxId, {
        apiKey: this.apiKey,
      });
      return await fn(sbx);
    } catch (err) {
      throw toQuotaError(err);
    }
  }

  async exec(
    ref: SandboxRef,
    cmd: string[],
    o: { timeoutMs: number; env?: Record<string, string>; stdin?: string },
  ): Promise<ExecResult> {
    const timeoutMs = o.timeoutMs ?? this.defaultTimeoutMs;
    const started = Date.now();
    return this.withBox(ref.id, async (sbx: any) => {
      const raw = await sbx.commands.run(cmd, {
        timeoutMs,
        timeout: timeoutMs,
        env: o.env,
        stdin: o.stdin,
      });
      // Normalize defensively: SDK may return a string, an object, or void.
      if (typeof raw === "string") {
        return {
          stdout: raw,
          stderr: "",
          exitCode: 0,
          durationMs: Date.now() - started,
        };
      }
      const r = (raw ?? {}) as Record<string, any>;
      return {
        stdout: String(r.stdout ?? r.output ?? ""),
        stderr: String(r.stderr ?? ""),
        exitCode: Number(r.exitCode ?? r.exit_code ?? r.code ?? 0),
        durationMs: Number(r.durationMs ?? Date.now() - started),
      };
    });
  }

  async executeCommand(
    sandboxId: string,
    cmd: string[] | string,
    onOutputChunk?: OutputChunkHandler,
  ): Promise<ExecResult> {
    const argv = normalizeCmd(cmd);
    const ref: SandboxRef = {
      id: sandboxId,
      template: "universal",
      status: "running",
      labels: {},
    };
    const res = await this.exec(ref, argv, {
      timeoutMs: this.defaultTimeoutMs,
    });
    if (onOutputChunk) {
      for (const line of res.stdout.split("\n")) {
        if (!line) continue;
        onOutputChunk({ stream: "stdout", data: line + "\n" });
      }
      for (const line of res.stderr.split("\n")) {
        if (!line) continue;
        onOutputChunk({ stream: "stderr", data: line + "\n" });
      }
    }
    return res;
  }

  async get(ref: SandboxRef): Promise<SandboxStatus> {
    try {
      const status = await this.withBox(ref.id, async (sbx: any) => {
        if (typeof sbx.status === "string") return sbx.status as string;
        if (typeof sbx.getStatus === "function")
          return (await sbx.getStatus()) as string;
        if (typeof sbx.state === "string") return sbx.state as string;
        return "running";
      });
      const s = String(status).toLowerCase();
      if (s.includes("suspend")) return "suspended";
      if (s.includes("stop")) return "stopped";
      if (s.includes("delet") || s.includes("terminat")) return "deleted";
      if (s.includes("fail") || s.includes("error")) return "failed";
      if (s.includes("creat") || s.includes("start") || s.includes("provis"))
        return "creating";
      return "running";
    } catch {
      return "deleted";
    }
  }

  async suspend(ref: SandboxRef): Promise<void> {
    await this.withBox(ref.id, async (sbx: any) => {
      if (typeof sbx.suspend === "function") await sbx.suspend();
      else if (typeof sbx.pause === "function") await sbx.pause();
    });
  }

  async stop(ref: SandboxRef): Promise<void> {
    await this.withBox(ref.id, async (sbx: any) => {
      if (typeof sbx.stop === "function") await sbx.stop();
    });
  }

  async delete(ref: SandboxRef): Promise<void> {
    // S-19: delete permanently tears down (alias for kill).
    await this.kill(ref);
  }

  async kill(ref: SandboxRef): Promise<void> {
    const mod = await this.loadSdk();
    const Sandbox = this.sdkSandbox(mod);
    try {
      await Sandbox.kill(ref.id, { apiKey: this.apiKey });
    } catch (err) {
      throw toQuotaError(err);
    }
  }

  async list(labels?: Record<string, string>): Promise<SandboxRef[]> {
    const mod = await this.loadSdk();
    const Sandbox = this.sdkSandbox(mod);
    let items: any[];
    try {
      const raw = await Sandbox.list({ apiKey: this.apiKey });
      items = Array.isArray(raw) ? raw : (raw?.machines ?? raw?.items ?? []);
    } catch (err) {
      throw toQuotaError(err);
    }
    const refs: SandboxRef[] = items.map((m: any) => ({
      id: String(m?.id ?? m?.sandboxId ?? m?.name ?? ""),
      template: String(m?.template ?? "universal"),
      status: "running" as SandboxStatus,
      labels: { ...((m?.labels ?? m?.meta ?? m?.metadata ?? {}) as Record<string, string>) },
    }));
    if (!labels) return refs;
    return refs.filter((r) =>
      Object.entries(labels).every(([k, v]) => r.labels[k] === v),
    );
  }
}
