/**
 * @shipsafe/sandbox — live execution helpers for Pure Real Execution Mode.
 *
 * Connects to the operator's real InstaBox micro-VM (credentials from
 * `INSTABOX_API_KEY` / `INSTABOX_SANDBOX_ID`, never committed — see
 * `.gitignore` `.env*.local`), syncs the on-repo runner scripts to the VM
 * via the SDK file channel, and runs the real scanners with log polling.
 *
 * Streaming note: SDK v0.5 `commands.run` has no true streaming (`onStdout`
 * fires once at completion), so `runLiveScan` starts the scan detached
 * (`background: true`) writing to a log file and polls `tail -c` deltas.
 * Every byte delivered to `onStdout` is real VM output — never synthesized.
 *
 * Pull model (S-09): the server drives the VM; the guest receives no
 * control-plane credentials. Quota: one exec slot per scan, 10-min ceiling.
 */
import fs from "node:fs";
import path from "node:path";

/** Local runner filenames synced to the VM (order: entrypoint first). */
export const LIVE_RUNNER_FILES = [
  "shipsafe-runner.sh",
  "scanner.py",
  "osint_engine.py",
] as const;

/**
 * Remote layout lives under the VM user's home (`$HOME/shipsafe`) — the
 * sandbox user is unprivileged, so `/root` is not writable. Result JSONs are
 * read from `<base>/out` (never /tmp, which the runners do not use).
 */
export interface RemotePaths {
  base: string;
  runnerDir: string;
  outDir: string;
  workDir: string;
  log: string;
}

export function remotePaths(base: string): RemotePaths {
  return {
    base,
    runnerDir: `${base}/runner`,
    outDir: `${base}/out`,
    workDir: `${base}/work`,
    log: `${base}/work/scan.log`,
  };
}

/** Detect the writable remote base by asking the VM for `$HOME`. */
export async function resolveRemoteBase(sbx: SandboxLike): Promise<string> {
  const raw = (await sbx.commands.run("echo -n $HOME", {})) as Record<string, any> | string;
  const home =
    typeof raw === "string" ? raw : String(raw?.stdout ?? raw ?? "");
  return `${home.trim() || "/data/home"}/shipsafe`;
}

export const DONE_SENTINEL = "__SHIPSafe_DONE__";

/** Minimal structural surface used from the SDK `Sandbox` object. */
export interface ExecLike {
  run(cmd: string, opts?: Record<string, unknown>): Promise<unknown>;
}

export interface FilesLike {
  read(path: string): Promise<string>;
  write(path: string, data: string | Uint8Array): Promise<unknown>;
}

export interface SandboxLike {
  commands: ExecLike;
  files: FilesLike;
}

export interface LiveSandboxOptions {
  apiKey?: string;
  sandboxId?: string;
  /** Injected SDK module (tests). When omitted, lazily imported. */
  sdk?: unknown;
}

function readEnv(name: string, override: string | undefined): string | undefined {
  return override ?? process.env[name] ?? undefined;
}

/**
 * Connect to the live InstaBox micro-VM.
 * Throws an exact, displayable error when credentials are missing.
 */
export async function getLiveSandbox(opts: LiveSandboxOptions = {}): Promise<SandboxLike> {
  const apiKey = readEnv("INSTABOX_API_KEY", opts.apiKey);
  const sandboxId = readEnv("INSTABOX_SANDBOX_ID", opts.sandboxId);
  if (!apiKey || !sandboxId) {
    throw new Error(
      "INSTABOX_API_KEY and INSTABOX_SANDBOX_ID must be set in .env.local",
    );
  }
  let mod: any;
  if (opts.sdk) {
    mod = opts.sdk;
  } else {
    try {
      mod = await import("@insforge/instabox-sdk");
    } catch (err) {
      throw new Error(
        `InstaBox SDK unavailable: ${(err as Error).message}`,
      );
    }
  }
  const Sandbox = mod.Sandbox ?? mod.default?.Sandbox ?? mod.default ?? mod;
  return (await Sandbox.connect(sandboxId, { apiKey })) as SandboxLike;
}

/**
 * Locate the on-repo `runner/` directory from a starting directory.
 * Checks `<start>/runner` then `<start>/../../runner` (server cwd vs
 * package cwd). Throws an exact error when the scripts are absent.
 */
export function resolveRunnerDir(startDir: string = process.cwd()): string {
  const candidates = [
    path.join(startDir, "runner"),
    path.join(startDir, "..", "..", "runner"),
  ];
  for (const dir of candidates) {
    try {
      if (fs.existsSync(path.join(dir, "scanner.py"))) return dir;
    } catch {
      // try next candidate
    }
  }
  throw new Error(
    `runner scripts not found (looked in ${candidates.join(", ")})`,
  );
}

/** Read the three runner scripts from a local `runner/` dir, keyed by filename. */
export function loadRunnerFiles(runnerDir: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of LIVE_RUNNER_FILES) {
    // Normalize CRLF -> LF: repo checkouts on Windows carry \r\n, which
    // breaks bash (`$'\r': command not found`) and python shebangs on Linux.
    out[name] = fs
      .readFileSync(path.join(runnerDir, name), "utf8")
      .replace(/\r\n/g, "\n");
  }
  return out;
}

/**
 * Push runner scripts to the VM over the SDK file channel (atomic
 * temp-file + rename server-side) and make the entrypoints executable.
 */
export async function syncRunnerToVM(
  sbx: SandboxLike,
  remoteBase: string,
  files: Record<string, string>,
): Promise<void> {
  const paths = remotePaths(remoteBase);
  for (const [name, content] of Object.entries(files)) {
    await sbx.files.write(`${paths.runnerDir}/${name}`, content);
  }
  await sbx.commands.run(`chmod +x ${paths.runnerDir}/shipsafe-runner.sh ${paths.runnerDir}/osint_engine.sh || true`, {});
}

/** Single-quote-escape one shell argument. */
export function shellQuote(arg: string): string {
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export interface LiveStdoutEvents {
  onStdout(chunk: string): void;
}

export interface RunLiveScanOpts {
  pollIntervalMs?: number;
  /** Wall-clock budget (default 9.5 min, under the 10-min exec ceiling). */
  timeoutMs?: number;
  signal?: AbortSignal;
  sleep?: (ms: number) => Promise<void>;
  /** Remote base dir; resolved via `resolveRemoteBase` when omitted. */
  remoteBase?: string;
}

export interface LiveScanResult {
  scanResult: unknown;
  osintResult: unknown;
  exitCode: number | null;
  logText: string;
}

interface RawExec {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

/** Run without ever throwing on non-zero exit (SDK `run` throws CommandExitError). */
async function runRaw(sbx: SandboxLike, cmd: string, timeoutMs: number): Promise<RawExec> {
  try {
    const raw = (await sbx.commands.run(cmd, { timeoutMs })) as Record<string, any> | string;
    if (typeof raw === "string") {
      return { ok: true, stdout: raw, stderr: "", exitCode: 0 };
    }
    const r = (raw ?? {}) as Record<string, any>;
    return {
      ok: true,
      stdout: String(r.stdout ?? r.output ?? ""),
      stderr: String(r.stderr ?? ""),
      exitCode: typeof r.exitCode === "number" ? r.exitCode : 0,
    };
  } catch (err) {
    const e = (err ?? {}) as Record<string, any>;
    const stdout = typeof e.stdout === "string" ? e.stdout : String(e.stdout ?? "");
    const stderr = typeof e.stderr === "string" ? e.stderr : e.message ? String(e.message) : "";
    const exitCode =
      typeof e.exitCode === "number"
        ? e.exitCode
        : typeof e.exit_code === "number"
          ? e.exit_code
          : typeof e.code === "number"
            ? e.code
            : null;
    return { ok: false, stdout, stderr, exitCode };
  }
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Run the real scanners on the live VM and stream real stdout.
 *
 * Starts `shipsafe-runner.sh` + `osint_engine.py` detached (background),
 * appending to a log file with a `__SHIPSafe_DONE__ rc=N` sentinel, then
 * polls `tail -c` deltas until the sentinel, a timeout, or an abort.
 * Returns the parsed `scan_result.json` / `osint_result.json` (null when
 * the scan never produced them — the caller records that as failure data,
 * never as findings).
 */
export async function runLiveScan(
  sbx: SandboxLike,
  targetUrl: string,
  events: LiveStdoutEvents,
  opts: RunLiveScanOpts = {},
): Promise<LiveScanResult> {
  const pollIntervalMs = opts.pollIntervalMs ?? 1500;
  const timeoutMs = opts.timeoutMs ?? 570_000;
  const sleep = opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const quoted = shellQuote(targetUrl);
  const base = opts.remoteBase ?? (await resolveRemoteBase(sbx));
  const paths = remotePaths(base);
  const log = paths.log;

  const launch = [
    `mkdir -p ${paths.outDir} ${paths.workDir} && rm -f ${log}`,
    `(bash ${paths.runnerDir}/shipsafe-runner.sh ${quoted} ${paths.outDir} > ${log} 2>&1`,
    `python3 ${paths.runnerDir}/osint_engine.py ${quoted} ${paths.outDir} >> ${log} 2>&1`,
    `echo "${DONE_SENTINEL} rc=$?" >> ${log})`,
  ].join("; ");

  const started = await sbx.commands.run(launch, { background: true, timeoutMs } as Record<string, unknown>);
  const handle = started as { pid?: number; kill?: () => Promise<unknown> };
  const deadline = Date.now() + timeoutMs;
  let offset = 0;
  let logText = "";
  let exitCode: number | null = null;

  const abort = () => {
    if (typeof handle?.kill === "function") {
      void handle.kill().catch(() => undefined);
    }
  };
  if (opts.signal?.aborted) {
    abort();
    throw new Error("Live scan aborted before polling started");
  }
  const onAbort = () => abort();
  opts.signal?.addEventListener("abort", onAbort, { once: true });

  try {
    for (;;) {
      if (opts.signal?.aborted) throw new Error("Live scan aborted by client disconnect");
      // `tail -c +N` prints from byte N; `|| true` keeps the exit code 0 so
      // the SDK never throws for a missing/empty log mid-startup.
      const tail = await runRaw(sbx, `(tail -c +${offset + 1} ${log} 2>/dev/null || true)`, 30_000);
      if (tail.stdout) {
        offset += Buffer.byteLength(tail.stdout, "utf8");
        logText += tail.stdout;
        events.onStdout(tail.stdout);
      }
      const marker = new RegExp(`${DONE_SENTINEL} rc=(-?\\d+)`).exec(logText);
      if (marker?.[1] !== undefined) {
        exitCode = Number(marker[1]);
        break;
      }
      if (Date.now() >= deadline) {
        abort();
        throw new Error(`Live scan timed out after ${timeoutMs}ms without a completion sentinel`);
      }
      await sleep(pollIntervalMs);
    }
  } finally {
    opts.signal?.removeEventListener("abort", onAbort);
  }

  // Drain any bytes appended with the sentinel write itself.
  const drain = await runRaw(sbx, `(tail -c +${offset + 1} ${log} 2>/dev/null || true)`, 30_000);
  if (drain.stdout) {
    logText += drain.stdout;
    events.onStdout(drain.stdout);
  }

  let scanResult: unknown = null;
  let osintResult: unknown = null;
  try {
    scanResult = tryParseJson(await sbx.files.read(`${paths.outDir}/scan_result.json`));
  } catch {
    scanResult = null;
  }
  try {
    osintResult = tryParseJson(await sbx.files.read(`${paths.outDir}/osint_result.json`));
  } catch {
    osintResult = null;
  }
  return { scanResult, osintResult, exitCode, logText };
}
