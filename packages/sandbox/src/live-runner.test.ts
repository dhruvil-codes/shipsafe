/**
 * live-runner tests: injected fakes only — no network, no credentials.
 * Real VM connectivity is verified manually against the operator's sandbox;
 * these tests pin the contract (env errors, file sync, poll/sentinel loop,
 * timeout kill, abort kill).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DONE_SENTINEL,
  getLiveSandbox,
  loadRunnerFiles,
  resolveRemoteBase,
  resolveRunnerDir,
  runLiveScan,
  shellQuote,
  syncRunnerToVM,
  type SandboxLike,
} from "./live-runner.js";

const ENV_KEYS = ["INSTABOX_API_KEY", "INSTABOX_SANDBOX_ID"];

function clearLiveEnv(): void {
  for (const k of ENV_KEYS) delete process.env[k];
}

function makeFakeBox(handlers: {
  onRun?: (cmd: string) => unknown;
  files?: Record<string, string>;
}): SandboxLike & { runs: string[]; writes: Array<[string, string]> } {
  const runs: string[] = [];
  const writes: Array<[string, string]> = [];
  const store: Record<string, string> = { ...(handlers.files ?? {}) };
  const box: SandboxLike & { runs: string[]; writes: Array<[string, string]> } = {
    runs,
    writes,
    commands: {
      run: async (cmd: string) => {
        runs.push(cmd);
        return handlers.onRun?.(cmd);
      },
    },
    files: {
      read: async (p: string) => {
        if (!(p in store)) throw new Error(`no such file: ${p}`);
        return store[p] as string;
      },
      write: async (p: string, data: string | Uint8Array) => {
        writes.push([p, String(data)]);
        store[p] = String(data);
        return { path: p };
      },
    },
  };
  return box;
}

describe("getLiveSandbox", () => {
  beforeEach(clearLiveEnv);
  afterEach(clearLiveEnv);

  it("throws an exact error when credentials are missing", async () => {
    await expect(getLiveSandbox()).rejects.toThrow(
      "INSTABOX_API_KEY and INSTABOX_SANDBOX_ID must be set in .env.local",
    );
  });

  it("connects through the injected SDK with the env credentials", async () => {
    process.env.INSTABOX_API_KEY = "ibk_test";
    process.env.INSTABOX_SANDBOX_ID = "m_test";
    const fakeBox = { commands: {}, files: {} };
    const connect = vi.fn(async () => fakeBox);
    const box = await getLiveSandbox({ sdk: { Sandbox: { connect } } });
    expect(connect).toHaveBeenCalledWith("m_test", { apiKey: "ibk_test" });
    expect(box).toBe(fakeBox);
  });
});

describe("resolveRunnerDir / loadRunnerFiles", () => {
  it("throws an exact error when no runner dir exists", () => {
    expect(() => resolveRunnerDir("/definitely/not/here")).toThrow(
      /runner scripts not found/,
    );
  });

  it("loads the three real runner scripts from the repo", () => {
    const dir = resolveRunnerDir(process.cwd());
    const files = loadRunnerFiles(dir);
    expect(Object.keys(files).sort()).toEqual(
      ["shipsafe-runner.sh", "scanner.py", "osint_engine.py"].sort(),
    );
    for (const content of Object.values(files)) {
      expect(content.length).toBeGreaterThan(0);
    }
  });

  it("normalizes CRLF to LF for the Linux VM", async () => {
    const { default: fs } = await import("node:fs");
    const { default: os } = await import("node:os");
    const { default: path } = await import("node:path");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shipsafe-runner-"));
    for (const name of ["shipsafe-runner.sh", "scanner.py", "osint_engine.py"]) {
      fs.writeFileSync(path.join(dir, name), "#!/usr/bin/env bash\r\necho hi\r\n");
    }
    const files = loadRunnerFiles(dir);
    for (const content of Object.values(files)) {
      expect(content).not.toContain("\r");
      expect(content).toContain("echo hi\n");
    }
  });
});

describe("resolveRemoteBase", () => {
  it("derives the base from the VM home directory", async () => {
    const box = makeFakeBox({
      onRun: (cmd: string) =>
        cmd.includes("echo -n $HOME")
          ? { stdout: "/data/home", stderr: "", exitCode: 0 }
          : { stdout: "", stderr: "", exitCode: 0 },
    });
    await expect(resolveRemoteBase(box)).resolves.toBe("/data/home/shipsafe");
  });
});

describe("shellQuote", () => {
  it("single-quote-escapes hostile targets", () => {
    expect(shellQuote("https://example.com")).toBe("'https://example.com'");
    expect(shellQuote("a'b")).toBe(`'a'\\''b'`);
  });
});

describe("syncRunnerToVM", () => {
  it("writes every file over the file channel and chmods entrypoints", async () => {
    const box = makeFakeBox({});
    await syncRunnerToVM(box, "/data/home/shipsafe", {
      "scanner.py": "print(1)",
      "osint_engine.py": "print(2)",
    });
    expect(box.writes.map(([p]) => p)).toEqual([
      "/data/home/shipsafe/runner/scanner.py",
      "/data/home/shipsafe/runner/osint_engine.py",
    ]);
    expect(box.runs.some((c) => c.includes("chmod +x"))).toBe(true);
  });
});

describe("runLiveScan", () => {
  it("polls the log, streams deltas, and returns parsed results", async () => {
    const fullLog = `[tls] probing\n[tls] OK\n${DONE_SENTINEL} rc=0\n`;
    const fullBytes = Buffer.from(fullLog, "utf8");
    const box = makeFakeBox({
      onRun: (cmd: string) => {
        if (cmd.includes("mkdir -p") || cmd.includes("shipsafe-runner.sh")) {
          return { pid: 4242, kill: async () => true };
        }
        // Emulate `tail -c +N` byte-offset semantics like the real command.
        const at = /tail -c \+(\d+)/.exec(cmd);
        const start = at?.[1] !== undefined ? Number(at[1]) - 1 : 0;
        const slice = Buffer.from(fullBytes.slice(start)).toString("utf8");
        // First poll only reveals the first line (log still growing).
        const revealed = start === 0 ? slice.slice(0, 14) : slice;
        return { stdout: revealed, stderr: "", exitCode: 0 };
      },
      files: {
        "/data/home/shipsafe/out/scan_result.json": JSON.stringify({
          target: "https://example.com",
          tools: [],
        }),
        "/data/home/shipsafe/out/osint_result.json": JSON.stringify({
          tool: "osint-suite",
          status: "passed",
        }),
      },
    });
    const chunks: string[] = [];
    const res = await runLiveScan(
      box,
      "https://example.com",
      { onStdout: (c) => chunks.push(c) },
      { pollIntervalMs: 0, sleep: async () => undefined, remoteBase: "/data/home/shipsafe" },
    );
    expect(chunks.join("")).toBe(fullLog);
    expect(res.exitCode).toBe(0);
    expect(res.scanResult).toMatchObject({ target: "https://example.com" });
    expect(res.osintResult).toMatchObject({ tool: "osint-suite" });
    // Launch command quotes the target, backgrounds the run, and uses
    // python3 for the Python engine (never bash).
    expect(box.runs[0]).toContain("'https://example.com'");
    expect(box.runs[0]).toContain("python3");
    expect(box.runs[0]).toContain("osint_engine.py");
    expect(box.runs[0]).not.toMatch(/bash [^;]*osint_engine\.py/);
  });

  it("returns null results when the VM produced no result files", async () => {
    const box = makeFakeBox({
      onRun: (cmd: string) => {
        if (cmd.includes("shipsafe-runner.sh")) {
          return { pid: 1, kill: async () => true };
        }
        return { stdout: `${DONE_SENTINEL} rc=1\n`, stderr: "", exitCode: 0 };
      },
      files: {},
    });
    const res = await runLiveScan(
      box,
      "https://example.com",
      { onStdout: () => undefined },
      { pollIntervalMs: 0, sleep: async () => undefined, remoteBase: "/data/home/shipsafe" },
    );
    expect(res.exitCode).toBe(1);
    expect(res.scanResult).toBeNull();
    expect(res.osintResult).toBeNull();
  });

  it("kills the background run and throws on timeout", async () => {
    let killed = false;
    const box = makeFakeBox({
      onRun: (cmd: string) => {
        if (cmd.includes("shipsafe-runner.sh")) {
          return { pid: 9, kill: async () => { killed = true; return true; } };
        }
        return { stdout: "[tls] still going\n", stderr: "", exitCode: 0 };
      },
    });
    await expect(
      runLiveScan(
        box,
        "https://example.com",
        { onStdout: () => undefined },
        { pollIntervalMs: 0, timeoutMs: 5, sleep: async () => undefined, remoteBase: "/data/home/shipsafe" },
      ),
    ).rejects.toThrow(/timed out/);
    expect(killed).toBe(true);
  });

  it("kills the background run on abort", async () => {
    let killed = false;
    const box = makeFakeBox({
      onRun: (cmd: string) => {
        if (cmd.includes("shipsafe-runner.sh")) {
          return { pid: 9, kill: async () => { killed = true; return true; } };
        }
        return { stdout: "", stderr: "", exitCode: 0 };
      },
    });
    const controller = new AbortController();
    const pending = runLiveScan(
      box,
      "https://example.com",
      { onStdout: () => undefined },
      {
        pollIntervalMs: 5,
        timeoutMs: 60_000,
        signal: controller.signal,
        remoteBase: "/data/home/shipsafe",
        sleep: async () => {
          controller.abort();
        },
      },
    );
    await expect(pending).rejects.toThrow(/abort/i);
    expect(killed).toBe(true);
  });
});
