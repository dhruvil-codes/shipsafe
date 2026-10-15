import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  create: vi.fn(),
  connect: vi.fn(),
  list: vi.fn(),
  kill: vi.fn(),
}));

vi.mock("@insforge/instabox-sdk", () => ({
  Sandbox: {
    create: mocks.create,
    connect: mocks.connect,
    list: mocks.list,
    kill: mocks.kill,
  },
}));

import { InstaboxSandboxProvider } from "./instabox-provider.js";
import { SandboxQuotaError } from "./provider.js";

function runningBox(runResult: unknown = { stdout: "ok\n", stderr: "", exitCode: 0 }) {
  return {
    id: "sbx_mock_1",
    commands: { run: vi.fn().mockResolvedValue(runResult) },
    status: "running",
  };
}

beforeEach(() => {
  mocks.create.mockReset();
  mocks.connect.mockReset();
  mocks.list.mockReset();
  mocks.kill.mockReset();
});

describe("InstaboxSandboxProvider (mocked SDK)", () => {
  it("create calls Sandbox.create with template + idempotency key from scan_id", async () => {
    mocks.create.mockResolvedValue({ id: "sbx_abc" });
    const p = new InstaboxSandboxProvider({
      apiKey: "ibk_test",
      sdk: undefined,
    });
    const ref = await p.create({
      template: "universal",
      labels: { scan_id: "scn_123", workspace_id: "ws_1" },
    });
    expect(ref.id).toBe("sbx_abc");
    expect(mocks.create).toHaveBeenCalledTimes(1);
    const [template, opts] = mocks.create.mock.calls[0] as [string, Record<string, unknown>];
    expect(template).toBe("universal");
    expect(String(opts.idempotencyKey)).toContain("scn_123");
    expect(opts.apiKey).toBe("ibk_test");
  });

  it("exec runs via Sandbox.connect + commands.run", async () => {
    const box = runningBox();
    mocks.connect.mockResolvedValue(box);
    const p = new InstaboxSandboxProvider({ apiKey: "ibk_test" });
    const res = await p.exec(
      { id: "sbx_abc", template: "universal", status: "running", labels: {} },
      ["echo", "hi"],
      { timeoutMs: 60_000 },
    );
    expect(mocks.connect).toHaveBeenCalledWith("sbx_abc", expect.anything());
    expect(box.commands.run).toHaveBeenCalledWith(
      ["echo", "hi"],
      expect.objectContaining({ timeoutMs: 60_000 }),
    );
    expect(res.stdout).toBe("ok\n");
    expect(res.exitCode).toBe(0);
  });

  it("executeCommand streams chunks via onOutputChunk", async () => {
    const box = runningBox({ stdout: "a\nb\n", stderr: "", exitCode: 0 });
    mocks.connect.mockResolvedValue(box);
    const p = new InstaboxSandboxProvider({ apiKey: "ibk_test" });
    const chunks: Array<{ stream: string; data: string }> = [];
    const res = await p.executeCommand("sbx_abc", ["echo", "hi"], (c) =>
      chunks.push(c),
    );
    expect(res.exitCode).toBe(0);
    expect(chunks.map((c) => c.data).join("")).toContain("a\n");
  });

  it("surfaces 429 quota_exceeded as SandboxQuotaError", async () => {
    const quotaErr = Object.assign(new Error("429 quota_exceeded"), {
      statusCode: 429,
      code: "quota_exceeded",
    });
    mocks.create.mockRejectedValue(quotaErr);
    const p = new InstaboxSandboxProvider({ apiKey: "ibk_test" });
    await expect(
      p.create({ template: "universal", labels: { scan_id: "scn_q" } }),
    ).rejects.toBeInstanceOf(SandboxQuotaError);
  });

  it("kill calls Sandbox.kill and delete aliases kill (S-19)", async () => {
    mocks.kill.mockResolvedValue(undefined);
    const p = new InstaboxSandboxProvider({ apiKey: "ibk_test" });
    const ref = {
      id: "sbx_gone",
      template: "universal",
      status: "running" as const,
      labels: {},
    };
    await p.kill(ref);
    expect(mocks.kill).toHaveBeenCalledWith("sbx_gone", expect.anything());
    await p.delete(ref);
    expect(mocks.kill).toHaveBeenCalledTimes(2);
  });

  it("list filters by labels client-side", async () => {
    mocks.list.mockResolvedValue([
      { id: "a", template: "universal", labels: { scan_id: "s1" } },
      { id: "b", template: "universal", labels: { scan_id: "s2" } },
    ]);
    const p = new InstaboxSandboxProvider({ apiKey: "ibk_test" });
    expect(await p.list()).toHaveLength(2);
    expect(await p.list({ scan_id: "s1" })).toHaveLength(1);
  });
});
