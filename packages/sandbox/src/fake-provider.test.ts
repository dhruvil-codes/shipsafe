import { describe, expect, it } from "vitest";
import { FakeSandboxProvider } from "./fake-provider.js";
import { SandboxQuotaError } from "./provider.js";

describe("FakeSandboxProvider", () => {
  it("creates a sandbox with labels (reconciler labels)", async () => {
    const p = new FakeSandboxProvider();
    const ref = await p.create({
      template: "universal",
      labels: {
        scan_id: "scn_123",
        workspace_id: "ws_1",
        expires_at: "2030-01-01T00:00:00Z",
      },
    });
    expect(ref.id).toMatch(/^sbx_fake_/);
    expect(ref.status).toBe("running");
    expect(ref.labels.scan_id).toBe("scn_123");
  });

  it("is idempotent for the same scan_id+step", async () => {
    const p = new FakeSandboxProvider();
    const a = await p.create({
      template: "universal",
      labels: { scan_id: "scn_dup", step: "create" },
    });
    const b = await p.create({
      template: "universal",
      labels: { scan_id: "scn_dup", step: "create" },
    });
    expect(b.id).toBe(a.id);
    expect(p.size).toBe(1);
  });

  it("executes echo deterministically", async () => {
    const p = new FakeSandboxProvider();
    const ref = await p.create({
      template: "universal",
      labels: { scan_id: "scn_echo" },
    });
    const res = await p.exec(ref, ["echo", "hello", "world"], {
      timeoutMs: 10_000,
    });
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain("hello world");
    expect(res.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("executes tls-probe / headers / ports probes deterministically", async () => {
    const p = new FakeSandboxProvider();
    const ref = await p.create({
      template: "universal",
      labels: { scan_id: "scn_probes" },
    });
    for (const cmd of [["tls-probe"], ["headers"], ["ports"]]) {
      const res = await p.exec(ref, cmd, { timeoutMs: 10_000 });
      expect(res.exitCode).toBe(0);
      expect(() => JSON.parse(res.stdout)).not.toThrow();
    }
  });

  it("streams stdout chunks via executeCommand onOutputChunk", async () => {
    const p = new FakeSandboxProvider({ streamDelayMs: 1 });
    const ref = await p.create({
      template: "universal",
      labels: { scan_id: "scn_stream" },
    });
    const chunks: Array<{ stream: string; data: string }> = [];
    const res = await p.executeCommand(ref.id, ["echo", "stream-me"], (c) =>
      chunks.push(c),
    );
    expect(res.stdout).toContain("stream-me");
    expect(chunks.length).toBeGreaterThan(0);
    expect(chunks.every((c) => c.stream === "stdout")).toBe(true);
    expect(chunks.map((c) => c.data).join("")).toContain("stream-me");
  });

  it("enforces the 5-machine quota with quota_exceeded", async () => {
    const p = new FakeSandboxProvider();
    for (let i = 0; i < 5; i++) {
      await p.create({
        template: "universal",
        labels: { scan_id: `scn_q_${i}` },
      });
    }
    await expect(
      p.create({ template: "universal", labels: { scan_id: "scn_q_6" } }),
    ).rejects.toMatchObject({ code: "quota_exceeded", statusCode: 429 });
    await expect(
      p.create({ template: "universal", labels: { scan_id: "scn_q_6" } }),
    ).rejects.toBeInstanceOf(SandboxQuotaError);
  });

  it("enforces the 4-concurrent-exec quota", async () => {
    const p = new FakeSandboxProvider({ streamDelayMs: 30 });
    const ref = await p.create({
      template: "universal",
      labels: { scan_id: "scn_conc" },
    });
    const runs = Array.from({ length: 5 }, () =>
      p.exec(ref, ["echo", "x"], { timeoutMs: 10_000 }),
    );
    const results = await Promise.allSettled(runs);
    const rejected = results.filter((r) => r.status === "rejected");
    expect(rejected.length).toBeGreaterThanOrEqual(1);
    const reason = (rejected[0] as PromiseRejectedResult).reason;
    expect(String(reason?.code ?? reason?.message)).toMatch(
      /quota_exceeded/,
    );
  });

  it("kill removes the sandbox and frees the quota slot (S-19)", async () => {
    const p = new FakeSandboxProvider();
    const ref = await p.create({
      template: "universal",
      labels: { scan_id: "scn_kill" },
    });
    await p.kill(ref);
    expect(await p.get(ref)).toBe("deleted");
    expect(await p.list()).toHaveLength(0);
    // Slot freed: creating again works.
    const ref2 = await p.create({
      template: "universal",
      labels: { scan_id: "scn_kill_2" },
    });
    expect(ref2.id).not.toBe(ref.id);
  });

  it("suspend/stop/list filtering work", async () => {
    const p = new FakeSandboxProvider();
    const a = await p.create({
      template: "universal",
      labels: { scan_id: "scn_a", workspace_id: "ws_1" },
    });
    await p.create({
      template: "universal",
      labels: { scan_id: "scn_b", workspace_id: "ws_2" },
    });
    await p.suspend(a);
    expect(await p.get(a)).toBe("suspended");
    await p.stop(a);
    expect(await p.get(a)).toBe("stopped");
    expect(await p.list({ workspace_id: "ws_2" })).toHaveLength(1);
    expect(await p.list({ workspace_id: "ws_1" })).toHaveLength(1);
    expect(await p.list()).toHaveLength(2);
  });
});
