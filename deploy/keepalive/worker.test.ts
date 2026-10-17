import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { type Env } from "./worker";

const env: Env = { INSTABOX_API_KEY: "test-secret", INSTABOX_SANDBOX_ID: "sbx_test" };
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("keepalive worker", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns health without making an external request", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const response = await worker.fetch(new Request("https://worker.example/health"));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("ok");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("executes a harmless command for a running machine", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({ state: "running" }))
      .mockResolvedValueOnce(json({ exitCode: 0, timedOut: false }));
    await worker.scheduled({} as ScheduledEvent, env);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.instabox.sh/v1/machines/sbx_test");
    const request = fetchMock.mock.calls[1][1];
    expect(request?.body).toBe(JSON.stringify({ cmd: "true", timeoutSeconds: 5 }));
    expect((request?.headers as Record<string, string>).Authorization).toBe("Bearer test-secret");
  });

  it("resumes a suspended machine and waits for the operation", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({ state: "suspended" }))
      .mockResolvedValueOnce(json({ id: "op_1", state: "running" }, 202))
      .mockResolvedValueOnce(json({ id: "op_1", state: "succeeded" }))
      .mockResolvedValueOnce(json({ state: "running" }))
      .mockResolvedValueOnce(json({ exitCode: 0, timedOut: false }));
    await worker.scheduled({} as ScheduledEvent, env);
    expect(fetchMock.mock.calls[1][0]).toBe("https://api.instabox.sh/v1/machines/sbx_test/resume");
    expect(fetchMock.mock.calls[2][0]).toBe("https://api.instabox.sh/v1/operations/op_1?wait=25s");
  });

  it("fails visibly for an unexpected state and does not execute", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({ state: "error" }));
    await expect(worker.scheduled({} as ScheduledEvent, env)).rejects.toThrow("unexpected_machine_state");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not log credentials or command output on failure", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({ state: "running" }))
      .mockResolvedValueOnce(json({ exitCode: 1, timedOut: false, stderr: "private output" }));
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(worker.scheduled({} as ScheduledEvent, env)).rejects.toThrow("keepalive_command_failed");
    expect(error).toHaveBeenCalledWith("[keepalive] failed: keepalive_command_failed");
    expect(JSON.stringify(error.mock.calls)).not.toContain(env.INSTABOX_API_KEY);
    expect(JSON.stringify(error.mock.calls)).not.toContain("private output");
  });
});
