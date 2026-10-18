import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  start: vi.fn(),
  kickQueue: vi.fn(),
  listQueuedScans: vi.fn(),
  reserveDispatch: vi.fn(),
  recordDispatch: vi.fn(),
  releaseDispatch: vi.fn(),
  hasCleanupFailure: vi.fn(),
  reserveRecovery: vi.fn(),
  releaseRecovery: vi.fn(),
}));

vi.mock("workflow/api", () => ({ start: mocks.start }));
vi.mock("./runtime-store", () => ({ runtimeStore: {
  listQueuedScans: mocks.listQueuedScans,
  reserveDispatch: mocks.reserveDispatch,
  recordDispatch: mocks.recordDispatch,
  releaseDispatch: mocks.releaseDispatch,
  hasCleanupFailure: mocks.hasCleanupFailure,
  reserveRecovery: mocks.reserveRecovery,
  releaseRecovery: mocks.releaseRecovery,
} }));
vi.mock("./baseline-runtime", () => ({ kickQueue: mocks.kickQueue }));
vi.mock("../../../workflows/scan", () => ({ scanRecoveryWorkflow: vi.fn(), scanWorkflow: vi.fn() }));

import { dispatchQueue, QueueDispatchError } from "./queue-dispatch";
import { scanRecoveryWorkflow, scanWorkflow } from "../../../workflows/scan";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetAllMocks();
  mocks.hasCleanupFailure.mockResolvedValue(false);
});

describe("queue dispatch", () => {
  it("starts the local worker without waiting for its completion", async () => {
    vi.stubEnv("VERCEL", "");
    let finish!: () => void;
    const completion = new Promise<void>(resolve => { finish = resolve; });
    mocks.kickQueue.mockReturnValue(completion);

    await dispatchQueue();

    expect(mocks.kickQueue).toHaveBeenCalledOnce();
    expect(mocks.listQueuedScans).not.toHaveBeenCalled();
    finish();
  });

  it("starts a durable workflow for each reserved queued scan and records its run id", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://configured");
    vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "workflow");
    mocks.listQueuedScans.mockResolvedValue([{ id: "scn_first" }, { id: "scn_second" }]);
    mocks.reserveDispatch.mockResolvedValueOnce("token-first").mockResolvedValueOnce("token-second");
    mocks.start.mockResolvedValueOnce({ runId: "run-first" }).mockResolvedValueOnce({ runId: "run-second" });

    await dispatchQueue();

    expect(mocks.start).toHaveBeenNthCalledWith(1, scanWorkflow, ["scn_first"]);
    expect(mocks.start).toHaveBeenNthCalledWith(2, scanWorkflow, ["scn_second"]);
    expect(mocks.recordDispatch).toHaveBeenNthCalledWith(1, "scn_first", "token-first", "run-first");
    expect(mocks.recordDispatch).toHaveBeenNthCalledWith(2, "scn_second", "token-second", "run-second");
    expect(mocks.kickQueue).not.toHaveBeenCalled();
  });

  it("starts only the recovery workflow whose singleton database lease it reserved", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://configured");
    vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "workflow");
    mocks.reserveRecovery.mockResolvedValue("recovery-token");
    mocks.listQueuedScans.mockResolvedValue([]);
    mocks.start.mockResolvedValue({ runId: "recovery-run" });

    await dispatchQueue();

    expect(mocks.start).toHaveBeenCalledWith(scanRecoveryWorkflow, ["recovery-token"]);
    expect(mocks.releaseRecovery).not.toHaveBeenCalled();
  });

  it("does not start a duplicate workflow when another request holds the dispatch reservation", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://configured");
    vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "workflow");
    mocks.listQueuedScans.mockResolvedValue([{ id: "scn_first" }]);
    mocks.reserveDispatch.mockResolvedValue(undefined);

    await dispatchQueue();

    expect(mocks.start).not.toHaveBeenCalled();
    expect(mocks.recordDispatch).not.toHaveBeenCalled();
  });

  it("releases the reservation and reports a safe error when workflow start fails", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://configured");
    vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "workflow");
    mocks.listQueuedScans.mockResolvedValue([{ id: "scn_first" }]);
    mocks.reserveDispatch.mockResolvedValue("token-first");
    mocks.start.mockRejectedValue(new Error("provider detail"));

    let failure: unknown;
    try { await dispatchQueue(); } catch (error) { failure = error; }
    expect(failure).toBeInstanceOf(QueueDispatchError);
    expect(failure).toMatchObject({ code: "DISPATCH_UNAVAILABLE" });
    expect(mocks.releaseDispatch).toHaveBeenCalledWith("scn_first", "token-first");
  });

  it("releases the singleton lease when the recovery workflow cannot start", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://configured");
    vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "workflow");
    mocks.reserveRecovery.mockResolvedValue("recovery-token");
    mocks.start.mockRejectedValue(new Error("provider detail"));

    await expect(dispatchQueue()).rejects.toMatchObject({ code: "DISPATCH_UNAVAILABLE" });
    expect(mocks.releaseRecovery).toHaveBeenCalledWith("recovery-token");
    expect(mocks.listQueuedScans).not.toHaveBeenCalled();
  });

  it("fails closed on Vercel when durable dispatch is not configured", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://configured");
    vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "");

    await expect(dispatchQueue()).rejects.toMatchObject({ code: "DISPATCH_UNAVAILABLE" });
    expect(mocks.kickQueue).not.toHaveBeenCalled();
    expect(mocks.listQueuedScans).not.toHaveBeenCalled();
  });
});
