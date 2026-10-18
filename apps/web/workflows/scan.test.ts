import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  sleep: vi.fn(),
  start: vi.fn(),
  executeDurableScan: vi.fn(),
  heartbeatRecovery: vi.fn(),
  reapExpiredExecutions: vi.fn(),
  expireQueuedScan: vi.fn(),
  dispatchQueuedScans: vi.fn(),
}));
vi.mock("workflow", () => ({ sleep: mocks.sleep }));
vi.mock("workflow/api", () => ({ start: mocks.start }));
vi.mock("../app/api/_lib/baseline-runtime", () => ({ executeDurableScan: mocks.executeDurableScan }));
vi.mock("../app/api/_lib/runtime-store", () => ({ runtimeStore: {
  heartbeatRecovery: mocks.heartbeatRecovery,
  reapExpiredExecutions: mocks.reapExpiredExecutions,
  expireQueuedScan: mocks.expireQueuedScan,
} }));
vi.mock("../app/api/_lib/queue-dispatch", () => ({ dispatchQueuedScans: mocks.dispatchQueuedScans }));

import { continueRecoveryStep, executeScanStep, recoverDispatchStep, scanRecoveryWorkflow, scanWorkflow } from "./scan";

afterEach(() => vi.resetAllMocks());

describe("durable scan workflow", () => {
  it("retries busy claims after durable sleeps and exits after the scan completes", async () => {
    mocks.executeDurableScan.mockResolvedValueOnce("busy").mockResolvedValueOnce("busy").mockResolvedValueOnce("done");
    mocks.sleep.mockResolvedValue(undefined);

    await scanWorkflow("scn_123");

    expect(mocks.executeDurableScan).toHaveBeenCalledTimes(3);
    expect(mocks.executeDurableScan).toHaveBeenCalledWith("scn_123");
    expect(mocks.sleep).toHaveBeenCalledTimes(2);
    expect(mocks.sleep).toHaveBeenCalledWith("5s");
  });

  it("allows two retries for transient infrastructure errors", () => {
    expect((executeScanStep as typeof executeScanStep & { maxRetries: number }).maxRetries).toBe(2);
  });

  it("marks only still-queued work failed after the bounded busy wait", async () => {
    mocks.executeDurableScan.mockResolvedValue("busy");
    mocks.sleep.mockResolvedValue(undefined);

    await scanWorkflow("scn_waiting");

    expect(mocks.executeDurableScan).toHaveBeenCalledTimes(360);
    expect(mocks.expireQueuedScan).toHaveBeenCalledWith("scn_waiting");
  });

  it("renews the recovery lease before reaping and redispatching work", async () => {
    mocks.heartbeatRecovery.mockResolvedValue(true);

    await expect(recoverDispatchStep("lease-token")).resolves.toBe(true);

    expect(mocks.heartbeatRecovery).toHaveBeenCalledWith("lease-token");
    expect(mocks.reapExpiredExecutions).toHaveBeenCalledOnce();
    expect(mocks.dispatchQueuedScans).toHaveBeenCalledOnce();
  });

  it("stops when a newer recovery workflow owns the lease", async () => {
    mocks.heartbeatRecovery.mockResolvedValue(false);

    await expect(recoverDispatchStep("stale-token")).resolves.toBe(false);
    expect(mocks.reapExpiredExecutions).not.toHaveBeenCalled();
    expect(mocks.dispatchQueuedScans).not.toHaveBeenCalled();
    await scanRecoveryWorkflow("stale-token");
    expect(mocks.sleep).not.toHaveBeenCalled();
  });

  it("starts a successor recovery run after its bounded cycle count", async () => {
    mocks.heartbeatRecovery.mockResolvedValue(true);
    mocks.start.mockResolvedValue({ runId: "successor" });

    await continueRecoveryStep("lease-token");

    expect(mocks.heartbeatRecovery).toHaveBeenCalledWith("lease-token");
    expect(mocks.start).toHaveBeenCalledWith(scanRecoveryWorkflow, ["lease-token"]);
  });
});
