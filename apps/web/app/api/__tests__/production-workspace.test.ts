import { afterEach, describe, expect, it, vi } from "vitest";

const runtime = vi.hoisted(() => ({
  ownedScan: vi.fn(), listScans: vi.fn(), isPersistent: vi.fn(), hasCleanupFailure: vi.fn(),
  listEvents: vi.fn(), getScan: vi.fn(), listFindings: vi.fn(),
}));
const dispatcher = vi.hoisted(() => ({ dispatchQueue: vi.fn() }));
vi.mock("../_lib/runtime-store", () => ({ runtimeStore: runtime }));
vi.mock("../_lib/queue-dispatch", () => dispatcher);

import { GET as scanDetail } from "../scans/[id]/route";
import { GET as scanStream } from "../scans/[id]/stream/route";
import { GET as scansList } from "../scans/route";
import { workspaceId } from "../_lib/workspace";

const capability = "a".repeat(64);
const request = (cookie: string) => new Request("https://shipsafe.app/api/scans/scan_1", {
  headers: { cookie: `shipsafe_workspace=${cookie}` },
});

afterEach(() => {
  vi.unstubAllEnvs();
  runtime.ownedScan.mockReset();
  runtime.listScans.mockReset();
  runtime.isPersistent.mockReset();
  runtime.hasCleanupFailure.mockReset();
  runtime.listEvents.mockReset();
  runtime.getScan.mockReset();
  runtime.listFindings.mockReset();
  dispatcher.dispatchQueue.mockReset();
});

describe("production workspace capabilities", () => {
  it("accepts a well-formed DB-backed capability and passes it to the tenant-scoped scan lookup", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://redacted/test");
    runtime.ownedScan.mockResolvedValue(undefined);

    const req = request(capability);
    expect(workspaceId(req)).toBe(capability);
    expect((await scanDetail(req, { params: Promise.resolve({ id: "scan_1" }) })).status).toBe(404);
    expect(runtime.ownedScan).toHaveBeenCalledWith(capability, "scan_1");
  });

  it("rejects malformed capabilities and refuses local memory ownership on Vercel without a database", () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "");
    expect(workspaceId(request("not-a-capability"))).toBeUndefined();
    expect(workspaceId(request(capability))).toBeUndefined();
  });

  it("keeps the scan-list GET read-only and does not dispatch queued work", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://redacted/test");
    runtime.listScans.mockResolvedValue([]);
    expect((await scansList(request(capability))).status).toBe(200);
    expect(runtime.listScans).toHaveBeenCalledWith(capability);
    expect(dispatcher.dispatchQueue).not.toHaveBeenCalled();
  });

  it("subscribes to a queued scan without dispatching unrelated queued work", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("DATABASE_URL", "postgres://redacted/test");
    vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "workflow");
    vi.stubEnv("VERCEL_DEPLOYMENT_ID", "deployment-test");
    vi.stubEnv("INSTABOX_API_KEY", "test-key");
    vi.stubEnv("INSTABOX_SANDBOX_ID", "test-machine");
    const scan = { id: "scan_1", status: "QUEUED", score: undefined, coverage: undefined };
    runtime.ownedScan.mockResolvedValue(scan);
    runtime.isPersistent.mockResolvedValue(true);
    runtime.hasCleanupFailure.mockResolvedValue(false);
    runtime.listEvents.mockResolvedValue([]);
    runtime.getScan.mockResolvedValue(scan);
    runtime.listFindings.mockResolvedValue([]);

    const response = await scanStream(request(capability), { params: Promise.resolve({ id: "scan_1" }) });
    expect(response.status).toBe(200);
    await response.body!.cancel();
    expect(dispatcher.dispatchQueue).not.toHaveBeenCalled();
  });
});
