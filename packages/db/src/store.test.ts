import { describe, expect, it } from "vitest";
import { InMemoryScanStore, createStore } from "./store.js";

describe("InMemoryScanStore", () => {
  it("creates and retrieves a scan with QUEUED status", async () => {
    const store = createStore();
    const scan = await store.createScan({ projectId: "prj_1" });
    expect(scan.id).toMatch(/^scn_/);
    expect(scan.status).toBe("QUEUED");

    const fetched = await store.getScan(scan.id);
    expect(fetched?.id).toBe(scan.id);
    expect(fetched?.projectId).toBe("prj_1");
  });

  it("returns undefined for unknown scan ids", async () => {
    const store = new InMemoryScanStore();
    await expect(store.getScan("scn_missing")).resolves.toBeUndefined();
  });

  it("updates scan status, sandbox, score and coverage", async () => {
    const store = new InMemoryScanStore();
    const scan = await store.createScan({ projectId: "prj_1" });
    const updated = await store.updateScan(scan.id, {
      status: "RUNNING",
      sandboxId: "sbx_1",
    });
    expect(updated.status).toBe("RUNNING");
    expect(updated.sandboxId).toBe("sbx_1");

    const done = await store.updateScan(scan.id, {
      status: "COMPLETED",
      score: 82,
      coverage: 0.9,
    });
    expect(done.score).toBe(82);
    expect(done.coverage).toBe(0.9);
  });

  it("throws when updating a missing scan", async () => {
    const store = new InMemoryScanStore();
    await expect(
      store.updateScan("scn_missing", { status: "FAILED" }),
    ).rejects.toThrow("scan not found");
  });

  it("stores and lists findings per scan", async () => {
    const store = new InMemoryScanStore();
    const a = await store.createScan({ projectId: "prj_1" });
    const b = await store.createScan({ projectId: "prj_1" });

    await store.addFinding({
      scanId: a.id,
      severity: "HIGH",
      title: "Missing HSTS",
      description: "Strict-Transport-Security header absent",
      evidence: JSON.stringify({ header: "missing" }),
      remediation: "Add HSTS header",
    });
    expect(await store.listFindings(a.id)).toHaveLength(1);
    expect(await store.listFindings(b.id)).toHaveLength(0);
  });

  it("stores and lists events in timestamp order", async () => {
    const store = new InMemoryScanStore();
    const scan = await store.createScan({ projectId: "prj_1" });
    await store.addEvent({
      scanId: scan.id,
      stage: "RUNNING",
      message: "second",
      timestamp: new Date("2026-01-02T00:00:00Z"),
    });
    await store.addEvent({
      scanId: scan.id,
      stage: "PROVISIONING",
      message: "first",
      timestamp: new Date("2026-01-01T00:00:00Z"),
    });
    const events = await store.listEvents(scan.id);
    expect(events.map((e) => e.message)).toEqual(["first", "second"]);
  });
});
