import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { ApiScanStore } from "./store";

const stores: ApiScanStore[] = [];
const directories: string[] = [];
function directory() { const path = mkdtempSync(join(tmpdir(), "shipsafe-store-")); directories.push(path); return path; }
function store(path?: string) { const instance = new ApiScanStore(path); stores.push(instance); return instance; }
function project(instance: ApiScanStore) { return instance.createProject("owner", { name: "Fixture", url: "https://example.test", environment: "development" }); }

afterEach(() => {
  for (const instance of stores.splice(0)) instance.close();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("single-process local scan persistence", () => {
  it("does not create storage or acquire a lock until first access", () => {
    const path = join(directory(), "not-created");
    const instance = store(path);
    expect(instance.isPersistent()).toBe(true);
    expect(existsSync(path)).toBe(false);
    instance.countActive();
    expect(existsSync(join(path, "store.lock"))).toBe(true);
  });

  it("restores ownership, verification, reports, findings and events", () => {
    const path = directory();
    const first = store(path);
    const target = project(first);
    first.setVerification(target.id, true);
    const scan = first.createScan({ projectId: target.id, url: target.url, mode: "lab" });
    const report = { profile: "fixture", checked: ["HEADER-01"] };
    first.updateScan(scan.id, { status: "COMPLETED", reportManifest: report });
    report.checked.push("MUTATION");
    first.addFinding({ scanId: scan.id, severity: "low", title: "Header", description: "Absent", evidence: "response", remediation: "Set header", classification: "hardening", checkId: "HEADER-01" });
    first.addEvent({ scanId: scan.id, stage: "COMPLETED", message: "Recorded result" });
    first.close();
    const second = store(path);
    expect(second.hasOwner("owner")).toBe(true);
    expect(second.hasOwner("other")).toBe(false);
    expect(second.getProject("owner", target.id)?.verifiedAt).toBeTruthy();
    expect(second.getProject("other", target.id)).toBeUndefined();
    expect(second.ownedScan("other", scan.id)).toBeUndefined();
    expect(second.getScan(scan.id)).toMatchObject({ status: "COMPLETED", mode: "lab", reportManifest: { checked: ["HEADER-01"] } });
    expect(second.listFindings(scan.id)[0]).toMatchObject({ classification: "hardening", checkId: "HEADER-01" });
    expect(second.listEvents(scan.id)).toHaveLength(1);
    expect(second.getScan(scan.id)?.score).toBeUndefined();
    expect(readFileSync(join(path, "store.json"), "utf8")).not.toContain("AbortController");
  });

  it("keeps queued jobs FIFO and fails interrupted executions without retrying", () => {
    const path = directory();
    const first = store(path);
    const target = project(first);
    const scans = Array.from({ length: 5 }, () => first.createScan({ projectId: target.id, url: target.url }));
    first.claimExecution(scans[0].id);
    first.updateScan(scans[1].id, { status: "RUNNING" });
    first.updateScan(scans[2].id, { status: "PROCESSING" });
    first.close();
    const second = store(path);
    expect(second.listQueuedScans().map(s => s.id)).toEqual(scans.slice(3).map(s => s.id));
    for (const scan of scans.slice(0, 3)) {
      expect(second.getScan(scan.id)?.status).toBe("FAILED");
      expect(second.listEvents(scan.id)[0].message).toContain("no automatic rescan");
      expect(second.claimExecution(scan.id)).toBeUndefined();
    }
    second.close();
    const third = store(path);
    expect(third.listEvents(scans[0].id)).toHaveLength(1);
  });

  it("rejects another active writer and permits access after explicit close", () => {
    const path = directory();
    const first = store(path);
    project(first);
    const second = store(path);
    expect(() => second.countActive()).toThrow(/active writer/);
    first.close();
    expect(store(path).hasOwner("owner")).toBe(true);
  });

  it("reclaims a lock only after its process has exited", () => {
    const path = directory();
    const child = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
    expect(child.status).toBe(0);
    writeFileSync(join(path, "store.lock"), JSON.stringify({ pid: child.pid, token: "old-process" }));
    expect(store(path).countActive()).toBe(0);
    expect(JSON.parse(readFileSync(join(path, "store.lock"), "utf8")).pid).toBe(process.pid);
  });

  it.each(["{broken", JSON.stringify({ version: 2 }), JSON.stringify({ version: 1, projects: [], owners: [], scans: [{ id: "bad" }], findings: [], events: [] })])("fails closed on corrupt or unsupported snapshots", (raw) => {
    const path = directory();
    writeFileSync(join(path, "store.json"), raw);
    const instance = store(path);
    expect(() => instance.countActive()).toThrow();
    expect(() => project(instance)).toThrow(/closed or failed/);
    expect(readFileSync(join(path, "store.json"), "utf8")).toBe(raw);
    expect(existsSync(join(path, "store.lock"))).toBe(false);
  });

  it("does not replace malformed locks or steal ownership based on age", () => {
    const path = directory();
    writeFileSync(join(path, "store.lock"), "broken");
    expect(() => store(path).countActive()).toThrow();
    expect(readFileSync(join(path, "store.lock"), "utf8")).toBe("broken");
  });

  it("preserves cleanup quarantine across a service restart", () => {
    const path = directory();
    const first = store(path);
    const target = project(first);
    const job = first.createScan({ projectId: target.id, url: target.url });
    first.updateScan(job.id, { status: "FAILED", reportManifest: { cleanupState: "unverified" } });
    first.close();
    const second = store(path);
    expect(second.hasCleanupFailure()).toBe(true);
    expect(second.getScan(job.id)?.reportManifest).toEqual({ cleanupState: "unverified" });
  });
});
