import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApiScanStore, type Project } from "./store";
import { assertDeepAuthorization, DEEP_AUTHORIZATION_TTL_MS } from "./security-policy";

function fixture() {
  const store = new ApiScanStore();
  const project = store.createProject("owner", { name: "Fixture", url: "https://my-app.com", environment: "staging" });
  store.setVerification(project.id, true);
  const grant = store.authorizeDeep("owner", project.id, ["configuration", "cors"])!;
  return { store, project: store.getProject("owner", project.id)!, grant };
}

describe("verified Deep policy", () => {
  it("bounds consent and rejects missing proof, expired, future, wrong-host and mismatched grants", () => {
    const { project, grant } = fixture();
    const scan = { url: project.url, authorizationId: grant.id };
    expect(assertDeepAuthorization(project, scan)).toEqual(grant);
    expect(Date.parse(grant.expiresAt) - Date.parse(grant.createdAt)).toBe(DEEP_AUTHORIZATION_TTL_MS);
    const invalid: Project[] = [
      { ...project, verifiedAt: null }, { ...project, verificationExpiresAt: null },
      { ...project, verifiedAt: new Date(Date.now() + 60_000).toISOString() },
      { ...project, securityAuthorization: { ...grant, hostname: "www.my-app.com" } },
      { ...project, securityAuthorization: { ...grant, revokedAt: new Date().toISOString() } },
      { ...project, securityAuthorization: { ...grant, classes: [] } },
      { ...project, securityAuthorization: { ...grant, classes: ["cors", "cors"] } },
    ];
    for (const target of invalid) expect(() => assertDeepAuthorization(target, scan)).toThrow();
    expect(() => assertDeepAuthorization(project, scan, Date.parse(grant.expiresAt))).toThrow();
    expect(() => assertDeepAuthorization(project, { ...scan, authorizationId: "wrong" })).toThrow();
    expect(() => assertDeepAuthorization(project, { ...scan, url: "https://www.my-app.com" })).toThrow();
  });

  it("does not allow callers to mutate stored grant classes through returned objects", () => {
    const { store, project } = fixture();
    project.securityAuthorization!.classes.length = 0;
    expect(store.getProject("owner", project.id)!.securityAuthorization!.classes).toEqual(["configuration", "cors"]);
    expect(store.authorizeDeep("stranger", project.id, ["cors"])).toBeUndefined();
    expect(store.revokeDeep("stranger", project.id)).toBeUndefined();
  });

  it("persists grant revocation and only cancels Deep jobs, signaling running execution", () => {
    const directory = mkdtempSync(join(tmpdir(), "shipsafe-deep-"));
    let store = new ApiScanStore(directory);
    try {
      const project = store.createProject("owner", { name: "Fixture", url: "https://my-app.com", environment: "staging" });
      store.setVerification(project.id, true);
      const grant = store.authorizeDeep("owner", project.id, ["discovery"])!;
      const deep = store.createScan({ projectId: project.id, url: project.url, mode: "deep", authorizationId: grant.id });
      const queued = store.createScan({ projectId: project.id, url: project.url, mode: "deep", authorizationId: grant.id });
      const standard = store.createScan({ projectId: project.id, url: project.url, mode: "standard" });
      const controller = store.claimExecution(deep.id)!;
      expect(store.revokeDeep("owner", project.id)).toEqual([deep.id, queued.id]);
      expect(controller.signal.aborted).toBe(true);
      expect(store.getScan(standard.id)!.status).toBe("QUEUED");
      store.close();
      store = new ApiScanStore(directory);
      expect(store.getProject("stranger", project.id)).toBeUndefined();
      expect(store.getProject("owner", project.id)!.securityAuthorization!.revokedAt).toBeTruthy();
      expect(store.getProject("owner", project.id)!.securityAuthorizationRevision).toBe(2);
      expect(store.getScan(deep.id)).toMatchObject({ mode: "deep", authorizationId: grant.id, status: "CANCELLED" });
      expect(store.listEvents(deep.id)[0].stage).toBe("CANCELLED");
      expect(store.listQueuedScans().map(scan => scan.id)).toEqual([standard.id]);
    } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
  });
});
