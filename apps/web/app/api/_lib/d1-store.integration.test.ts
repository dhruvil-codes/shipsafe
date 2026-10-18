import { describe, expect, it } from "vitest";
import { getD1Store } from "./d1-store";

describe("Cloudflare D1 live integration", () => {
  it("persists projects and scans in Cloudflare D1 via the edge worker", async () => {
    const store = getD1Store();
    const owner = `test-owner-${Date.now()}`;
    const testUrl = `https://test-${Date.now()}.example.com`;

    // 1. Create project
    const project = await store.createProject(owner, {
      name: "integration-test",
      url: testUrl,
      environment: "production",
    });
    expect(project.id).toMatch(/^prj_/);
    expect(project.url).toBe(testUrl);

    // 2. Fetch project
    const retrieved = await store.getProject(owner, project.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe(project.id);

    // 3. Create scan
    const scan = await store.createScan({
      projectId: project.id,
      projectName: project.name,
      url: project.url,
      mode: "standard",
      scopeAccepted: true,
    });
    expect(scan.id).toMatch(/^scn_/);
    expect(scan.status).toBe("QUEUED");

    // 4. Retrieve scan
    const fetchedScan = await store.getScan(scan.id);
    expect(fetchedScan).toBeDefined();
    expect(fetchedScan?.id).toBe(scan.id);
    expect(fetchedScan?.projectId).toBe(project.id);

    // 5. Complete scan so it releases the active slot in D1
    await store.completeExecution(scan.id, { score: 100, coverage: 100 }, [], "Integration test completed.");
    const completed = await store.getScan(scan.id);
    expect(completed?.status).toBe("COMPLETED");
  });
});
