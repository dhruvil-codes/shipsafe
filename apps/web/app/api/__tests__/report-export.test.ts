import { beforeEach, describe, expect, it } from "vitest";
import { apiStore } from "../_lib/store";
import { GET as workspace } from "../workspace/route";
import { workspaceId } from "../_lib/workspace";
import { GET as download } from "../scans/[id]/report/route";

const ctx = (id: string) => ({ params: Promise.resolve({ id }) });
const request = (cookie = "", format = "html") => new Request(`https://shipsafe.app/api/report?format=${format}`, { headers: { cookie } });
beforeEach(() => apiStore.reset());
async function fixture(status: "COMPLETED" | "QUEUED" | "FAILED" = "COMPLETED") {
  const init = await workspace(request());
  const cookie = init.headers.get("set-cookie")!.split(";")[0]!;
  const owner = workspaceId(request(cookie))!;
  const project = apiStore.createProject(owner, { name: "Owned fixture", url: "https://fixture.invalid/", environment: "development" });
  const scan = apiStore.createScan({ projectId: project.id, url: project.url, mode: "lab" });
  apiStore.updateScan(scan.id, { status, reportManifest: { engine: "fixture", version: "1", synthetic: true, profile: "baseline", cleanupState: "verified", checks: [{ id: "csp", title: "CSP", status: "observation", evidence: "CSP absent", remediation: "Set a policy" }] } });
  apiStore.addFinding({ scanId: scan.id, title: "Missing CSP", severity: "info", classification: "hardening", description: "Hardening observation", evidence: "</pre><script>untrusted</script>", remediation: "Set a tested CSP" });
  return { cookie, scan };
}

describe("private report downloads", () => {
  it("does not expose reports to other browsers or unauthenticated requests", async () => {
    const { scan } = await fixture();
    expect((await download(request(), ctx(scan.id))).status).toBe(404);
    const stranger = await workspace(request());
    expect((await download(request(stranger.headers.get("set-cookie")!.split(";")[0]), ctx(scan.id))).status).toBe(404);
  });
  it("exports an inert private HTML attachment with prompts and real evidence", async () => {
    const { cookie, scan } = await fixture();
    const response = await download(request(cookie), ctx(scan.id));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toContain(`shipsafe-${scan.id}.html`);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    const html = await response.text();
    expect(html).toContain("Ready-to-copy fix prompt");
    expect(html).toContain("Set a tested CSP");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("Synthetic demonstration");
  });
  it("exports structured check outcomes and one fix prompt per finding", async () => {
    const { cookie, scan } = await fixture();
    const response = await download(request(cookie, "json"), ctx(scan.id));
    const data = await response.json();
    expect(data.scan.id).toBe(scan.id);
    expect(data.checks).toHaveLength(1);
    expect(data.findings[0].fixPrompt).toContain("UNTRUSTED_FINDING_DATA_JSON");
    expect(data.findings[0].fixPrompt).toContain("Set a tested CSP");
    expect(data.scan.score).toBeUndefined();
    expect(data.summary.baselineScore).toBeNull();
  });
  it("rejects running scans and unsupported formats; labels failed exports partial", async () => {
    const { cookie, scan } = await fixture("QUEUED");
    expect((await download(request(cookie), ctx(scan.id))).status).toBe(409);
    apiStore.updateScan(scan.id, { status: "FAILED" });
    expect((await download(request(cookie, "pdf"), ctx(scan.id))).status).toBe(400);
    const report = await (await download(request(cookie, "json"), ctx(scan.id))).json();
    expect(report.summary.partial).toBe(true);
  });
});
