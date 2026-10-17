import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiStore } from "../../../_lib/store";
import { ensureWorkspace } from "../../../_lib/workspace";
import { GET, POST, DELETE } from "./route";
import { POST as scan } from "../../../scans/route";
const dns = vi.hoisted(() => ({ resolveTxt: vi.fn(), cancel: vi.fn() }));
vi.mock("node:dns/promises", () => ({ Resolver: vi.fn(function () { return dns; }) }));
vi.mock("../../../_lib/baseline-runtime", () => ({ kickQueue: vi.fn() }));
const context = (id: string) => ({ params: Promise.resolve({ id }) });
function request(cookie: string, method = "GET", body?: unknown, origin?: string) {
  return new Request("https://shipsafe.app/api", { method, headers: { cookie, "content-type": "application/json", ...(origin ? { origin } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
}
function fixture() {
  const identity = ensureWorkspace(new Request("https://shipsafe.app/api"));
  const cookie = identity.cookie!.split(";")[0];
  const project = apiStore.createProject(identity.id, { name: "Test", url: "https://my-app.com", environment: "staging" });
  return { cookie, project };
}
beforeEach(() => { apiStore.reset(); dns.resolveTxt.mockReset().mockResolvedValue([]); });

describe("Deep consent route", () => {
  it("keeps instructions and mutations owner scoped and rejects cross-origin consent", async () => {
    const { cookie, project } = fixture();
    const stranger = fixture().cookie;
    expect((await GET(request(stranger), context(project.id))).status).toBe(404);
    expect((await POST(request(stranger, "POST", { consent: true, classes: ["cors"] }), context(project.id))).status).toBe(404);
    expect((await DELETE(request(stranger, "DELETE"), context(project.id))).status).toBe(404);
    expect((await POST(request(cookie, "POST", { consent: true, classes: ["cors"] }, "https://attacker.com"), context(project.id))).status).toBe(403);
    expect(dns.resolveTxt).not.toHaveBeenCalled();
    expect(await (await GET(request(cookie), context(project.id))).json()).toMatchObject({ hostname: "my-app.com", authorization: null, dnsRecord: { type: "TXT", name: "_shipsafe.my-app.com" } });
  });

  it("rejects checkbox-only and unsupported consent, and requires fresh exact-host DNS", async () => {
    const { cookie, project } = fixture();
    for (const body of [{ consent: true }, { consent: true, classes: [] }, { consent: true, classes: ["injection"] }, { consent: true, classes: ["cors", "cors"] }, { consent: true, classes: ["cors"], hostname: "other.com" }]) {
      expect((await POST(request(cookie, "POST", body), context(project.id))).status).toBe(400);
    }
    expect((await POST(request(cookie, "POST", { consent: true, classes: ["cors"] }), context(project.id))).status).toBe(422);
    dns.resolveTxt.mockResolvedValue([[`shipsafe-verification=${project.verificationToken}`]]);
    const response = await POST(request(cookie, "POST", { consent: true, classes: ["cors"] }), context(project.id));
    expect(response.status).toBe(201);
    expect(dns.resolveTxt).toHaveBeenLastCalledWith("_shipsafe.my-app.com");
    expect(await response.json()).toMatchObject({ authorization: { hostname: "my-app.com", classes: ["cors"] } });
  });

  it("does not resurrect consent if revocation completes during DNS verification, including before the first grant", async () => {
    const { cookie, project } = fixture();
    let finishDns!: (records: string[][]) => void;
    let lookupStarted!: () => void;
    const started = new Promise<void>(resolve => { lookupStarted = resolve; });
    dns.resolveTxt.mockImplementation(() => { lookupStarted(); return new Promise<string[][]>(resolve => { finishDns = resolve; }); });
    const pending = POST(request(cookie, "POST", { consent: true, classes: ["cors"] }), context(project.id));
    await started;
    expect((await DELETE(request(cookie, "DELETE"), context(project.id))).status).toBe(200);
    finishDns([[`shipsafe-verification=${project.verificationToken}`]]);
    expect((await pending).status).toBe(409);
    const current = await (await GET(request(cookie), context(project.id))).json();
    expect(current.authorization).toBeNull();
    // A later deliberate consent can create a new grant.
    dns.resolveTxt.mockResolvedValue([[`shipsafe-verification=${project.verificationToken}`]]);
    expect((await POST(request(cookie, "POST", { consent: true, classes: ["cors"] }), context(project.id))).status).toBe(201);
  });

  it("rejects Deep checkbox submissions and rechecks DNS on enqueue, while standard needs no proof", async () => {
    const { cookie, project } = fixture();
    expect((await scan(request(cookie, "POST", { projectId: project.id, scopeAccepted: true, mode: "deep" }))).status).toBe(400);
    expect((await scan(request(cookie, "POST", { projectId: project.id, scopeAccepted: true, mode: "deep", authorizationId: "invented" }))).status).toBe(403);
    dns.resolveTxt.mockResolvedValue([[`shipsafe-verification=${project.verificationToken}`]]);
    const grant = (await (await POST(request(cookie, "POST", { consent: true, classes: ["cors"] }), context(project.id))).json()).authorization;
    dns.resolveTxt.mockResolvedValue([]);
    expect((await scan(request(cookie, "POST", { projectId: project.id, scopeAccepted: true, mode: "deep", authorizationId: grant.id }))).status).toBe(422);
    expect(dns.resolveTxt).toHaveBeenCalledTimes(2);
    expect((await scan(request(cookie, "POST", { projectId: project.id, scopeAccepted: true }))).status).toBe(503);
    expect(dns.resolveTxt).toHaveBeenCalledTimes(2);
    expect((await DELETE(request(cookie, "DELETE"), context(project.id))).status).toBe(200);
    expect((await scan(request(cookie, "POST", { projectId: project.id, scopeAccepted: true, mode: "deep", authorizationId: grant.id }))).status).toBe(403);
  });
});
