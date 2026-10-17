import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiStore, type Project } from "../_lib/store";
import { workspaceId } from "../_lib/workspace";
import { DNS_TIMEOUT_MS } from "../_lib/verification";
import { GET as workspace } from "../workspace/route";
import { GET as listProjects, POST as createProject } from "../projects/route";
import { GET as projectDetail } from "../projects/[id]/route";
import { POST as verify } from "../projects/[id]/verify/route";
import { GET as listScans, POST as createScan } from "../scans/route";
import { GET as getScan } from "../scans/[id]/route";
import { POST as cancelScan } from "../scans/[id]/cancel/route";
import { GET as streamScan } from "../scans/[id]/stream/route";

const dns = vi.hoisted(() => ({ resolveTxt: vi.fn(), cancel: vi.fn() }));
vi.mock("node:dns/promises", () => ({ Resolver: vi.fn(function () { return dns; }) }));
vi.mock("@shipsafe/sandbox/live-runner", () => ({ getLiveSandbox: vi.fn(), runLiveScan: vi.fn() }));
import { getLiveSandbox, runLiveScan } from "@shipsafe/sandbox/live-runner";

function request(cookie = "", body?: unknown, extraHeaders: Record<string, string> = {}): Request {
  return new Request("https://shipsafe.app/api", {
    method: body === undefined ? "GET" : "POST",
    headers: { cookie, "Content-Type": "application/json", ...extraHeaders },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
const context = (id: string) => ({ params: Promise.resolve({ id }) });

async function browser(): Promise<string> {
  const response = await workspace(request());
  return response.headers.get("set-cookie")!.split(";")[0]!;
}

async function projectFor(cookie: string): Promise<Project> {
  const response = await createProject(request(cookie, { name: "My app", url: "https://my-app.com", environment: "staging" }));
  expect(response.status).toBe(201);
  return (await response.json() as { project: Project }).project;
}

beforeEach(() => {
  apiStore.reset();
  vi.clearAllMocks();
  dns.resolveTxt.mockReset().mockResolvedValue([]);
});
afterEach(() => vi.useRealTimers());

describe("browser workspace and projects", () => {
  it("creates an HttpOnly capability and reports actual execution limitations", async () => {
    const response = await workspace(request());
    expect(response.headers.get("set-cookie")).toMatch(/shipsafe_workspace=[a-f0-9]{64}; Path=\/; HttpOnly; SameSite=Strict; Secure/);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toMatchObject({ mode: "browser", persistence: "memory", executionConfigured: false, githubConfigured: false });
    const cookie = response.headers.get("set-cookie")!.split(";")[0]!;
    expect((await workspace(request(cookie))).headers.has("set-cookie")).toBe(false);
  });

  it("bootstraps a workspace when listing projects directly", async () => {
    const response = await listProjects(request());
    expect(response.headers.has("set-cookie")).toBe(true);
    expect(await response.json()).toEqual({ projects: [] });
  });

  it("persists projects only for the capability that created them", async () => {
    const owner = await browser();
    const stranger = await browser();
    const project = await projectFor(owner);
    expect(project).toMatchObject({ name: "My app", environment: "staging", verifiedAt: null, verificationExpiresAt: null });
    expect(project.verificationToken).toMatch(/^[a-f0-9]{64}$/);
    expect(await (await listProjects(request(owner))).json()).toEqual({ projects: [project] });
    expect(await (await listProjects(request(stranger))).json()).toEqual({ projects: [] });
    expect((await projectDetail(request(stranger), context(project.id))).status).toBe(404);
    expect((await verify(request(stranger, {}), context(project.id))).status).toBe(404);
    expect(dns.resolveTxt).not.toHaveBeenCalled();
    expect((await projectDetail(request(owner), context(project.id))).status).toBe(200);
  });

  it("does not trust a client-selected capability value", async () => {
    const response = await workspace(request(`shipsafe_workspace=${"f".repeat(64)}`));
    expect(response.headers.get("set-cookie")).not.toContain(`=${"f".repeat(64)};`);
  });

  it.each([
    "http://localhost", "http://127.0.0.1", "http://0x7f000001", "http://10.0.0.1",
    "http://[::1]", "http://[::ffff:127.0.0.1]", "http://169.254.169.254", "https://metadata.google.internal",
    "https://app.local", "https://admin:password@app.com", "https://app.com:8000", "ftp://app.com", "https://app.com/#fragment",
  ])("rejects unsupported project target %s", async (url) => {
    const response = await createProject(request(await browser(), { name: "App", url, environment: "production" }));
    expect(response.status).toBe(400);
    expect(dns.resolveTxt).not.toHaveBeenCalled();
  });

  it("blocks cross-origin browser mutations", async () => {
    const response = await createProject(request(await browser(), { name: "App", url: "https://app.com", environment: "production" }, { origin: "https://attacker.com" }));
    expect(response.status).toBe(403);
  });
});

describe("exact-domain DNS ownership", () => {
  it("accepts split TXT chunks and sets a bounded expiry", async () => {
    const owner = await browser();
    const project = await projectFor(owner);
    dns.resolveTxt.mockResolvedValue([["shipsafe-verification=", project.verificationToken]]);
    const response = await verify(request(owner, {}), context(project.id));
    expect(response.status).toBe(200);
    expect(dns.resolveTxt).toHaveBeenCalledWith("_shipsafe.my-app.com");
    const verified = (await response.json() as { project: Project }).project;
    expect(verified.verifiedAt).not.toBeNull();
    expect(Date.parse(verified.verificationExpiresAt!) - Date.parse(verified.verifiedAt!)).toBeCloseTo(86_400_000, -2);
  });

  it("rejects an incorrect proof and revokes a previously verified record", async () => {
    const owner = await browser();
    const project = await projectFor(owner);
    apiStore.setVerification(project.id, true);
    dns.resolveTxt.mockResolvedValue([["shipsafe-verification=wrong-token"]]);
    const response = await verify(request(owner, {}), context(project.id));
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ code: "VERIFICATION_FAILED", error: expect.stringContaining("Add TXT") });
    expect(apiStore.getProject(workspaceId(request(owner)), project.id)?.verifiedAt).toBeNull();
  });

  it("fails closed on a DNS error", async () => {
    const owner = await browser();
    const project = await projectFor(owner);
    dns.resolveTxt.mockRejectedValue(Object.assign(new Error("missing"), { code: "ENODATA" }));
    const response = await verify(request(owner, {}), context(project.id));
    expect(response.status).toBe(422);
    expect((await response.json() as { error: string }).error).toContain("No verification TXT record");
  });

  it("bounds a DNS lookup that never resolves", async () => {
    vi.useFakeTimers();
    const owner = await browser();
    const project = await projectFor(owner);
    dns.resolveTxt.mockImplementation(() => new Promise(() => {}));
    const pending = verify(request(owner, {}), context(project.id));
    await vi.advanceTimersByTimeAsync(DNS_TIMEOUT_MS + 1);
    expect((await pending).status).toBe(422);
    expect(dns.cancel).toHaveBeenCalledOnce();
  });
});

describe("scan attestation and execution readiness", () => {
  it("rejects malformed JSON without creating a project or scan", async () => {
    const invalid = () => new Request("https://shipsafe.app/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" });
    expect((await createProject(invalid())).status).toBe(400);
    expect((await createScan(invalid())).status).toBe(400);
    expect(apiStore.countActive()).toBe(0);
  });

  it("rejects direct URLs, missing attestation, and another browser's project", async () => {
    const owner = await browser();
    const project = await projectFor(owner);
    expect((await createScan(request(owner, { url: "https://app.com" }))).status).toBe(403);
    expect((await createScan(request(owner, { projectId: project.id }))).status).toBe(400);
    expect((await createScan(request(owner, { projectId: project.id, scopeAccepted: false }))).status).toBe(400);
    expect((await createScan(request(await browser(), { projectId: project.id, scopeAccepted: true }))).status).toBe(404);
    expect(dns.resolveTxt).not.toHaveBeenCalled();
  });

  it("accepts the user's attestation without DNS setup, then reports unavailable execution", async () => {
    const owner = await browser();
    const project = await projectFor(owner);
    const response = await createScan(request(owner, { projectId: project.id, scopeAccepted: true }));
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ code: "EXECUTION_NOT_READY", executionConfigured: false });
    expect(dns.resolveTxt).not.toHaveBeenCalled();
    expect(apiStore.countActive()).toBe(0);
    expect(getLiveSandbox).not.toHaveBeenCalled();
    expect(runLiveScan).not.toHaveBeenCalled();
  });
});

describe("owned histories, cancellation, and duplicate streams", () => {
  async function fixture() {
    const owner = await browser();
    const project = await projectFor(owner);
    const scan = apiStore.createScan({ projectId: project.id, projectName: project.name, url: project.url, scopeAccepted: true });
    apiStore.addEvent({ scanId: scan.id, stage: "QUEUED", message: "Recorded event" });
    return { owner, project, scan };
  }

  it("scopes list, detail, stream, and cancel to the browser capability", async () => {
    const { owner, project, scan } = await fixture();
    const stranger = await browser();
    expect(await (await listScans(request(stranger))).json()).toEqual({ scans: [] });
    expect((await getScan(request(stranger), context(scan.id))).status).toBe(404);
    expect((await streamScan(request(stranger), context(scan.id))).status).toBe(404);
    expect((await cancelScan(request(stranger, {}), context(scan.id))).status).toBe(404);
    expect((await getScan(request(owner), context(scan.id))).status).toBe(200);
    expect(await (await projectDetail(request(owner), context(project.id))).json()).toMatchObject({ scans: [{ id: scan.id }] });
    expect(dns.resolveTxt).not.toHaveBeenCalled();
  });

  it("retains partial evidence and aborts the owned execution on cancellation", async () => {
    const { owner, scan } = await fixture();
    const execution = apiStore.claimExecution(scan.id)!;
    apiStore.addFinding({ scanId: scan.id, severity: "LOW", title: "Recorded result", description: "Recorded", evidence: "{}", remediation: "Review" });
    expect((await cancelScan(request(owner, {}), context(scan.id))).status).toBe(200);
    expect(execution.signal.aborted).toBe(true);
    expect(apiStore.getScan(scan.id)?.status).toBe("CANCELLED");
    expect(apiStore.listFindings(scan.id)).toHaveLength(1);
    expect(apiStore.listEvents(scan.id)).toHaveLength(2);
    await cancelScan(request(owner, {}), context(scan.id));
    expect(apiStore.listEvents(scan.id)).toHaveLength(2);
  });

  it("replays completed evidence without executing or modifying the record", async () => {
    const { owner, scan } = await fixture();
    apiStore.updateScan(scan.id, { status: "COMPLETED", score: 80, coverage: 20 });
    for (let i = 0; i < 2; i++) {
      const response = await streamScan(request(owner), context(scan.id));
      expect(response.headers.get("content-type")).toBe("text/event-stream");
      const text = await response.text();
      expect(text).toContain("Recorded event");
      expect(text).toContain("event: done");
    }
    expect(apiStore.getScan(scan.id)?.status).toBe("COMPLETED");
    expect(apiStore.listEvents(scan.id)).toHaveLength(1);
    expect(runLiveScan).not.toHaveBeenCalled();
    expect(dns.resolveTxt).not.toHaveBeenCalled();
  });

  it("cannot start a queued scan or duplicate an already running execution via SSE", async () => {
    const { owner, scan } = await fixture();
    expect((await streamScan(request(owner), context(scan.id))).status).toBe(503);
    const execution = apiStore.claimExecution(scan.id);
    expect(execution).toBeDefined();
    expect(apiStore.claimExecution(scan.id)).toBeUndefined();
    expect((await streamScan(request(owner), context(scan.id))).status).toBe(409);
    expect(runLiveScan).not.toHaveBeenCalled();
  });
});
