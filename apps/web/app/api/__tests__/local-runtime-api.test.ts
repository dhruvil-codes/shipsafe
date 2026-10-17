import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiStore } from "../_lib/store";
import { workspaceId } from "../_lib/workspace";
import { GET as workspace } from "../workspace/route";
import { POST as lab } from "../scans/lab/route";
import { POST as submit } from "../scans/route";
import { GET as detail } from "../scans/[id]/route";
import { GET as stream } from "../scans/[id]/stream/route";
import { POST as cancel } from "../scans/[id]/cancel/route";

const mocks = vi.hoisted(() => ({ kickQueue: vi.fn(), resolveTxt: vi.fn(), cancelDns: vi.fn() }));
vi.mock("../_lib/baseline-runtime", () => ({ kickQueue: mocks.kickQueue }));
vi.mock("node:dns/promises", () => ({ Resolver: vi.fn(function () { return { resolveTxt: mocks.resolveTxt, cancel: mocks.cancelDns }; }) }));

function request(cookie = "", body?: unknown, headers: Record<string, string> = {}, method = "POST") {
  return new Request("https://shipsafe.app/api", { method, headers: { cookie, ...headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
}
const context = (id: string) => ({ params: Promise.resolve({ id }) });
async function browser() {
  const response = await workspace(request("", undefined, {}, "GET"));
  return response.headers.get("set-cookie")!.split(";")[0];
}
function target(cookie: string, verified = false) {
  const owner = workspaceId(request(cookie))!;
  const project = apiStore.createProject(owner, { name: "Owned test app", url: "https://my-app.com/", environment: "development" });
  if (verified) apiStore.setVerification(project.id, true);
  mocks.resolveTxt.mockResolvedValue([[`shipsafe-verification=${project.verificationToken}`]]);
  return project;
}

beforeEach(() => {
  apiStore.reset();
  vi.stubEnv("SHIPSAFE_RUNTIME", "local");
  vi.stubEnv("SHIPSAFE_LAB_ENABLED", "1");
  vi.stubEnv("INSTABOX_API_KEY", "fixture-not-a-real-key");
  vi.stubEnv("INSTABOX_SANDBOX_ID", "fixture-not-a-real-vm");
  vi.stubEnv("VERCEL", "");
  vi.stubEnv("CF_PAGES", "");
  vi.spyOn(apiStore, "isPersistent").mockReturnValue(true);
  mocks.kickQueue.mockReset();
  mocks.resolveTxt.mockReset();
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  apiStore.reset();
});

describe("explicit local lab API", () => {
  it("queues only the fixed owned lab fixture without accepting scope bypass inputs", async () => {
    const cookie = await browser();
    for (const input of [{ url: "http://localhost:1234" }, { mode: "standard" }, { scopeAccepted: true }, {}]) {
      expect((await lab(request(cookie, input))).status).toBe(400);
    }
    expect(apiStore.countActive()).toBe(0);
    const response = await lab(request(cookie));
    expect(response.status).toBe(202);
    const { scanId } = await response.json();
    expect(apiStore.getScan(scanId)).toMatchObject({ mode: "lab", url: "https://shipsafe-fixture.invalid/", status: "QUEUED" });
    expect(apiStore.getScan(scanId)?.scopeAccepted).toBeUndefined();
    expect(mocks.resolveTxt).not.toHaveBeenCalled();
    expect(mocks.kickQueue).toHaveBeenCalledOnce();
  });

  it("enforces the browser submission rate limit", async () => {
    const cookie = await browser();
    for (let i = 0; i < 3; i++) expect((await lab(request(cookie))).status).toBe(202);
    expect((await lab(request(cookie))).status).toBe(429);
    expect(apiStore.countActive()).toBe(3);
  });

  it("enforces the global active queue limit across browsers", async () => {
    const cookie = await browser();
    const project = target(cookie);
    for (let i = 0; i < 5; i++) apiStore.createScan({ projectId: project.id, url: project.url, mode: "lab" });
    expect((await lab(request(await browser()))).status).toBe(429);
  });

  it("does not expose another browser's report or stream", async () => {
    const owner = await browser();
    const response = await lab(request(owner));
    const { scanId } = await response.json();
    const other = await browser();
    expect((await detail(request(other), context(scanId))).status).toBe(404);
    expect((await stream(request(other), context(scanId))).status).toBe(404);
    expect((await cancel(request(other), context(scanId))).status).toBe(404);
    expect((await detail(request("shipsafe_workspace=" + "f".repeat(64)), context(scanId))).status).toBe(404);
  });
});

describe("website scan authorization", () => {
  it("requires an owned project and explicit authorization attestation, with no DNS setup", async () => {
    const cookie = await browser();
    const project = target(cookie);
    expect((await submit(request(cookie, { url: "https://my-app.com/" }))).status).toBe(403);
    expect((await submit(request(cookie, { projectId: project.id }))).status).toBe(400);
    expect((await submit(request(cookie, { projectId: project.id, scopeAccepted: false }))).status).toBe(400);
    expect((await submit(request(await browser(), { projectId: project.id, scopeAccepted: true }))).status).toBe(404);
    const response = await submit(request(cookie, { projectId: project.id, scopeAccepted: true }));
    expect(response.status).toBe(202);
    const { scanId } = await response.json();
    expect(apiStore.getScan(scanId)).toMatchObject({ mode: "standard", status: "QUEUED", scopeAccepted: true, url: project.url });
    expect(mocks.resolveTxt).not.toHaveBeenCalled();
    expect(mocks.kickQueue).toHaveBeenCalledOnce();
  });
});

describe("persisted event transport and cancellation", () => {
  it("replays event IDs after Last-Event-ID and ends with the saved result", async () => {
    const cookie = await browser();
    const project = target(cookie);
    const job = apiStore.createScan({ projectId: project.id, url: project.url, mode: "lab" });
    const first = apiStore.addEvent({ scanId: job.id, stage: "QUEUED", message: "First recorded event" });
    const second = apiStore.addEvent({ scanId: job.id, stage: "COMPLETED", message: "Second recorded event" });
    apiStore.updateScan(job.id, { status: "COMPLETED" });
    const response = await stream(request(cookie, undefined, { "Last-Event-ID": first.id }, "GET"), context(job.id));
    const body = await response.text();
    expect(response.headers.get("content-type")).toBe("text/event-stream");
    expect(body).not.toContain(first.id);
    expect(body).toContain(`id: ${second.id}`);
    expect(body).toContain('"type":"result"');
    expect(body).toContain("event: done");
  });

  it("streams existing active events while disconnecting leaves the job running", async () => {
    const cookie = await browser();
    const project = target(cookie);
    const job = apiStore.createScan({ projectId: project.id, url: project.url, mode: "lab" });
    const execution = apiStore.claimExecution(job.id)!;
    const event = apiStore.addEvent({ scanId: job.id, stage: "RUNNING", message: "Actual saved progress" });
    const response = await stream(request(cookie, undefined, {}, "GET"), context(job.id));
    const reader = response.body!.getReader();
    const decode = new TextDecoder();
    expect(decode.decode((await reader.read()).value)).toContain(": connected");
    expect(decode.decode((await reader.read()).value)).toContain(`id: ${event.id}`);
    await reader.cancel();
    expect(execution.signal.aborted).toBe(false);
    expect(apiStore.getScan(job.id)?.status).toBe("PROVISIONING");
  });

  it("preserves check identity, status, timestamp, and complete message through persistence and SSE", async () => {
    const cookie = await browser();
    const project = target(cookie);
    const job = apiStore.createScan({ projectId: project.id, url: project.url, mode: "lab" });
    const timestamp = "2026-10-17T12:34:56.789+00:00";
    const message = "[OBSERVATION] Content Security Policy — " + "detail ".repeat(240);
    const event = apiStore.addEvent({ scanId: job.id, stage: "check_done", checkId: "csp", status: "observation", timestamp, message });
    apiStore.addEvent({ scanId: job.id, stage: "earlier timestamp", timestamp: "2020-01-01T00:00:00.000Z", message: "Appended after check" });
    const saved = apiStore.listEvents(job.id)[0]!;
    expect(saved).toMatchObject({ checkId: "csp", status: "observation", timestamp, message });
    const response = await stream(request(cookie, undefined, {}, "GET"), context(job.id));
    const reader = response.body!.getReader();
    const decode = new TextDecoder();
    await reader.read();
    const body = decode.decode((await reader.read()).value);
    expect(body).toContain(`id: ${event.id}`);
    expect(body).toContain(JSON.stringify({ type: "event", ...event }));
    expect(body).toContain(message);
    expect(apiStore.listEvents(job.id).map(item => item.stage)).toEqual(["check_done", "earlier timestamp"]);
    await reader.cancel();
  });

  it("explicit cancellation aborts backend execution and retains evidence", async () => {
    const cookie = await browser();
    const project = target(cookie);
    const job = apiStore.createScan({ projectId: project.id, url: project.url });
    const execution = apiStore.claimExecution(job.id)!;
    apiStore.addEvent({ scanId: job.id, stage: "RUNNING", message: "Prior evidence" });
    const response = await cancel(request(cookie), context(job.id));
    expect(response.status).toBe(200);
    expect(execution.signal.aborted).toBe(true);
    expect(apiStore.getScan(job.id)?.status).toBe("CANCELLED");
    expect(apiStore.listEvents(job.id).map(event => event.message)).toContain("Prior evidence");
    expect(apiStore.listEvents(job.id).some(event => event.stage === "CANCELLED")).toBe(true);
  });
});
