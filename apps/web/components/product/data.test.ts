import { afterEach, describe, expect, it, vi } from "vitest";
import { isVerified, request, type Project } from "./data";

const project: Project = {
  id: "prj_test", name: "Test", url: "https://example.com/", environment: "staging",
  verificationToken: "test-token", createdAt: "2026-10-15T00:00:00Z",
  verifiedAt: null, verificationExpiresAt: null,
};

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("current ownership presentation", () => {
  it("never treats missing or expired verification as current", () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-15T12:00:00Z"));
    expect(isVerified(project)).toBe(false);
    expect(isVerified({ ...project, verifiedAt: "2026-10-14T12:00:00Z", verificationExpiresAt: "2026-10-15T12:00:00Z" })).toBe(false);
    expect(isVerified({ ...project, verifiedAt: "2026-10-15T11:00:00Z", verificationExpiresAt: "2026-10-16T11:00:00Z" })).toBe(true);
  });
});

describe("workspace requests", () => {
  it("initializes one capability session before concurrent workspace reads", async () => {
    let finishInitialization!: (response: Response) => void;
    const initialization = new Promise<Response>((resolve) => { finishInitialization = resolve; });
    const fetchMock = vi.fn((path: string) => path === "/api/workspace"
      ? initialization
      : Promise.resolve(new Response(JSON.stringify({ projects: [] }))));
    vi.stubGlobal("fetch", fetchMock);
    const projects = request("/api/projects");
    const workspace = request("/api/workspace");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/workspace");
    finishInitialization(new Response(JSON.stringify({ mode: "browser", persistence: "memory", executionConfigured: false, githubConfigured: false })));
    await Promise.all([projects, workspace]);
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual(["/api/workspace", "/api/projects"]);
  });

  it("preserves same-origin capability cookies and request bodies", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ project }), { status: 201 })));
    vi.stubGlobal("fetch", fetchMock);
    const result = await request("/api/projects", { method: "POST", body: JSON.stringify({ name: "Test" }) });
    expect(fetchMock).toHaveBeenCalledWith("/api/projects", expect.objectContaining({ credentials: "same-origin", method: "POST", body: '{"name":"Test"}' }));
    expect(result).toEqual({ project });
  });

  it("surfaces backend validation guidance", async () => {
    vi.stubGlobal("fetch", vi.fn((path: string) => Promise.resolve(path === "/api/workspace"
      ? new Response("{}")
      : new Response(JSON.stringify({ error: "Invalid project", details: ["Public HTTPS URL required"] }), { status: 400 }))));
    await expect(request("/api/projects")).rejects.toThrow("Invalid project. Public HTTPS URL required");
  });

  it("does not substitute successful data for unavailable endpoints", async () => {
    vi.stubGlobal("fetch", vi.fn((path: string) => Promise.resolve(path === "/api/workspace"
      ? new Response("{}")
      : new Response("unavailable", { status: 503 }))));
    await expect(request("/api/projects")).rejects.toThrow("Request failed (503)");
  });
});
