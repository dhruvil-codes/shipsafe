import { beforeEach, describe, expect, it } from "vitest";
import { apiStore, MAX_ACTIVE_SCANS } from "../_lib/store";
import { POST as createScan } from "../scans/route";
import { GET as getScan } from "../scans/[id]/route";
import { POST as cancelScan } from "../scans/[id]/cancel/route";
import { GET as streamScan } from "../scans/[id]/stream/route";

function postJson(payload: unknown): Request {
  return new Request("http://localhost/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function createValidScan(url = "https://example.com") {
  const res = await createScan(postJson({ url }));
  const body = (await res.json()) as { scanId: string; status: string };
  return { res, body };
}

async function readStream(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  expect(reader).toBeDefined();
  const decoder = new TextDecoder();
  let text = "";
  for (;;) {
    const { done, value } = (await reader!.read()) as ReadableStreamReadResult<Uint8Array>;
    if (done) break;
    text += decoder.decode(value, { stream: true });
  }
  return text;
}

describe("POST /api/scans", () => {
  beforeEach(() => apiStore.reset());

  it("accepts a valid https URL and returns scanId + QUEUED", async () => {
    const res = await createScan(postJson({ url: "https://example.com" }));
    expect(res.status).toBe(201);
    const body = (await res.json()) as { scanId: string; status: string };
    expect(body.scanId).toMatch(/^scn_/);
    expect(body.status).toBe("QUEUED");
  });

  it("rejects non-http protocols", async () => {
    const res = await createScan(postJson({ url: "ftp://example.com/x" }));
    expect(res.status).toBe(400);
  });

  it("rejects malformed URLs", async () => {
    const res = await createScan(postJson({ url: "not-a-url" }));
    expect(res.status).toBe(400);
  });

  it("blocks loopback, private and metadata targets (S-07)", async () => {
    for (const url of [
      "http://localhost:3000/",
      "http://127.0.0.1/",
      "https://192.168.1.10/admin",
      "https://10.0.0.5/",
      "https://172.16.4.9/",
      "http://169.254.169.254/latest/meta-data/",
      "http://0.0.0.0/",
    ]) {
      const res = await createScan(postJson({ url }));
      expect(res.status, url).toBe(400);
    }
  });

  it("returns 429 when the 5-VM quota is exhausted", async () => {
    for (let i = 0; i < MAX_ACTIVE_SCANS; i++) {
      const { res } = await createValidScan(`https://example-${i}.com`);
      expect(res.status).toBe(201);
    }
    const res = await createScan(postJson({ url: "https://overflow.example.com" }));
    expect(res.status).toBe(429);
  });
});

describe("GET /api/scans/:id", () => {
  beforeEach(() => apiStore.reset());

  it("returns scan details with score and findings", async () => {
    const { body } = await createValidScan();
    const res = await getScan(new Request("http://localhost/"), {
      params: Promise.resolve({ id: body.scanId }),
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      scan: { id: string; status: string; score: number | null };
      findings: unknown[];
      events: unknown[];
    };
    expect(data.scan.id).toBe(body.scanId);
    expect(data.scan.score).toBeNull();
    expect(data.findings).toEqual([]);
    expect(data.events.length).toBeGreaterThan(0);
  });

  it("returns 404 for unknown scans", async () => {
    const res = await getScan(new Request("http://localhost/"), {
      params: Promise.resolve({ id: "scn_missing" }),
    });
    expect(res.status).toBe(404);
  });
});

describe("SSE /api/scans/:id/stream", () => {
  beforeEach(() => apiStore.reset());

  it("emits stored events, log lines and a done terminator", async () => {
    const { body } = await createValidScan();
    const res = await streamScan(new Request("http://localhost/"), {
      params: Promise.resolve({ id: body.scanId }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/event-stream");
    const text = await readStream(res);
    expect(text).toContain("data:");
    expect(text).toContain("Scan queued");
    expect(text).toContain("event: done");
  });

  it("returns 404 for unknown scans", async () => {
    const res = await streamScan(new Request("http://localhost/"), {
      params: Promise.resolve({ id: "scn_missing" }),
    });
    expect(res.status).toBe(404);
  });
});

describe("POST /api/scans/:id/cancel", () => {
  beforeEach(() => apiStore.reset());

  it("cancels a queued scan and frees its quota slot", async () => {
    const { body } = await createValidScan();
    const res = await cancelScan(new Request("http://localhost/", { method: "POST" }), {
      params: Promise.resolve({ id: body.scanId }),
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as { scanId: string; status: string };
    expect(data.status).toBe("CANCELLED");

    const detail = (await (
      await getScan(new Request("http://localhost/"), {
        params: Promise.resolve({ id: body.scanId }),
      })
    ).json()) as { scan: { status: string } };
    expect(detail.scan.status).toBe("CANCELLED");

    // Freed slot: a full quota still accepts one more scan.
    for (let i = 0; i < MAX_ACTIVE_SCANS; i++) {
      await createValidScan(`https://fresh-${i}.example.com`);
    }
    const overflow = await createScan(
      postJson({ url: "https://one-too-many.example.com" }),
    );
    expect(overflow.status).toBe(429);
  });

  it("returns 404 for unknown scans", async () => {
    const res = await cancelScan(new Request("http://localhost/", { method: "POST" }), {
      params: Promise.resolve({ id: "scn_missing" }),
    });
    expect(res.status).toBe(404);
  });
});
