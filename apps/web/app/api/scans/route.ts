import { apiStore, MAX_ACTIVE_SCANS } from "../_lib/store";
import { CreateScanSchema } from "../_lib/url";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function newProjectId(): string {
  return `prj_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * POST /api/scans — submit a scan.
 * Body: { url, projectName? }. Validates the URL (http/https only, blocks
 * private/loopback/metadata ranges best-effort per S-07), reserves a slot
 * against the 5-VM quota, and returns { scanId, status }.
 */
export async function POST(request: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = CreateScanSchema.safeParse(body);
  if (!parsed.success) {
    return Response.json(
      {
        error: "Invalid scan target",
        details: parsed.error.issues.map((i) => i.message),
      },
      { status: 400 },
    );
  }

  if (apiStore.countActive() >= MAX_ACTIVE_SCANS) {
    return Response.json(
      { error: "Scan quota exceeded: too many active scans (max 5)" },
      { status: 429 },
    );
  }

  const normalizedUrl = new URL(parsed.data.url).href;
  const scan = apiStore.createScan({
    projectId: newProjectId(),
    projectName: parsed.data.projectName,
    url: normalizedUrl,
  });
  apiStore.addEvent({
    scanId: scan.id,
    stage: "QUEUED",
    message: `Scan queued for ${normalizedUrl}`,
  });

  return Response.json({ scanId: scan.id, status: scan.status }, { status: 201 });
}
