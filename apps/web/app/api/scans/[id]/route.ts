import { runtimeStore } from "../../_lib/runtime-store";
import { json, serviceUnavailable, workspaceId } from "../../_lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ id: string }>;
};

async function resolveParams(ctx: RouteContext): Promise<{ id: string }> {
  return await ctx.params;
}

/** GET /api/scans/:id — scan details + score + findings. */
export async function GET(
  request: Request,
  context: RouteContext,
): Promise<Response> {
  const { id } = await resolveParams(context);
  try {
    const scan = await runtimeStore.ownedScan(workspaceId(request), id);
    if (!scan) return json({ error: "Scan not found" }, 404);
    const findings = await runtimeStore.listFindings(id);
    const events = await runtimeStore.listEvents(id);
    return json({
    scan: {
      id: scan.id,
      projectId: scan.projectId,
      projectName: scan.projectName,
      url: scan.url,
      status: scan.status,
      score: scan.score ?? null,
      coverage: scan.coverage ?? null,
      createdAt: scan.createdAt,
      mode: scan.mode,
      reportManifest: scan.reportManifest,
    },
    findings,
    events,
    });
  } catch { return serviceUnavailable(); }
}
