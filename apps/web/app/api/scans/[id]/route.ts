import { apiStore } from "../../_lib/store";
import { json, workspaceId } from "../../_lib/workspace";

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
  const scan = apiStore.ownedScan(workspaceId(request), id);
  if (!scan) {
    return json({ error: "Scan not found" }, 404);
  }
  const findings = apiStore.listFindings(id);
  const events = apiStore.listEvents(id);
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
}
