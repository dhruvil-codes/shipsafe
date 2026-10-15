import { apiStore } from "../../_lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = {
  params: { id: string } | Promise<{ id: string }>;
};

async function resolveParams(ctx: RouteContext): Promise<{ id: string }> {
  return await ctx.params;
}

/** GET /api/scans/:id — scan details + score + findings. */
export async function GET(
  _request: Request,
  context: RouteContext,
): Promise<Response> {
  const { id } = await resolveParams(context);
  const scan = apiStore.getScan(id);
  if (!scan) {
    return Response.json({ error: "Scan not found" }, { status: 404 });
  }
  const findings = apiStore.listFindings(id);
  const events = apiStore.listEvents(id);
  return Response.json({
    scan: {
      id: scan.id,
      projectId: scan.projectId,
      projectName: scan.projectName,
      url: scan.url,
      status: scan.status,
      score: scan.score ?? null,
      coverage: scan.coverage ?? null,
      createdAt: scan.createdAt,
    },
    findings,
    events,
  });
}
