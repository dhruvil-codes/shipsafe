import { apiStore, TERMINAL_STATUSES } from "../../../_lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ id: string }>;
};

/**
 * POST /api/scans/:id/cancel — request cancellation.
 * Marks the scan CANCELLED and records the best-effort sandbox teardown
 * intent (S-19). The workflow/reconciler performs the actual kill; here we
 * log the intent since route handlers never hold sandbox credentials.
 */
export async function POST(
  _request: Request,
  context: RouteContext,
): Promise<Response> {
  const { id } = await context.params;
  const scan = apiStore.getScan(id);
  if (!scan) {
    return Response.json({ error: "Scan not found" }, { status: 404 });
  }
  if (TERMINAL_STATUSES.has(scan.status)) {
    return Response.json({ scanId: scan.id, status: scan.status });
  }

  // Best-effort kill intent: the orchestrator/reconciler owns teardown.
  console.log(`[cancel] scan ${id}: requesting sandbox teardown (best-effort)`);
  const updated = apiStore.updateScan(id, { status: "CANCELLED" });
  apiStore.addEvent({
    scanId: id,
    stage: "CANCELLED",
    message: "Cancellation requested; sandbox teardown initiated",
  });

  return Response.json({ scanId: id, status: updated?.status ?? "CANCELLED" });
}
