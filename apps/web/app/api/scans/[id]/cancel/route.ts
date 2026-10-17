import { apiStore, TERMINAL_STATUSES } from "../../../_lib/store";
import { json, mutationAllowed, workspaceId } from "../../../_lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  const { id } = await context.params;
  const scan = apiStore.ownedScan(workspaceId(request), id);
  if (!scan) return json({ error: "Scan not found" }, 404);
  if (TERMINAL_STATUSES.has(scan.status)) return json({ scanId: id, status: scan.status });
  apiStore.abortExecution(id);
  apiStore.updateScan(id, { status: "CANCELLED" });
  apiStore.addEvent({ scanId: id, stage: "CANCELLED", message: "Scan cancelled; recorded evidence and events were retained" });
  return json({ scanId: id, status: "CANCELLED" });
}
