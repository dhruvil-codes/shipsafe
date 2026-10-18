import { runtimeStore } from "../../../_lib/runtime-store";
import { TERMINAL_STATUSES } from "../../../_lib/store";
import { json, mutationAllowed, serviceUnavailable, workspaceId } from "../../../_lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  const { id } = await context.params;
  try {
    const scan = await runtimeStore.ownedScan(workspaceId(request), id);
    if (!scan) return json({ error: "Scan not found" }, 404);
    if (TERMINAL_STATUSES.has(scan.status)) return json({ scanId: id, status: scan.status });
    await runtimeStore.abortExecution(id);
    await runtimeStore.updateScan(id, { status: "CANCELLED" });
    await runtimeStore.addEvent({ scanId: id, stage: "CANCELLED", message: "Scan cancelled; recorded evidence and events were retained" });
    return json({ scanId: id, status: "CANCELLED" });
  } catch { return serviceUnavailable(); }
}
