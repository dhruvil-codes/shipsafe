import { runtimeStore } from "../../_lib/runtime-store";
import { json, serviceUnavailable, workspaceId } from "../../_lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  const owner = workspaceId(request);
  try {
    const project = await runtimeStore.getProject(owner, id);
    if (!owner || !project) return json({ error: "Project not found" }, 404);
    return json({ project, scans: await runtimeStore.listScans(owner, id) });
  } catch { return serviceUnavailable(); }
}
