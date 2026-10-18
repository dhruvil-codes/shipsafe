import { runtimeStore } from "../../../_lib/runtime-store";
import { json, mutationAllowed, serviceUnavailable, workspaceId } from "../../../_lib/workspace";
import { verifyProject } from "../../../_lib/verification";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  const { id } = await context.params;
  let project;
  try { project = await runtimeStore.getProject(workspaceId(request), id); }
  catch { return serviceUnavailable(); }
  if (!project) return json({ error: "Project not found" }, 404);
  let result;
  try { result = await verifyProject(project); }
  catch { return serviceUnavailable(); }
  return result.ok ? json({ project: result.project }) : json({ error: result.error, code: "VERIFICATION_FAILED" }, 422);
}
