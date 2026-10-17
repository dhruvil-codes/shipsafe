import { apiStore } from "../../../_lib/store";
import { json, mutationAllowed, workspaceId } from "../../../_lib/workspace";
import { verifyProject } from "../../../_lib/verification";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  const { id } = await context.params;
  const project = apiStore.getProject(workspaceId(request), id);
  if (!project) return json({ error: "Project not found" }, 404);
  const result = await verifyProject(project);
  return result.ok ? json({ project: result.project }) : json({ error: result.error, code: "VERIFICATION_FAILED" }, 422);
}
