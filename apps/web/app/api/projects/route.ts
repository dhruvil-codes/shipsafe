import { runtimeStore } from "../_lib/runtime-store";
import { ProjectSchema } from "../_lib/url";
import { ensureWorkspace, json, mutationAllowed, serviceUnavailable } from "../_lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const workspace = ensureWorkspace(request);
  try { return json({ projects: await runtimeStore.listProjects(workspace.id) }, 200, workspace.cookie); }
  catch { return serviceUnavailable(); }
}

export async function POST(request: Request): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
  const parsed = ProjectSchema.safeParse(body);
  if (!parsed.success) return json({ error: "Invalid project", details: parsed.error.issues.map((issue) => issue.message) }, 400);
  const workspace = ensureWorkspace(request);
  try {
    const project = await runtimeStore.createProject(workspace.id, { ...parsed.data, url: new URL(parsed.data.url).href });
    return json({ project }, 201, workspace.cookie);
  } catch { return serviceUnavailable(); }
}
