import { apiStore } from "../../_lib/store";
import { ensureWorkspace, json, mutationAllowed } from "../../_lib/workspace";
import { executionReadiness, executionUnavailable } from "../../_lib/readiness";
import { kickQueue } from "../../_lib/baseline-runtime";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Fixed owned fixture. No submitted URL, code, port or hostname is ever executed. */
export async function POST(request: Request): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  if (!executionReadiness().labEnabled) return json(executionUnavailable(), 503);
  // Reject a body so callers cannot mistake this endpoint for a localhost scan bypass.
  if ((await request.text()).trim()) return json({ error: "The private lab accepts no target or options." }, 400);
  const workspace = ensureWorkspace(request);
  if (apiStore.countActive() >= 5 || apiStore.listScans(workspace.id).filter(scan => Date.parse(scan.createdAt) > Date.now() - 60_000).length >= 3) return json({ error: "Scan queue limit reached. Please wait." }, 429, workspace.cookie);
  const url = "https://shipsafe-fixture.invalid/";
  const project = apiStore.listProjects(workspace.id).find(item => item.url === url) ?? apiStore.createProject(workspace.id, { name: "ShipSafe private lab", url, environment: "development" });
  const scan = apiStore.createScan({ projectId: project.id, projectName: project.name, url, mode: "lab" });
  apiStore.addEvent({ scanId: scan.id, stage: "QUEUED", message: "Owned synthetic fixture queued. This tests ShipSafe's execution flow, not a customer website." });
  kickQueue();
  return json({ scanId: scan.id, status: scan.status }, 202, workspace.cookie);
}
