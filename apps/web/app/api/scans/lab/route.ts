import { runtimeStore } from "../../_lib/runtime-store";
import { ensureWorkspace, json, mutationAllowed, serviceUnavailable } from "../../_lib/workspace";
import { executionReadiness, executionUnavailable } from "../../_lib/readiness";
import { dispatchQueue } from "../../_lib/queue-dispatch";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

/** Fixed owned fixture. No submitted URL, code, port or hostname is ever executed. */
export async function POST(request: Request): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  try {
    if (!(await executionReadiness()).labEnabled) return json(await executionUnavailable(), 503);
  } catch { return serviceUnavailable(); }
  // Reject a body so callers cannot mistake this endpoint for a localhost scan bypass.
  if ((await request.text()).trim()) return json({ error: "The private lab accepts no target or options." }, 400);
  const workspace = ensureWorkspace(request);
  const url = "https://shipsafe-fixture.invalid/";
  try {
    const [active, recent] = await Promise.all([
      runtimeStore.countActive(),
      runtimeStore.listScans(workspace.id),
    ]);
    if (active >= 5 || recent.filter(scan => Date.parse(scan.createdAt) > Date.now() - 60_000).length >= 3) {
      return json({ error: "Scan queue limit reached. Please wait.", code: active >= 5 ? "QUEUE_FULL" : "RATE_LIMITED" }, 429, workspace.cookie);
    }
    const projects = await runtimeStore.listProjects(workspace.id);
    const project = projects.find(item => item.url === url) ?? await runtimeStore.createProject(workspace.id, { name: "ShipSafe private lab", url, environment: "development" });
    const scan = await runtimeStore.createScan({ projectId: project.id, projectName: project.name, url, mode: "lab" });
    await runtimeStore.addEvent({ scanId: scan.id, stage: "QUEUED", message: "Owned synthetic fixture queued. This tests ShipSafe's execution flow, not a customer website." });
    try { await dispatchQueue(); }
    catch { return serviceUnavailable("DISPATCH_UNAVAILABLE", workspace.cookie); }
    return json({ scanId: scan.id, status: scan.status }, 202, workspace.cookie);
  } catch (error) {
    const code = (error as { code?: string })?.code;
    if (code === "QUEUE_FULL" || code === "RATE_LIMITED") return json({ error: "Scan queue limit reached. Please wait.", code }, 429, workspace.cookie);
    return serviceUnavailable("STORAGE_UNAVAILABLE", workspace.cookie);
  }
}
