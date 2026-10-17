import { ensureWorkspace, json } from "../_lib/workspace";
import { executionReadiness } from "../_lib/readiness";
import { apiStore } from "../_lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const workspace = ensureWorkspace(request);
  return json({ mode: "browser", persistence: apiStore.isPersistent() ? "local-file" : "memory", githubConfigured: false, ...executionReadiness() }, 200, workspace.cookie);
}
