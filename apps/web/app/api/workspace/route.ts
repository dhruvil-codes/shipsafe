import { ensureWorkspace, json } from "../_lib/workspace";
import { executionReadiness } from "../_lib/readiness";
import { runtimeStore } from "../_lib/runtime-store";
import { serviceUnavailable } from "../_lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  try {
    const workspace = ensureWorkspace(request);
    const readiness = await executionReadiness();
    return json({ mode: "browser", persistence: runtimeStore.storageKind(), githubConfigured: false, ...readiness }, 200, workspace.cookie);
  } catch { return serviceUnavailable(); }
}
