import { apiStore } from "../_lib/store";
import { CreateScanSchema } from "../_lib/url";
import { json, mutationAllowed, workspaceId } from "../_lib/workspace";
import { executionReadiness, executionUnavailable } from "../_lib/readiness";
import { assertDeepAuthorization } from "../_lib/security-policy";
import { verifyProject } from "../_lib/verification";
import { kickQueue } from "../_lib/baseline-runtime";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET(request: Request): Promise<Response> {
  if (executionReadiness().executionConfigured) kickQueue();
  const owner = workspaceId(request);
  return json({ scans: owner ? apiStore.listScans(owner) : [] });
}

/** Only a browser-owned project and recorded authorization attestation can reach readiness. */
export async function POST(request: Request): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
  if (body && typeof body === "object" && "url" in body) {
    return json({ error: "Raw URL scan payloads are disabled. Use the URL entry flow to create a target and accept its exact-host scope. Deep Scan additionally requires verified ownership and consent.", code: "PROJECT_REQUIRED" }, 403);
  }
  const parsed = CreateScanSchema.safeParse(body);
  if (!parsed.success) return json({ error: "A projectId and scopeAccepted: true are required", code: "SCOPE_REQUIRED" }, 400);
  let project = apiStore.getProject(workspaceId(request), parsed.data.projectId);
  if (!project) return json({ error: "Project not found" }, 404);
  if (parsed.data.mode === "deep") {
    try { assertDeepAuthorization(project, { url: project.url, authorizationId: parsed.data.authorizationId }); }
    catch { return json({ error: "Deep scan requires current verified exact-host authorization.", code: "DEEP_AUTHORIZATION_REQUIRED" }, 403); }
    const verification = await verifyProject(project);
    if (!verification.ok) return json({ error: verification.error, code: "VERIFICATION_FAILED" }, 422);
    project = verification.project;
    // Re-read after the asynchronous DNS lookup so revocation wins an enqueue race.
    project = apiStore.getProject(workspaceId(request), project.id)!;
    try { assertDeepAuthorization(project, { url: project.url, authorizationId: parsed.data.authorizationId }); }
    catch { return json({ error: "Deep authorization is no longer valid.", code: "DEEP_AUTHORIZATION_REQUIRED" }, 403); }
  }
  if (!executionReadiness().executionConfigured) return json(executionUnavailable(), 503);
  if (apiStore.countActive() >= 5) return json({ error: "The scan queue is full. Try again after a job finishes.", code: "QUEUE_FULL" }, 429);
  const owner = workspaceId(request)!;
  if (apiStore.listScans(owner).filter(scan => Date.parse(scan.createdAt) > Date.now() - 60_000).length >= 3) return json({ error: "Please wait before submitting another scan.", code: "RATE_LIMITED" }, 429);
  const scan = apiStore.createScan({ projectId: project.id, projectName: project.name, url: project.url, mode: parsed.data.mode, authorizationId: parsed.data.authorizationId, scopeAccepted: true });
  apiStore.addEvent({ scanId: scan.id, stage: "QUEUED", message: parsed.data.mode === "deep" ? "Verified Deep assessment queued for the consented exact hostname and test classes." : "Baseline queued from the user's authorization attestation. Checks are bounded to this exact hostname; no subdomain discovery or exploit templates." });
  kickQueue();
  return json({ scanId: scan.id, status: scan.status }, 202);
}
