import { runtimeStore } from "../_lib/runtime-store";
import { CreateScanSchema } from "../_lib/url";
import { json, mutationAllowed, serviceUnavailable, workspaceId } from "../_lib/workspace";
import { executionReadiness, executionUnavailable } from "../_lib/readiness";
import { assertDeepAuthorization } from "../_lib/security-policy";
import { verifyProject } from "../_lib/verification";
import { dispatchQueue } from "../_lib/queue-dispatch";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function GET(request: Request): Promise<Response> {
  try {
    const owner = workspaceId(request);
    return json({ scans: owner ? await runtimeStore.listScans(owner) : [] });
  } catch { return serviceUnavailable(); }
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
  const owner = workspaceId(request);
  let project;
  try { project = await runtimeStore.getProject(owner, parsed.data.projectId); }
  catch { return serviceUnavailable(); }
  if (!project) return json({ error: "Project not found" }, 404);
  if (parsed.data.mode === "deep") {
    try { assertDeepAuthorization(project, { url: project.url, authorizationId: parsed.data.authorizationId }); }
    catch { return json({ error: "Deep scan requires current verified exact-host authorization.", code: "DEEP_AUTHORIZATION_REQUIRED" }, 403); }
    let verification;
    try { verification = await verifyProject(project); }
    catch { return serviceUnavailable(); }
    if (!verification.ok) return json({ error: verification.error, code: "VERIFICATION_FAILED" }, 422);
    project = verification.project;
    // Re-read after the asynchronous DNS lookup so revocation wins an enqueue race.
    try { project = await runtimeStore.getProject(owner, project.id); }
    catch { return serviceUnavailable(); }
    if (!project) return json({ error: "Project not found" }, 404);
    try { assertDeepAuthorization(project, { url: project.url, authorizationId: parsed.data.authorizationId }); }
    catch { return json({ error: "Deep authorization is no longer valid.", code: "DEEP_AUTHORIZATION_REQUIRED" }, 403); }
  }
  let readiness;
  try { readiness = await executionReadiness(); }
  catch { return serviceUnavailable(); }
  if (!readiness.executionConfigured) {
    try { return json(await executionUnavailable(), 503); }
    catch { return serviceUnavailable(); }
  }
  if (!owner) return json({ error: "Project not found" }, 404);
  try {
    const [active, recent] = await Promise.all([
      runtimeStore.countActive(),
      runtimeStore.listScans(owner),
    ]);
    if (active >= 5) return json({ error: "The scan queue is full. Try again after a job finishes.", code: "QUEUE_FULL" }, 429);
    if (recent.filter(scan => Date.parse(scan.createdAt) > Date.now() - 60_000).length >= 3) {
      return json({ error: "Please wait before submitting another scan.", code: "RATE_LIMITED" }, 429);
    }
    const scan = await runtimeStore.createScan({ projectId: project.id, projectName: project.name, url: project.url, mode: parsed.data.mode, authorizationId: parsed.data.authorizationId, scopeAccepted: true });
    await runtimeStore.addEvent({ scanId: scan.id, stage: "QUEUED", message: parsed.data.mode === "deep" ? "Verified Deep assessment queued for the consented exact hostname and test classes." : "Baseline queued from the user's authorization attestation. Checks are bounded to this exact hostname; no subdomain discovery or exploit templates." });
    try { await dispatchQueue(); }
    catch { return serviceUnavailable("DISPATCH_UNAVAILABLE"); }
    return json({ scanId: scan.id, status: scan.status }, 202);
  } catch (error) {
    const code = (error as { code?: string })?.code;
    if (code === "QUEUE_FULL") return json({ error: "The scan queue is full. Try again after a job finishes.", code }, 429);
    if (code === "RATE_LIMITED") return json({ error: "Please wait before submitting another scan.", code }, 429);
    return serviceUnavailable();
  }
}
