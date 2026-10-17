import { z } from "zod";
import { apiStore } from "../../../_lib/store";
import { DEEP_CLASSES } from "../../../_lib/security-policy";
import { verifyProject } from "../../../_lib/verification";
import { json, mutationAllowed, workspaceId } from "../../../_lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const consentSchema = z.object({
  consent: z.literal(true),
  classes: z.array(z.enum(DEEP_CLASSES)).min(1).max(DEEP_CLASSES.length).refine(values => new Set(values).size === values.length),
}).strict();
type Context = { params: Promise<{ id: string }> };

/** Owner-only DNS instructions and the current bounded grant. */
export async function GET(request: Request, context: Context): Promise<Response> {
  const { id } = await context.params;
  const project = apiStore.getProject(workspaceId(request), id);
  if (!project) return json({ error: "Project not found" }, 404);
  const hostname = new URL(project.url).hostname;
  return json({ hostname, dnsRecord: { type: "TXT", name: `_shipsafe.${hostname}`, value: `shipsafe-verification=${project.verificationToken}` }, authorization: project.securityAuthorization ?? null });
}

/** Consent never substitutes for a fresh exact-host DNS proof. */
export async function POST(request: Request, context: Context): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  const { id } = await context.params;
  const owner = workspaceId(request);
  const project = apiStore.getProject(owner, id);
  if (!project) return json({ error: "Project not found" }, 404);
  let body: unknown;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
  const parsed = consentSchema.safeParse(body);
  if (!parsed.success) return json({ error: "Explicit consent and supported, unique test classes are required.", code: "CONSENT_REQUIRED" }, 400);
  const result = await verifyProject(project);
  if (!result.ok) return json({ error: result.error, code: "VERIFICATION_FAILED" }, 422);
  const authorization = apiStore.authorizeDeep(owner!, id, parsed.data.classes, project.securityAuthorizationRevision ?? 0);
  if (!authorization) return json({ error: "Authorization changed while DNS was being verified. Submit fresh consent to continue.", code: "AUTHORIZATION_CHANGED" }, 409);
  return json({ authorization }, 201);
}

/** Cancels queued and active Deep scans without cancelling standard work. */
export async function DELETE(request: Request, context: Context): Promise<Response> {
  if (!mutationAllowed(request)) return json({ error: "Cross-origin requests are not allowed" }, 403);
  const { id } = await context.params;
  const owner = workspaceId(request);
  if (!apiStore.getProject(owner, id)) return json({ error: "Project not found" }, 404);
  return json({ revoked: true, cancelledScanIds: apiStore.revokeDeep(owner!, id) });
}
