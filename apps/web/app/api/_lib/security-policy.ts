import { z } from "zod";
import type { Project, ScanRecord } from "./store";
import { publicProjectUrl } from "./url";

export const DEEP_CLASSES = ["configuration", "discovery", "cors", "vulnerability"] as const;
export const DEEP_AUTHORIZATION_TTL_MS = 15 * 60 * 1000;
export const SecurityAuthorizationSchema = z.object({
  id: z.string().min(1), hostname: z.string().min(1),
  classes: z.array(z.enum(DEEP_CLASSES)).min(1).max(DEEP_CLASSES.length).refine(values => new Set(values).size === values.length),
  createdAt: z.string().datetime(), expiresAt: z.string().datetime(), revokedAt: z.string().datetime().optional(),
}).strict();
export type SecurityAuthorization = z.infer<typeof SecurityAuthorizationSchema>;

/** Deterministic exact-host policy; DNS must also be refreshed before dispatch. */
export function assertDeepAuthorization(project: Project, scan?: Pick<ScanRecord, "url" | "authorizationId">, now = Date.now()): SecurityAuthorization {
  const parsed = SecurityAuthorizationSchema.safeParse(project.securityAuthorization);
  if (!parsed.success || !publicProjectUrl(project.url)) throw new Error("Deep scan requires verified exact-host authorization.");
  const grant = parsed.data;
  const verified = Date.parse(project.verifiedAt ?? "");
  const proofExpiry = Date.parse(project.verificationExpiresAt ?? "");
  const created = Date.parse(grant.createdAt);
  const expiry = Date.parse(grant.expiresAt);
  if (!Number.isFinite(now) || !Number.isFinite(verified) || verified > now || !Number.isFinite(proofExpiry) || proofExpiry <= now ||
      created > now || expiry <= now || expiry <= created || expiry - created > DEEP_AUTHORIZATION_TTL_MS || expiry > proofExpiry ||
      grant.revokedAt || grant.hostname !== new URL(project.url).hostname ||
      (scan && (scan.authorizationId !== grant.id || !publicProjectUrl(scan.url) || new URL(scan.url).hostname !== grant.hostname))) {
    throw new Error("Deep authorization is expired, revoked, or outside the verified exact host.");
  }
  return structuredClone(grant);
}
