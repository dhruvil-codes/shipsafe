import { z } from "zod";
import type { ScanRecord } from "./store";

export const SecurityResultSchema = z.object({
  id: z.string().min(1).max(80), category: z.string().min(1).max(80), title: z.string().min(1).max(300),
  severity: z.enum(["info", "low", "medium", "high", "critical"]), confidence: z.enum(["none", "low", "medium", "high"]),
  status: z.enum(["PASS", "FAIL", "WARNING", "NOT_APPLICABLE", "NOT_TESTED"]),
  evidence: z.string().min(1).max(12000), timestamp: z.string().datetime({ offset: true }), affectedUrl: z.string().url().max(2048),
  why: z.string().min(1).max(4000), verification: z.string().min(1).max(4000), remediation: z.string().min(1).max(4000), version: z.string().min(1).max(40),
}).strict();
const Results = z.array(SecurityResultSchema).min(1).max(128);
const Registry = z.array(z.object({ id: z.string(), category: z.string(), title: z.string(), version: z.string(), implemented: z.boolean(), severity: z.string(), scoreEligible: z.boolean().optional() }).passthrough()).min(1).max(128);
type Report = { checks: { id: string; title: string; status: string; evidence: string; remediation?: string }[]; findings: { checkId: string; title: string; severity: string; classification: string; description: string; evidence: string; remediation: string }[]; manifest: Record<string, unknown> };

/** Recompute posture from trusted definitions; unavailable checks earn no credit. */
export function securityPosture(value: unknown, definitions: unknown, mode: ScanRecord["mode"]) {
  const results = Results.parse(value);
  const registry = Registry.parse(definitions);
  const eligibleIds = new Set(registry.filter(d => d.implemented && d.scoreEligible !== false && (!d.id.startsWith("deep-") || mode === "deep")).map(d => d.id));
  const eligible = results.filter(r => eligibleIds.has(r.id) && r.status !== "NOT_APPLICABLE");
  const passed = eligible.filter(r => r.status === "PASS").length;
  const tested = eligible.filter(r => ["PASS", "FAIL", "WARNING"].includes(r.status)).length;
  return {
    value: eligible.length && tested ? Math.round(100 * passed / eligible.length) : undefined,
    coverage: eligible.length ? Math.round(100 * tested / eligible.length) : undefined,
    passed, tested, eligible: eligible.length, version: "security-posture-v1", untestedCredit: 0,
    label: "Applicable hardening posture; separate from CVSS vulnerability severity",
  };
}

/** Treat guest output as untrusted and reject invented, duplicate or inconsistent outcomes. */
export function validateSecurityReport(report: Report, scan: ScanRecord, definitions: unknown, classes: readonly string[] = []): void {
  const results = Results.parse(report.manifest.unifiedResults);
  const registry = Registry.parse(definitions);
  const byId = new Map(registry.map(d => [d.id, d]));
  if (byId.size !== registry.length || results.length !== registry.length || new Set(results.map(r => r.id)).size !== results.length ||
      report.checks.length !== results.length || new Set(report.checks.map(c => c.id)).size !== report.checks.length ||
      report.manifest.engine !== "shipsafe-security" || report.manifest.profile !== `${scan.mode}-security-v1` ||
      report.manifest.scope !== new URL(scan.url).hostname || typeof report.manifest.scopeLimited !== "boolean" ||
      !Number.isInteger(report.manifest.requests) || Number(report.manifest.requests) < 1 || Number(report.manifest.requests) > 20) throw new Error("Invalid security report scope or coverage");
  const project = scan.mode === "deep" ? scan.authorizationId : undefined;
  if (scan.mode === "deep" && !project) throw new Error("Missing authorization reference");
  const statusMap = { PASS: "passed", FAIL: "observation", WARNING: "observation", NOT_APPLICABLE: "skipped", NOT_TESTED: "skipped" };
  for (const result of results) {
    const definition = byId.get(result.id);
    const requiredClass = ({ "deep-git-head": "configuration", "deep-discovery": "discovery", "deep-cors": "cors" } as Record<string, string>)[result.id];
    if (requiredClass && !classes.includes(requiredClass) && result.status !== "NOT_TESTED") throw new Error("Unconsented Deep result");
    const check = report.checks.find(c => c.id === result.id);
    if (!definition || result.category !== definition.category || result.title !== definition.title || result.version !== definition.version ||
        result.severity !== definition.severity || result.affectedUrl !== scan.url ||
        (!definition.implemented && result.status !== "NOT_TESTED") ||
        (scan.mode !== "deep" && result.id.startsWith("deep-") && result.status !== "NOT_TESTED") ||
        (result.status === "NOT_TESTED" && result.confidence !== "none") ||
        !check || check.status !== statusMap[result.status] || check.evidence !== result.evidence || check.title !== result.title) throw new Error("Security outcome violates its registered definition");
  }
  const issues = results.filter(r => r.status === "WARNING" || r.status === "FAIL");
  if (issues.length !== report.findings.length || new Set(report.findings.map(f => f.checkId)).size !== report.findings.length) throw new Error("Inconsistent security findings");
  for (const finding of report.findings) {
    const result = issues.find(r => r.id === finding.checkId);
    if (!result || finding.evidence !== result.evidence || finding.severity !== result.severity || finding.classification !== "hardening" ||
        finding.title !== result.title || finding.description !== result.why || finding.remediation !== result.remediation) throw new Error("Finding lacks matching evidence");
  }
  const posture = securityPosture(results, registry, scan.mode);
  if (report.manifest.scopeLimited) { posture.value = undefined; posture.coverage = undefined; }
  report.manifest.posture = posture;
  report.manifest.registry = definitions;
}
