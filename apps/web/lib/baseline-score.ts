/** A profile score for the bounded response-hardening checks only. */
export const BASELINE_SCORE_VERSION = "url-baseline-pass-ratio-v1";
export const BASELINE_CHECK_IDS = [
  "https", "https-redirect", "hsts", "csp", "framing", "nosniff", "referrer",
  "cookie-secure", "cookie-httponly", "cookie-samesite", "cors", "error-disclosure", "http-response",
] as const;
export const BASELINE_APPLICABLE_CHECKS = BASELINE_CHECK_IDS.length;

export type BaselineCheckOutcome = { id: string; status: string };
export type BaselineScore = {
  value: number;
  grade: "A" | "B" | "C" | "F";
  passed: number;
  observed: number;
  assessed: number;
  skipped: number;
  failed: number;
  coverage: number;
  applicable: number;
  version: string;
};

export function gradeForBaselineScore(score: number): BaselineScore["grade"] {
  if (score >= 90) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  return "F";
}

/** True only when each expected profile control has exactly one valid outcome. */
export function hasCompleteBaselineOutcomes(checks: readonly BaselineCheckOutcome[]): boolean {
  return checks.length === BASELINE_APPLICABLE_CHECKS
    && new Set(checks.map(check => check.id)).size === BASELINE_APPLICABLE_CHECKS
    && checks.every(check => (BASELINE_CHECK_IDS as readonly string[]).includes(check.id));
}

/**
 * Score the share of completed response checks that met their configured
 * baseline. Observations are assessed but do not pass; skipped and failed
 * outcomes receive no score or coverage credit. This is not the product-wide
 * vulnerability score from packages/scoring.
 */
export function scoreUrlBaseline(checks: readonly BaselineCheckOutcome[]): BaselineScore | null {
  if (checks.length === 0) return null;
  const byId = new Map<string, BaselineCheckOutcome>();
  const duplicates = new Set<string>();
  for (const check of checks) {
    if (!(BASELINE_CHECK_IDS as readonly string[]).includes(check.id)) continue;
    if (byId.has(check.id)) duplicates.add(check.id);
    else byId.set(check.id, check);
  }
  for (const id of duplicates) byId.delete(id);
  const valid = [...byId.values()];
  const passed = valid.filter(check => check.status === "passed").length;
  const observed = valid.filter(check => check.status === "observation").length;
  const skipped = valid.filter(check => check.status === "skipped").length;
  const failed = valid.filter(check => check.status === "failed").length;
  const assessed = passed + observed;
  if (assessed === 0) return null;
  return {
    value: Math.round((passed / assessed) * 100),
    grade: gradeForBaselineScore((passed / assessed) * 100),
    passed, observed, assessed, skipped, failed,
    coverage: Math.round((assessed / BASELINE_APPLICABLE_CHECKS) * 1000) / 10,
    applicable: BASELINE_APPLICABLE_CHECKS,
    version: BASELINE_SCORE_VERSION,
  };
}
