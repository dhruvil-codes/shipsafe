/**
 * @shipsafe/scoring — versioned security scoring (v1.0).
 *
 * Pure deterministic functions only (Policy Lives in the Backend — no LLM).
 *
 * Rules (PRD Section 15, starting formula v0.1 as pinned for v1.0):
 * - Per-finding penalty: CRITICAL 40, HIGH 20, MEDIUM 8, LOW 2, INFO 0.
 * - CategoryScore = max(0, 100 - sum of penalties in that category).
 * - Overall = weighted average over ASSESSED categories, weights renormalized.
 *   Category weights: auth 25%, api 20%, source 20%, storage 15%, web 10%,
 *   logging 10%.
 * - A category counts as assessed when it has >= 1 confirmed finding. When a
 *   scan assessed controls but produced no findings at all, every category
 *   passed and all six count as assessed. When nothing was assessed (no
 *   findings AND assessedControls = 0), the overall score is 0 — unrun checks
 *   earn no credit.
 * - Only `confirmed` findings carry penalties. `suspected` findings are
 *   recorded but score nothing (Evidence First).
 * - Any confirmed CRITICAL caps overall at 40 with a visible banner.
 * - Coverage = assessed / applicable * 100 (1 decimal; 0 when applicable = 0).
 * - Grades: >= 90 A, >= 70 B, >= 50 C, else F.
 */
import {
  SecurityScoreSchema,
  type FindingCategory,
  type NormalizedFinding,
  type SecurityGrade,
  type SecurityScore,
  type Severity,
} from '@shipsafe/shared';

/** Scoring rules version pinned on every emitted score. */
export const SCORING_VERSION = 'v1.0' as const;

/** Product-default category weights (sum to 100). Tunable, versioned. */
export const CATEGORY_WEIGHTS: Record<FindingCategory, number> = {
  auth: 25,
  api: 20,
  source: 20,
  storage: 15,
  web: 10,
  logging: 10,
};

/** Severity -> category-score penalty. */
export const SEVERITY_PENALTIES: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 20,
  MEDIUM: 8,
  LOW: 2,
  INFO: 0,
};

/** Confirmed criticals cap the overall score at this value. */
export const CRITICAL_CAP = 40;

/** Override banner shown whenever the critical cap applies. */
export const CRITICAL_BANNER = 'Critical finding caps score at 40';

const ALL_CATEGORIES = Object.keys(CATEGORY_WEIGHTS) as FindingCategory[];

function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

/** Grade thresholds: >= 90 A, >= 70 B, >= 50 C, else F. */
export function gradeFor(overall: number): SecurityGrade {
  if (overall >= 90) return 'A';
  if (overall >= 70) return 'B';
  if (overall >= 50) return 'C';
  return 'F';
}

/**
 * Compute the versioned security score for a scan.
 *
 * @param findings normalized findings (only `confirmed` ones score).
 * @param assessedControls number of applicable controls successfully assessed.
 * @param applicableControls number of applicable controls for the profile.
 */
export function computeScore(
  findings: NormalizedFinding[],
  assessedControls: number,
  applicableControls: number,
): SecurityScore {
  const confirmed = (findings ?? []).filter(
    (f): f is NormalizedFinding =>
      !!f && f.confidence === 'confirmed' && typeof f.category === 'string' && typeof f.severity === 'string',
  );

  // Assessed categories: any category with confirmed evidence. With zero
  // findings but assessed controls, everything passed -> all assessed.
  // With zero findings and zero assessed controls -> nothing assessed.
  const categoriesWithFindings = new Set<FindingCategory>();
  for (const finding of confirmed) categoriesWithFindings.add(finding.category);
  const assessedCategories: FindingCategory[] =
    categoriesWithFindings.size > 0
      ? [...categoriesWithFindings]
      : assessedControls > 0
        ? [...ALL_CATEGORIES]
        : [];

  const penalties = new Map<FindingCategory, number>();
  for (const finding of confirmed) {
    penalties.set(
      finding.category,
      (penalties.get(finding.category) ?? 0) + (SEVERITY_PENALTIES[finding.severity] ?? 0),
    );
  }

  const categoryScores: Record<string, number> = {};
  let weightedSum = 0;
  let weightTotal = 0;
  for (const category of assessedCategories) {
    const score = Math.max(0, 100 - (penalties.get(category) ?? 0));
    categoryScores[category] = score;
    weightedSum += score * CATEGORY_WEIGHTS[category];
    weightTotal += CATEGORY_WEIGHTS[category];
  }

  let overall = weightTotal > 0 ? Math.round(weightedSum / weightTotal) : 0;
  overall = Math.min(100, Math.max(0, overall));

  const hasCritical = confirmed.some((f) => f.severity === 'CRITICAL');
  const capped = hasCritical;
  if (hasCritical) overall = Math.min(overall, CRITICAL_CAP);

  const assessed = Math.max(0, Math.floor(assessedControls));
  const applicable = Math.max(0, Math.floor(applicableControls));
  const coverage = applicable === 0 ? 0 : round1(Math.min(100, (assessed / applicable) * 100));

  // Fail loud on internal inconsistency: output always matches the contract.
  return SecurityScoreSchema.parse({
    overall,
    grade: gradeFor(overall),
    coverage,
    capped,
    ...(capped ? { banner: CRITICAL_BANNER } : {}),
    categoryScores,
    scoringVersion: SCORING_VERSION,
  });
}
