/**
 * @shipsafe/shared — canonical Zod schemas + inferred TypeScript types.
 *
 * These contracts are consumed by every other ShipSafe workstream
 * (runner, orchestration, scoring, reports, API). Do not change them
 * without the contract-change protocol (docs/contracts/CHANGES.md).
 */
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/** Finding severity, ordered CRITICAL > HIGH > MEDIUM > LOW > INFO. */
export const SeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
export type Severity = z.infer<typeof SeveritySchema>;

// ---------------------------------------------------------------------------
// ScanManifest
// ---------------------------------------------------------------------------

/** Scan profiles supported by ShipSafe (PRD Section 8). */
export const ScanProfileSchema = z.enum([
  'baseline',
  'code-audit',
  'authenticated',
  'ai',
  'advanced',
]);
export type ScanProfile = z.infer<typeof ScanProfileSchema>;

/** Minimal scan manifest: what to scan, under which profile, within scope. */
export const ScanManifestSchema = z.object({
  scanId: z.string().min(1),
  targetUrl: z.string().url(),
  profile: ScanProfileSchema,
  allowedTargets: z.array(z.string().min(1)),
  createdAt: z.string().datetime(),
});
export type ScanManifest = z.infer<typeof ScanManifestSchema>;

// ---------------------------------------------------------------------------
// ToolResult
// ---------------------------------------------------------------------------

/**
 * Execution status of a single scanner invocation.
 * - `passed`: the tool ran to completion and its evidence was parsed.
 * - `failed`: the tool errored or timed out — its output MUST NOT create findings.
 * - `skipped`: the tool did not run — MUST NOT improve the score.
 */
export const ToolStatusSchema = z.enum(['passed', 'failed', 'skipped']);
export type ToolStatus = z.infer<typeof ToolStatusSchema>;

/** Raw result of one tool execution, as produced by the on-VM runner. */
export const ToolResultSchema = z.object({
  tool: z.string().min(1),
  toolVersion: z.string().min(1),
  status: ToolStatusSchema,
  startedAt: z.string().datetime(),
  endedAt: z.string().datetime(),
  durationMs: z.number().int().nonnegative(),
  checksAttempted: z.number().int().nonnegative(),
  evidence: z.unknown(),
  error: z.string().optional(),
});
export type ToolResult = z.infer<typeof ToolResultSchema>;

// ---------------------------------------------------------------------------
// NormalizedFinding
// ---------------------------------------------------------------------------

/** Scoring categories (PRD Section 15). */
export const FindingCategorySchema = z.enum([
  'auth',
  'api',
  'source',
  'storage',
  'web',
  'logging',
]);
export type FindingCategory = z.infer<typeof FindingCategorySchema>;

/**
 * Evidence confidence. Only `confirmed` findings (backed by scanner output)
 * affect the security score. `suspected` findings are recorded for review
 * but carry no penalty (Evidence First invariant).
 */
export const ConfidenceSchema = z.enum(['confirmed', 'suspected']);
export type Confidence = z.infer<typeof ConfidenceSchema>;

/**
 * A single deduplicated, evidence-backed finding.
 * `fingerprint` is `sha256(target|category|ruleId|title)` truncated to
 * 16 hex chars, so re-scans of the same issue produce the same fingerprint.
 */
export const NormalizedFindingSchema = z.object({
  fingerprint: z.string().regex(/^[0-9a-f]{16}$/),
  target: z.string().min(1),
  category: FindingCategorySchema,
  ruleId: z.string().min(1),
  title: z.string().min(1),
  description: z.string().min(1),
  severity: SeveritySchema,
  cwe: z.string().optional(),
  owasp: z.string().optional(),
  evidence: z.unknown(),
  remediation: z.string().min(1),
  confidence: ConfidenceSchema,
});
export type NormalizedFinding = z.infer<typeof NormalizedFindingSchema>;

// ---------------------------------------------------------------------------
// SecurityScore
// ---------------------------------------------------------------------------

export const SecurityGradeSchema = z.enum(['A', 'B', 'C', 'F']);
export type SecurityGrade = z.infer<typeof SecurityGradeSchema>;

/** Versioned aggregate score for one scan. `scoringVersion` pins the rules. */
export const SecurityScoreSchema = z.object({
  overall: z.number().min(0).max(100),
  grade: SecurityGradeSchema,
  coverage: z.number().min(0).max(100),
  capped: z.boolean(),
  banner: z.string().optional(),
  categoryScores: z.record(z.string(), z.number().min(0).max(100)),
  scoringVersion: z.literal('v1.0'),
});
export type SecurityScore = z.infer<typeof SecurityScoreSchema>;

// ---------------------------------------------------------------------------
// ScanEvent
// ---------------------------------------------------------------------------

/** Progress / lifecycle event for a scan (consumed by the live-scan view). */
export const ScanEventSchema = z.object({
  scanId: z.string().min(1),
  stage: z.string().min(1),
  message: z.string().min(1),
  timestamp: z.string().datetime(),
});
export type ScanEvent = z.infer<typeof ScanEventSchema>;
