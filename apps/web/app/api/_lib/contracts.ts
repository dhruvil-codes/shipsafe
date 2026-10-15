// TODO: import from @shipsafe/shared after merge of feat/agent-2.
// Local contract copy for the web API (Agent 3 parallel-build shim).
import { z } from "zod";

export const SeveritySchema = z.enum([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
]);
export type Severity = z.infer<typeof SeveritySchema>;

export const ToolResultSchema = z.object({
  tool: z.string(),
  toolVersion: z.string(),
  status: z.enum(["passed", "failed", "skipped"]),
  startedAt: z.string(),
  endedAt: z.string(),
  durationMs: z.number(),
  checksAttempted: z.number(),
  evidence: z.unknown(),
  error: z.string().optional(),
});
export type ToolResult = z.infer<typeof ToolResultSchema>;

export const NormalizedFindingSchema = z.object({
  fingerprint: z.string(),
  target: z.string(),
  category: z.enum(["auth", "api", "source", "storage", "web", "logging"]),
  ruleId: z.string(),
  title: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  evidence: z.unknown(),
  remediation: z.string(),
  confidence: z.enum(["confirmed", "suspected"]),
  cwe: z.string().optional(),
  owasp: z.string().optional(),
});
export type NormalizedFinding = z.infer<typeof NormalizedFindingSchema>;

export const SecurityScoreSchema = z.object({
  overall: z.number(),
  grade: z.enum(["A", "B", "C", "F"]),
  coverage: z.number(),
  capped: z.boolean(),
  banner: z.string().optional(),
  categoryScores: z.record(z.string(), z.number()),
  scoringVersion: z.literal("v1.0"),
});
export type SecurityScore = z.infer<typeof SecurityScoreSchema>;

export const ScanEventSchema = z.object({
  scanId: z.string(),
  stage: z.string(),
  message: z.string(),
  timestamp: z.string(),
});
export type ScanEvent = z.infer<typeof ScanEventSchema>;
