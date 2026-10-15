import { z } from "zod";

/** Lifecycle states for a scan sandbox. */
export type SandboxStatus =
  | "creating"
  | "running"
  | "suspended"
  | "stopped"
  | "deleted"
  | "failed";

/** Reference to a sandbox machine. */
export interface SandboxRef {
  id: string;
  template: string;
  status: SandboxStatus;
  labels: Record<string, string>;
}

/** Result of executing a command inside a sandbox. */
export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
}

/** Options for creating a sandbox. At least one of `template` / `snapshotId` SHOULD be set. */
export type CreateOpts =
  | { template: string; snapshotId?: string; labels: Record<string, string> }
  | { snapshotId: string; template?: string; labels: Record<string, string> };

/** Chunk emitted while streaming command output. */
export interface OutputChunk {
  stream: "stdout" | "stderr";
  data: string;
}

export type OutputChunkHandler = (chunk: OutputChunk) => void;

export const LabelsSchema = z.record(z.string(), z.string());

export const CreateOptsSchema = z
  .object({
    template: z.string().min(1).optional(),
    snapshotId: z.string().min(1).optional(),
    labels: LabelsSchema,
  })
  .refine((o) => o.template !== undefined || o.snapshotId !== undefined, {
    message: "Either template or snapshotId must be provided",
  });

export const SandboxRefSchema = z.object({
  id: z.string().min(1),
  template: z.string().min(1),
  status: z.enum([
    "creating",
    "running",
    "suspended",
    "stopped",
    "deleted",
    "failed",
  ]),
  labels: LabelsSchema,
});

export const ExecResultSchema = z.object({
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  durationMs: z.number().nonnegative(),
});
