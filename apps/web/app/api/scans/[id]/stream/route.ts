import { apiStore } from "../../../_lib/store";
import {
  getLiveSandbox,
  loadRunnerFiles,
  resolveRemoteBase,
  resolveRunnerDir,
  runLiveScan,
  syncRunnerToVM,
} from "@shipsafe/sandbox/live-runner";
import { normalize, normalizeOsint } from "@shipsafe/adapters";
import { computeScore } from "@shipsafe/scoring";
import { ToolResultSchema, type ToolResult } from "@shipsafe/shared";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
/** Full baseline + OSINT scan can run ~7 minutes; allow a long stream. */
export const maxDuration = 600;

type RouteContext = {
  params: Promise<{ id: string }>;
};

function sseLine(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function sseError(message: string): string {
  return sseLine({ type: "error", message });
}

const DONE = "event: done\ndata: {}\n\n";

function isToolResult(value: unknown): value is ToolResult {
  return ToolResultSchema.safeParse(value).success;
}

/**
 * GET /api/scans/:id/stream — live scan execution over Server-Sent Events.
 *
 * Pure Real Execution Mode: connects to the live InstaBox micro-VM, syncs
 * the runner scripts, executes the real scanners, and streams genuine VM
 * stdout line-by-line. No mock generators, no demo replays. When the VM
 * is unreachable the stream carries the exact error and terminates.
 */
export async function GET(
  request: Request,
  context: RouteContext,
): Promise<Response> {
  const { id } = await context.params;
  const scan = apiStore.getScan(id);
  if (!scan) {
    return Response.json({ error: "Scan not found" }, { status: 404 });
  }

  const storedEvents = apiStore.listEvents(id);
  const encoder = new TextEncoder();
  const signal = request.signal;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const enqueue = (text: string) => {
        controller.enqueue(encoder.encode(text));
      };
      const fail = (message: string, stage: string) => {
        apiStore.updateScan(id, { status: "FAILED" });
        apiStore.addEvent({ scanId: id, stage, message });
        enqueue(sseError(message));
        enqueue(DONE);
        controller.close();
      };

      enqueue(": connected\n\n");
      for (const event of storedEvents) {
        enqueue(
          sseLine({
            type: "event",
            scanId: event.scanId,
            stage: event.stage,
            message: event.message,
            timestamp: event.timestamp,
          }),
        );
      }

      if (signal.aborted) {
        controller.close();
        return;
      }

      // --- connect to the live micro-VM ---
      apiStore.updateScan(id, { status: "PROVISIONING" });
      apiStore.addEvent({ scanId: id, stage: "PROVISIONING", message: "Connecting to live InstaBox micro-VM" });
      let sbx;
      try {
        sbx = await getLiveSandbox();
      } catch (err) {
        const message = `[ERROR] Failed to connect to InstaBox Micro-VM: ${(err as Error).message}`;
        fail(message, "PROVISIONING");
        return;
      }
      enqueue(
        sseLine({
          type: "event",
          scanId: id,
          stage: "PROVISIONING",
          message: "Connected to live InstaBox micro-VM",
          timestamp: new Date().toISOString(),
        }),
      );

      // --- sync runner scripts ---
      let runnerDir: string;
      let remoteBase: string;
      try {
        runnerDir = resolveRunnerDir(process.cwd());
        remoteBase = await resolveRemoteBase(sbx);
      } catch (err) {
        fail(
          `[ERROR] Failed to connect to InstaBox Micro-VM: ${(err as Error).message}`,
          "PROVISIONING",
        );
        return;
      }
      try {
        await syncRunnerToVM(sbx, remoteBase, loadRunnerFiles(runnerDir));
      } catch (err) {
        fail(
          `[ERROR] Failed to sync runner scripts to InstaBox Micro-VM: ${(err as Error).message}`,
          "PROVISIONING",
        );
        return;
      }

      // --- execute the real scanners, streaming genuine stdout ---
      apiStore.updateScan(id, { status: "RUNNING" });
      apiStore.addEvent({ scanId: id, stage: "RUNNING", message: "Executing live scan on micro-VM" });
      let live;
      try {
        live = await runLiveScan(
          sbx,
          scan.url,
          {
            onStdout: (chunk: string) => {
              enqueue(sseLine({ type: "stdout", scanId: id, text: chunk }));
            },
          },
          { signal, remoteBase },
        );
      } catch (err) {
        if (signal.aborted) {
          apiStore.updateScan(id, { status: "CANCELLED" });
          apiStore.addEvent({ scanId: id, stage: "CANCELLED", message: "Stream disconnected; live run aborted" });
          controller.close();
          return;
        }
        fail(
          `[ERROR] Live scan failed on InstaBox Micro-VM: ${(err as Error).message}`,
          "RUNNING",
        );
        return;
      }

      // --- normalize genuine findings, score, persist ---
      apiStore.updateScan(id, { status: "PROCESSING" });
      const scanTools = (
        typeof live.scanResult === "object" &&
        live.scanResult !== null &&
        Array.isArray((live.scanResult as Record<string, unknown>)["tools"])
          ? ((live.scanResult as Record<string, unknown>)["tools"] as unknown[])
          : []
      ).filter(isToolResult);
      const osintTools = isToolResult(live.osintResult) ? [live.osintResult] : [];
      const findings = [
        ...normalize(scanTools, scan.url),
        ...normalizeOsint(osintTools, scan.url),
      ];
      const passedChecks = [...scanTools, ...osintTools]
        .filter((t) => t.status === "passed")
        .reduce((sum, t) => sum + t.checksAttempted, 0);
      const missed = [...scanTools, ...osintTools].filter((t) => t.status !== "passed").length;
      // A scan that produced no ToolResults at all assessed nothing.
      const assessed = scanTools.length + osintTools.length === 0 ? 0 : passedChecks;
      const applicable = assessed + missed;
      const score = computeScore(findings, assessed, applicable);
      apiStore.updateScan(id, {
        status: "COMPLETED",
        score: score.overall,
        coverage: score.coverage,
      });
      for (const f of findings) {
        apiStore.addFinding({
          scanId: id,
          severity: f.severity,
          title: f.title,
          description: f.description,
          evidence: JSON.stringify(f.evidence),
          remediation: f.remediation,
          cwe: f.cwe,
        });
      }
      apiStore.addEvent({
        scanId: id,
        stage: "COMPLETED",
        message: `Live scan completed: ${findings.length} findings, score ${score.overall}`,
      });
      enqueue(
        sseLine({
          type: "result",
          scanId: id,
          status: "COMPLETED",
          score: score.overall,
          coverage: score.coverage,
          findingsCount: findings.length,
        }),
      );
      enqueue(DONE);
      controller.close();
    },
    cancel() {
      // Client disconnected mid-scan: the runLiveScan abort listener kills
      // the background VM command; the store update happens in start().
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
