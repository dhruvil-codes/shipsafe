import { apiStore } from "../../../_lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ id: string }>;
};

function sseLine(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

const SIMULATED_STAGES = [
  { stage: "PROVISIONING", message: "Reserving slot (quota 5 VMs)" },
  { stage: "PROVISIONING", message: "Creating sandbox from baseline snapshot" },
  { stage: "RUNNING", message: "tls-check: probing certificate chain" },
  { stage: "RUNNING", message: "headers-check: fetching security headers" },
  { stage: "RUNNING", message: "ports-check: probing common ports" },
  { stage: "PROCESSING", message: "Normalizing findings and computing score" },
];

/**
 * GET /api/scans/:id/stream — Server-Sent Events stream of live scan output.
 * Replays stored ScanEvents, then emits staged log lines, then the final
 * result (or current status when still running). Ends with `event: done`
 * so EventSource clients on the frontend can terminate cleanly.
 */
export async function GET(
  _request: Request,
  context: RouteContext,
): Promise<Response> {
  const { id } = await context.params;
  const scan = apiStore.getScan(id);
  if (!scan) {
    return Response.json({ error: "Scan not found" }, { status: 404 });
  }

  const storedEvents = apiStore.listEvents(id);
  const findings = apiStore.listFindings(id);
  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(": connected\n\n"));
      for (const event of storedEvents) {
        controller.enqueue(
          encoder.encode(
            sseLine({
              type: "event",
              scanId: event.scanId,
              stage: event.stage,
              message: event.message,
              timestamp: event.timestamp,
            }),
          ),
        );
      }
      const alreadyTerminal = ["COMPLETED", "FAILED", "CANCELLED"].includes(
        scan.status,
      );
      if (!alreadyTerminal) {
        for (const line of SIMULATED_STAGES) {
          controller.enqueue(
            encoder.encode(
              sseLine({
                type: "log",
                scanId: id,
                stage: line.stage,
                message: line.message,
                timestamp: new Date().toISOString(),
              }),
            ),
          );
        }
      }
      controller.enqueue(
        encoder.encode(
          sseLine({
            type: "result",
            scanId: id,
            status: scan.status,
            score: scan.score ?? null,
            coverage: scan.coverage ?? null,
            findingsCount: findings.length,
          }),
        ),
      );
      controller.enqueue(encoder.encode("event: done\ndata: {}\n\n"));
      controller.close();
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
