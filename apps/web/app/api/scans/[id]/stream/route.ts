import { apiStore, TERMINAL_STATUSES } from "../../../_lib/store";
import { json, workspaceId } from "../../../_lib/workspace";
import { executionReadiness, executionUnavailable } from "../../../_lib/readiness";
import { kickQueue } from "../../../_lib/baseline-runtime";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Replay persisted events, then follow the worker without tying execution to the browser. */
export async function GET(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  const scan = apiStore.ownedScan(workspaceId(request), id);
  if (!scan) return json({ error: "Scan not found" }, 404);
  if (!TERMINAL_STATUSES.has(scan.status) && !executionReadiness().executionConfigured) {
    if (scan.status !== "QUEUED") return json({ error: "This scan already has an execution in progress", code: "SCAN_ALREADY_RUNNING" }, 409);
    return json(executionUnavailable(), 503);
  }
  if (executionReadiness().executionConfigured) kickQueue();
  const encoder = new TextEncoder();
  let stop = () => {};
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      let stopped = false;
      let timer: ReturnType<typeof setInterval> | undefined;
      let cursor = request.headers.get("last-event-id");
      const known = apiStore.listEvents(id);
      let seen = cursor ? known.findIndex(event => event.id === cursor) + 1 : 0;
      const send = (text: string) => controller.enqueue(encoder.encode(text));
      stop = () => {
        if (stopped) return;
        stopped = true;
        if (timer) clearInterval(timer);
        request.signal.removeEventListener("abort", stop);
        try { controller.close(); } catch { /* Already cancelled by the consumer. */ }
      };
      const tick = () => {
        if (stopped) return;
        try {
          const events = apiStore.listEvents(id);
          for (const event of events.slice(seen)) send(`id: ${event.id}\ndata: ${JSON.stringify({ type: "event", ...event })}\n\n`);
          seen = events.length;
          const current = apiStore.getScan(id);
          if (current && TERMINAL_STATUSES.has(current.status)) {
            send(`data: ${JSON.stringify({ type: "result", scanId: id, status: current.status, score: current.score ?? null, coverage: current.coverage ?? null, findingsCount: apiStore.listFindings(id).length })}\n\nevent: done\ndata: {}\n\n`);
            stop();
          } else send(": heartbeat\n\n");
        } catch { stop(); }
      };
      send(": connected\n\n");
      request.signal.addEventListener("abort", stop, { once: true });
      if (request.signal.aborted) { stop(); return; }
      tick();
      if (!stopped) timer = setInterval(tick, 750);
    },
    cancel() { stop(); },
  });
  return new Response(body, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store, no-transform", "Vary": "Cookie", "X-Accel-Buffering": "no" },
  });
}
