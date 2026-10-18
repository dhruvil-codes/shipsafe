import { runtimeStore } from "../../../_lib/runtime-store";
import { TERMINAL_STATUSES } from "../../../_lib/store";
import { json, serviceUnavailable, workspaceId } from "../../../_lib/workspace";
import { executionReadiness, executionUnavailable } from "../../../_lib/readiness";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

/** Replay persisted events, then follow the worker without tying execution to the browser. */
export async function GET(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  let scan;
  try { scan = await runtimeStore.ownedScan(workspaceId(request), id); }
  catch { return serviceUnavailable(); }
  if (!scan) return json({ error: "Scan not found" }, 404);
  if (!TERMINAL_STATUSES.has(scan.status)) {
    let readiness;
    try { readiness = await executionReadiness(); }
    catch { return serviceUnavailable(); }
    if (!readiness.executionConfigured) {
      if (scan.status !== "QUEUED") return json({ error: "This scan already has an execution in progress", code: "SCAN_ALREADY_RUNNING" }, 409);
      try { return json(await executionUnavailable(), 503); }
      catch { return serviceUnavailable(); }
    }
  }
  const encoder = new TextEncoder();
  let stop = () => {};
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      let stopped = false;
      let ticking = false;
      let timer: ReturnType<typeof setInterval> | undefined;
      let cursor: string | null | undefined = request.headers.get("last-event-id");
      let seen = 0;
      const send = (text: string) => controller.enqueue(encoder.encode(text));
      stop = () => {
        if (stopped) return;
        stopped = true;
        if (timer) clearInterval(timer);
        request.signal.removeEventListener("abort", stop);
        try { controller.close(); } catch { /* Already cancelled by the consumer. */ }
      };
      const tick = async () => {
        if (stopped || ticking) return;
        ticking = true;
        try {
          const events = await runtimeStore.listEvents(id);
          if (stopped) return;
          if (cursor) {
            const cursorIndex = events.findIndex(event => event.id === cursor);
            seen = cursorIndex >= 0 ? cursorIndex + 1 : 0;
            cursor = undefined;
          }
          for (const event of events.slice(seen)) send(`id: ${event.id}\ndata: ${JSON.stringify({ type: "event", ...event })}\n\n`);
          seen = events.length;
          const current = await runtimeStore.getScan(id);
          if (stopped) return;
          if (current && TERMINAL_STATUSES.has(current.status)) {
            const findings = await runtimeStore.listFindings(id);
            if (stopped) return;
            send(`data: ${JSON.stringify({ type: "result", scanId: id, status: current.status, score: current.score ?? null, coverage: current.coverage ?? null, findingsCount: findings.length })}\n\nevent: done\ndata: {}\n\n`);
            stop();
          } else send(": heartbeat\n\n");
        } catch { stop(); }
        finally { ticking = false; }
      };
      send(": connected\n\n");
      request.signal.addEventListener("abort", stop, { once: true });
      if (request.signal.aborted) { stop(); return; }
      void tick();
      if (!stopped) timer = setInterval(tick, 750);
    },
    cancel() { stop(); },
  });
  return new Response(body, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store, no-transform", "Vary": "Cookie", "X-Accel-Buffering": "no" },
  });
}
