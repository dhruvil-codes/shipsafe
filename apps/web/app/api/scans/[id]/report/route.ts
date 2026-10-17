import { apiStore, TERMINAL_STATUSES } from "../../../_lib/store";
import { json, workspaceId } from "../../../_lib/workspace";
import { buildReportDocument, renderReportHtml } from "../../../../../lib/report";
import type { Assessment } from "../../../../../lib/assessment";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Private downloads derive only from persisted evidence; exporting never starts a scan. */
export async function GET(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  const scan = apiStore.ownedScan(workspaceId(request), id);
  if (!scan) return json({ error: "Scan not found" }, 404);
  if (!TERMINAL_STATUSES.has(scan.status)) return json({ error: "The scan is still running. Its report will be available after it finishes." }, 409);
  const format = new URL(request.url).searchParams.get("format") ?? "html";
  if (format !== "html" && format !== "json") return json({ error: "Supported report formats are html and json." }, 400);
  const assessment: Assessment = {
    scan: { ...scan, projectName: scan.projectName ?? "", score: scan.score ?? null, coverage: scan.coverage ?? null },
    findings: apiStore.listFindings(id),
    events: apiStore.listEvents(id),
  };
  const filename = `shipsafe-${scan.id.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 80)}.${format}`;
  return new Response(format === "html" ? renderReportHtml(assessment) : JSON.stringify(buildReportDocument(assessment), null, 2), {
    headers: {
      "Content-Type": format === "html" ? "text/html; charset=utf-8" : "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
      "Vary": "Cookie",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox",
    },
  });
}
