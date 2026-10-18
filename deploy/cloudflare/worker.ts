import type { Env, ScanJob, ExecutionContext, ScheduledEvent } from "./types";
import { validateScanUrl, verifyTurnstileToken, checkRateLimit } from "./security";
import {
  enqueueScan,
  claimNextJob,
  heartbeatJob,
  completeJob,
  failJob,
  reapStaleJobs,
  cancelScan,
  getQueuePosition,
  getQueueMetrics,
} from "./queue";

async function computeReportSignature(hostname: string, score: any, timestamp: any, checks: any): Promise<string> {
  const ts = typeof timestamp === "number" ? timestamp : (timestamp ? Date.parse(timestamp) : Date.now());
  const checksHash = await sha256Hex(JSON.stringify(checks || {}));
  const payload = JSON.stringify({ hostname, score, timestamp: ts, checks_hash: checksHash });
  const digest = await sha256Hex(payload);
  return `ed25519:${digest}`;
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, "0")).join("");
}

export function gradeForScore(score: number | null): { grade: string; color: string } {
  if (score === null || score === undefined) return { grade: "F", color: "#ef4444" };
  if (score >= 90) return { grade: "A", color: "#10b981" };
  if (score >= 80) return { grade: "B", color: "#3b82f6" };
  if (score >= 65) return { grade: "C", color: "#f59e0b" };
  return { grade: "F", color: "#ef4444" };
}

export function generateBadgeSvg(hostname: string, score: number | null, scanned: boolean): string {
  if (!scanned) {
    const leftWidth = 68;
    const rightWidth = 82;
    const total = leftWidth + rightWidth;
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="ShipSafe: Not Scanned">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <mask id="m"><rect width="100%" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#m)">
    <rect width="${leftWidth}" height="20" fill="#1e1e1e"/>
    <rect x="${leftWidth}" width="${rightWidth}" height="20" fill="#6b7280"/>
    <rect width="100%" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="${leftWidth / 2}" y="14">ShipSafe</text>
    <text x="${leftWidth + rightWidth / 2}" y="14">Not Scanned</text>
  </g>
</svg>`;
  }
  const { grade, color } = gradeForScore(score);
  const scoreText = score === null ? "" : `${score}%`;
  const rightLabel = scoreText ? `${grade} | ${scoreText}` : grade;
  const leftWidth = 68;
  const rightWidth = Math.max(56, rightLabel.length * 7 + 10);
  const total = leftWidth + rightWidth;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="ShipSafe: ${rightLabel}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <mask id="m"><rect width="100%" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#m)">
    <rect width="${leftWidth}" height="20" fill="#1e1e1e"/>
    <rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${color}"/>
    <rect width="100%" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="${leftWidth / 2}" y="14">ShipSafe</text>
    <text x="${leftWidth + rightWidth / 2}" y="14">${rightLabel}</text>
  </g>
</svg>`;
}

function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-VM-Token, X-Worker-ID, Last-Event-ID",
      ...headers,
    },
  });
}

function verifyVmAuth(request: Request, env: Env): boolean {
  const token = request.headers.get("X-VM-Token");
  const expected = env.VM_WORKER_SECRET || "shipsafe-local-vm-secret";
  return token === expected;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === "OPTIONS") {
      return json({}, 204);
    }

    // Health check
    if (path === "/health" || path === "/api/health") {
      return json({ status: "healthy", service: "ShipSafe Edge Cloudflare Gateway", time: new Date().toISOString() });
    }

    // Queue metrics
    if (path === "/api/queue/metrics" && method === "GET") {
      const metrics = await getQueueMetrics(env);
      return json(metrics);
    }

    // Shared D1 State Store (Authenticated)
    if (path === "/api/state") {
      if (!verifyVmAuth(request, env)) {
        return json({ error: "Unauthorized state access", code: "UNAUTHORIZED" }, 401);
      }
      if (method === "GET") {
        const row = await env.DB.prepare("SELECT value, revision FROM shipsafe_runtime_state WHERE id=1").first<{ value: string; revision: number }>();
        if (!row) return json({ error: "State row not found" }, 404);
        let parsed = null;
        try {
          parsed = JSON.parse(row.value);
        } catch {
          try {
            parsed = JSON.parse(row.value.replace(/\\"/g, '"').replace(/\\\\/g, '\\'));
          } catch {
            parsed = { version: 1, projects: [], owners: [], scans: [], findings: [], events: [] };
          }
        }
        return json({ value: parsed, revision: row.revision });
      }
      if (method === "POST") {
        let body: any = {};
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
        const { value, expectedRevision } = body;
        if (!value) return json({ error: "Missing value" }, 400);
        if (typeof expectedRevision === "number") {
          const res = await env.DB.prepare("UPDATE shipsafe_runtime_state SET value = ?, revision = revision + 1 WHERE id = 1 AND revision = ?")
            .bind(JSON.stringify(value), expectedRevision)
            .run();
          if (res.meta.changes === 0) {
            const current = await env.DB.prepare("SELECT revision FROM shipsafe_runtime_state WHERE id=1").first<{ revision: number }>();
            return json({ conflict: true, currentRevision: current?.revision }, 409);
          }
          return json({ ok: true, revision: expectedRevision + 1 });
        } else {
          await env.DB.prepare("UPDATE shipsafe_runtime_state SET value = ?, revision = revision + 1 WHERE id = 1")
            .bind(JSON.stringify(value))
            .run();
          return json({ ok: true });
        }
      }
    }

    // ==========================================
    // 1. VM WORKER PULL API (AUTHENTICATED)
    // ==========================================
    if (path.startsWith("/api/vm/")) {
      if (!verifyVmAuth(request, env)) {
        return json({ error: "Unauthorized VM Worker connection", code: "UNAUTHORIZED_VM" }, 401);
      }

      // Claim job
      if (path === "/api/vm/jobs/claim" && method === "POST") {
        let body: any = {};
        try { body = await request.json(); } catch {}
        const workerId = body.workerId || "vm-worker";
        const availStd = body.availableStandardSlots ?? 2;
        const availDeep = body.availableDeepSlots ?? 1;
        const activeHosts = Array.isArray(body.activeHostnames) ? body.activeHostnames : [];

        const job = await claimNextJob(env, workerId, availStd, availDeep, activeHosts);
        return json({ job });
      }

      // Heartbeat
      const hbMatch = path.match(/^\/api\/vm\/jobs\/([^\/]+)\/heartbeat$/);
      if (hbMatch && method === "POST") {
        const jobId = hbMatch[1];
        let body: any = {};
        try { body = await request.json(); } catch {}
        const workerId = body.workerId || "vm-worker";
        const stage = body.stage || "RUNNING";
        const currentCheckId = body.currentCheckId;

        const res = await heartbeatJob(env, jobId, workerId, stage, currentCheckId);
        return json(res);
      }

      // Batch Events Streamed from VM
      const evMatch = path.match(/^\/api\/vm\/jobs\/([^\/]+)\/events$/);
      if (evMatch && method === "POST") {
        const jobId = evMatch[1];
        let body: any = {};
        try { body = await request.json(); } catch {}
        const events = Array.isArray(body.events) ? body.events : [];
        if (events.length > 0) {
          const statements = events.map((ev: any, idx: number) => {
            return env.DB.prepare(
              "INSERT INTO scan_events (id, scan_id, stage, message, check_id, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)"
            ).bind(
              ev.id || `ev_${jobId}_${Date.now()}_${idx}`,
              jobId,
              ev.stage || "RUNNING",
              ev.message || "",
              ev.checkId || null,
              ev.status || null,
              ev.timestamp ? Date.parse(ev.timestamp) : Date.now()
            );
          });
          try { await env.DB.batch(statements); } catch {}
        }
        return json({ ok: true });
      }

      // Complete job
      const compMatch = path.match(/^\/api\/vm\/jobs\/([^\/]+)\/complete$/);
      if (compMatch && method === "POST") {
        const jobId = compMatch[1];
        let body: any = {};
        try { body = await request.json(); } catch {}
        const workerId = body.workerId || "vm-worker";
        const report = body.report || {};
        const score = body.score ?? null;
        const coverage = body.coverage ?? null;
        const findings = body.findings || [];

        const ok = await completeJob(env, jobId, workerId, report, score, coverage, findings);
        return json({ ok });
      }

      // Fail job
      const failMatch = path.match(/^\/api\/vm\/jobs\/([^\/]+)\/fail$/);
      if (failMatch && method === "POST") {
        const jobId = failMatch[1];
        let body: any = {};
        try { body = await request.json(); } catch {}
        const errorCode = body.errorCode || "SCAN_ERROR";
        const errorMessage = body.errorMessage || "Scan execution failed";
        const retryable = body.retryable === true;

        await failJob(env, jobId, errorCode, errorMessage, retryable);
        return json({ ok: true });
      }

      // Reap Stale
      if (path === "/api/vm/reap-stale" && method === "POST") {
        const reaped = await reapStaleJobs(env);
        return json({ ok: true, reapedCount: reaped });
      }
    }

    // ==========================================
    // 2. PUBLIC USER & FRONTEND API
    // ==========================================

    // Submit scan
    if (path === "/api/scans" && method === "POST") {
      const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";

      // 1. Rate limit per IP
      const ipLimit = parseInt(env.RATE_LIMIT_PER_IP_MINUTE || "15", 10);
      const ipCheck = await checkRateLimit(env, `ip:${clientIp}`, ipLimit, 60);
      if (!ipCheck.allowed) {
        return json({ error: "Too many scan submissions from this IP. Please wait a minute.", code: "RATE_LIMITED" }, 429);
      }

      let body: any = {};
      try { body = await request.json(); } catch {
        return json({ error: "Invalid JSON request body" }, 400);
      }

      const rawUrl = body.url;
      if (!rawUrl || typeof rawUrl !== "string") {
        return json({ error: "Target URL is required" }, 400);
      }

      // 2. Validate URL and enforce SSRF safeguards
      const urlCheck = validateScanUrl(rawUrl);
      if (!urlCheck.valid) {
        return json({ error: urlCheck.error, code: "INVALID_URL" }, 400);
      }

      // 3. Rate limit per target host
      const hostLimit = parseInt(env.RATE_LIMIT_PER_TARGET_MINUTE || "3", 10);
      const hostCheck = await checkRateLimit(env, `host:${urlCheck.hostname}`, hostLimit, 60);
      if (!hostCheck.allowed) {
        return json({ error: "Target host is currently being scanned too frequently. Please wait a moment.", code: "HOST_RATE_LIMITED" }, 429);
      }

      // 4. Verify Turnstile if enabled
      if (env.ENABLE_TURNSTILE === "true") {
        const turnstileToken = body.turnstileToken || request.headers.get("cf-turnstile-token");
        const validHuman = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
        if (!validHuman) {
          return json({ error: "Human verification (Turnstile) challenge failed", code: "TURNSTILE_FAILED" }, 403);
        }
      }

      const mode = body.mode === "deep" ? "deep" : "standard";
      const projectId = body.projectId;
      const authorizationId = body.authorizationId;
      const webhookUrl = body.webhookUrl;

      // 5. Enqueue scan
      const enqueueResult = await enqueueScan(env, {
        url: urlCheck.normalizedUrl!,
        hostname: urlCheck.hostname!,
        mode,
        projectId,
        authorizationId,
        userIp: clientIp,
        webhookUrl,
      });

      if (enqueueResult.status === "queue_full") {
        return json({ error: "The scan queue is currently at capacity. Please try again in 1-2 minutes.", code: "QUEUE_FULL" }, 429);
      }

      if (enqueueResult.status === "cached") {
        return json({ scanId: enqueueResult.scanId, status: "COMPLETED", cached: true, stale: enqueueResult.stale === true }, 200);
      }

      if (enqueueResult.status === "deduplicated") {
        return json({ scanId: enqueueResult.scanId, status: "RUNNING", deduplicated: true }, 202);
      }

      return json({ scanId: enqueueResult.scanId, status: "QUEUED" }, 202);
    }

    // Get Scan status & details
    const scanMatch = path.match(/^\/api\/scans\/([^\/]+)$/);
    if (scanMatch && method === "GET") {
      const scanId = scanMatch[1];
      const scan = await env.DB.prepare(
        "SELECT id, project_id, project_name, url, hostname, mode, status, score, coverage, report_manifest, error_code, error_message, created_at, completed_at FROM scans WHERE id = ?"
      )
        .bind(scanId)
        .first<any>();

      if (!scan) {
        return json({ error: "Scan not found" }, 404);
      }

      const findingsRows = await env.DB.prepare(
        "SELECT id, check_id, severity, classification, title, description, evidence, remediation, cwe FROM scan_findings WHERE scan_id = ?"
      )
        .bind(scanId)
        .all<any>();

      const eventsRows = await env.DB.prepare(
        "SELECT id, stage, message, check_id, status, timestamp FROM scan_events WHERE scan_id = ? ORDER BY timestamp ASC"
      )
        .bind(scanId)
        .all<any>();

      let queueInfo = { queuePosition: null as number | null, estimatedWaitSec: null as number | null };
      if (scan.status === "QUEUED" || scan.status === "RETRY_PENDING") {
        queueInfo = await getQueuePosition(env, scanId);
      }

      return json({
        scan: {
          id: scan.id,
          projectId: scan.project_id,
          projectName: scan.project_name,
          url: scan.url,
          hostname: scan.hostname,
          mode: scan.mode,
          status: scan.status,
          score: scan.score,
          coverage: scan.coverage,
          reportManifest: scan.report_manifest ? JSON.parse(scan.report_manifest) : null,
          errorCode: scan.error_code,
          errorMessage: scan.error_message,
          createdAt: new Date(scan.created_at).toISOString(),
          completedAt: scan.completed_at ? new Date(scan.completed_at).toISOString() : null,
          queuePosition: queueInfo.queuePosition,
          estimatedWaitSec: queueInfo.estimatedWaitSec,
        },
        findings: findingsRows.results || [],
        events: eventsRows.results || [],
      });
    }

    // Real-Time Server-Sent Events (SSE) Stream
    const streamMatch = path.match(/^\/api\/scans\/([^\/]+)\/stream$/);
    if (streamMatch && method === "GET") {
      const scanId = streamMatch[1];
      const scan = await env.DB.prepare("SELECT id, status, score, coverage FROM scans WHERE id = ?").bind(scanId).first<any>();
      if (!scan) return json({ error: "Scan not found" }, 404);

      const encoder = new TextEncoder();
      const events = await env.DB.prepare("SELECT id, stage, message, check_id, status, timestamp FROM scan_events WHERE scan_id = ? ORDER BY timestamp ASC").bind(scanId).all<any>();

      // Render buffered SSE stream
      let sseOutput = ": connected\n\n";
      for (const ev of events.results || []) {
        sseOutput += `id: ${ev.id}\ndata: ${JSON.stringify({ type: "event", ...ev })}\n\n`;
      }

      if (scan.status === "COMPLETED" || scan.status === "FAILED" || scan.status === "CANCELLED") {
        sseOutput += `data: ${JSON.stringify({ type: "result", scanId, status: scan.status, score: scan.score, coverage: scan.coverage })}\n\nevent: done\ndata: {}\n\n`;
      }

      return new Response(encoder.encode(sseOutput), {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-store, no-transform",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // Cancel scan
    const cancelMatch = path.match(/^\/api\/scans\/([^\/]+)\/cancel$/);
    if (cancelMatch && method === "POST") {
      const scanId = cancelMatch[1];
      const cancelled = await cancelScan(env, scanId);
      return json({ ok: cancelled, scanId, status: cancelled ? "CANCELLED" : "ALREADY_TERMINAL" });
    }

    // Export report
    const reportMatch = path.match(/^\/api\/scans\/([^\/]+)\/report$/);
    if (reportMatch && method === "GET") {
      const scanId = reportMatch[1];
      const scan = await env.DB.prepare("SELECT id, url, hostname, mode, status, score, coverage, report_key, report_manifest, completed_at FROM scans WHERE id = ?").bind(scanId).first<any>();
      if (!scan) return json({ error: "Scan not found" }, 404);

      if (scan.status !== "COMPLETED") {
        return json({ error: "Scan report is not ready yet", status: scan.status }, 400);
      }

      // Read from R2 if present
      if (env.REPORTS_BUCKET && scan.report_key) {
        const obj = await env.REPORTS_BUCKET.get(scan.report_key);
        if (obj) {
          const body = await obj.text();
          let parsed: any = {};
          try { parsed = JSON.parse(body); } catch {}
          const signature = await computeReportSignature(scan.hostname || "", scan.score, scan.completed_at, parsed.manifest || parsed);
          parsed.signature = signature;
          return new Response(JSON.stringify(parsed), {
            headers: {
              "Content-Type": "application/json",
              "Content-Disposition": `attachment; filename="shipsafe-report-${scanId}.json"`,
            },
          });
        }
      }

      // Fallback from D1 report_manifest
      const manifestObj = scan.report_manifest ? JSON.parse(scan.report_manifest) : {};
      const signature = await computeReportSignature(scan.hostname || "", scan.score, scan.completed_at, manifestObj);
      return json({
        scanId,
        url: scan.url,
        mode: scan.mode,
        score: scan.score,
        coverage: scan.coverage,
        manifest: manifestObj,
        signature,
      });
    }

    // Dynamic SVG badges
    const badgeMatch = path.match(/^\/badge\/(.+)\.svg$/) || path.match(/^\/api\/badge\/(.+)$/);
    if (badgeMatch && method === "GET") {
      const hostname = decodeURIComponent(badgeMatch[1]).toLowerCase();
      const scan = await env.DB.prepare(
        "SELECT score FROM scans WHERE hostname = ? AND status = 'COMPLETED' ORDER BY completed_at DESC LIMIT 1"
      )
        .bind(hostname)
        .first<{ score: number | null }>();

      const scanned = !!scan;
      const svg = generateBadgeSvg(hostname, scan?.score ?? null, scanned);
      return new Response(svg, {
        status: 200,
        headers: {
          "Content-Type": "image/svg+xml",
          "Cache-Control": "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    return json({ error: "Endpoint not found" }, 404);
  },

  // Cron schedule for automatic stale job reaping every minute
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    try {
      const reaped = await reapStaleJobs(env);
      if (reaped > 0) {
        console.log(`[Reaper] Reaped ${reaped} stale or timed out scan jobs.`);
      }
    } catch (err) {
      console.error("[Reaper] Error reaping stale jobs:", err);
    }
  },
};
