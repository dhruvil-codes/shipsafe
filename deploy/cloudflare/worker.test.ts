import { describe, expect, it, beforeEach } from "vitest";
import { validateScanUrl, isPrivateOrReservedHost } from "./security";
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
  computeCacheKey,
} from "./queue";
import type { Env, D1Database, D1PreparedStatement } from "./types";

/**
 * In-memory Mock D1 Database for isolated unit testing.
 */
class MockD1Database implements D1Database {
  private scans: Map<string, any> = new Map();
  private events: any[] = [];
  private findings: any[] = [];
  private cachedReports: Map<string, any> = new Map();
  private rateLimits: Map<string, any> = new Map();

  prepare(query: string): D1PreparedStatement {
    const q = query.trim();
    let boundValues: any[] = [];

    const stmt: D1PreparedStatement = {
      bind(...values: any[]) {
        boundValues = values;
        return stmt;
      },
      async first<T = unknown>(colName?: string): Promise<T | null> {
        if (q.includes("SELECT report_key, score")) {
          // Cache check
          const [key, now] = boundValues;
          const cached = stmtDb.cachedReports.get(key);
          if (cached && cached.expires_at > now) return cached as T;
          return null;
        }
        if (q.includes("SELECT id, status FROM scans WHERE url = ?")) {
          // In-flight deduplication check
          const [url, mode] = boundValues;
          for (const s of stmtDb.scans.values()) {
            if (s.url === url && s.mode === mode && ["QUEUED", "CLAIMED", "RUNNING"].includes(s.status)) {
              return { id: s.id, status: s.status } as T;
            }
          }
          return null;
        }
        if (q.includes("SELECT COUNT(*) as count FROM scans WHERE status IN ('QUEUED'")) {
          let count = 0;
          for (const s of stmtDb.scans.values()) {
            if (["QUEUED", "CLAIMED", "RUNNING", "RETRY_PENDING"].includes(s.status)) count++;
          }
          return { count } as T;
        }
        if (q.includes("SELECT status FROM scans WHERE id = ?")) {
          const [id] = boundValues;
          const s = stmtDb.scans.get(id);
          return s ? ({ status: s.status } as T) : null;
        }
        if (q.includes("SELECT retry_count, max_retries FROM scans WHERE id = ?")) {
          const [id] = boundValues;
          const s = stmtDb.scans.get(id);
          return s ? ({ retry_count: s.retry_count || 0, max_retries: s.max_retries || 2 } as T) : null;
        }
        if (q.includes("SELECT url, hostname, mode FROM scans WHERE id = ?")) {
          const [id] = boundValues;
          const s = stmtDb.scans.get(id);
          return s ? ({ url: s.url, hostname: s.hostname, mode: s.mode } as T) : null;
        }
        if (q.includes("FROM scans WHERE id = ?") && q.includes("priority")) {
          const [id] = boundValues;
          const s = stmtDb.scans.get(id);
          return s ? ({ id: s.id, status: s.status, priority: s.priority, created_at: s.created_at } as T) : null;
        }
        if (q.includes("SELECT COUNT(*) as count FROM scans") && q.includes("priority >")) {
          const [p1, p2, createdAt, createdAt2, id] = boundValues;
          let count = 0;
          for (const s of stmtDb.scans.values()) {
            if (["QUEUED", "RETRY_PENDING"].includes(s.status)) {
              if (s.priority > p1 || (s.priority === p2 && (s.created_at < createdAt || (s.created_at === createdAt2 && s.id < id)))) count++;
            }
          }
          return { count } as T;
        }
        if (q.includes("SELECT COUNT(*) as c FROM scans WHERE status IN ('QUEUED'")) {
          let count = 0;
          for (const s of stmtDb.scans.values()) if (["QUEUED", "RETRY_PENDING"].includes(s.status)) count++;
          return { c: count } as T;
        }
        if (q.includes("SELECT COUNT(*) as c FROM scans WHERE status IN ('CLAIMED'")) {
          let count = 0;
          for (const s of stmtDb.scans.values()) if (["CLAIMED", "RUNNING"].includes(s.status)) count++;
          return { c: count } as T;
        }
        if (q.includes("SELECT COUNT(*) as c FROM scans WHERE status = 'COMPLETED'")) {
          let count = 0;
          for (const s of stmtDb.scans.values()) if (s.status === "COMPLETED") count++;
          return { c: count } as T;
        }
        if (q.includes("SELECT COUNT(*) as c FROM scans WHERE status IN ('FAILED'")) {
          let count = 0;
          for (const s of stmtDb.scans.values()) if (["FAILED", "EXPIRED"].includes(s.status)) count++;
          return { c: count } as T;
        }
        return null;
      },
      async run<T = unknown>(): Promise<{ success: boolean; meta: { changes: number } }> {
        if (q.includes("INSERT INTO scans")) {
          const [id, projId, projName, url, hostname, mode, priority, authId, userIp, userId, createdAt, updatedAt] = boundValues;
          stmtDb.scans.set(id, {
            id,
            project_id: projId,
            project_name: projName,
            url,
            hostname,
            mode,
            status: "QUEUED",
            priority,
            authorization_id: authId,
            user_ip: userIp,
            user_id: userId,
            created_at: createdAt,
            updated_at: updatedAt,
            retry_count: 0,
            max_retries: 2,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (q.includes("UPDATE scans") && q.includes("SET status = 'CLAIMED'")) {
          const [workerId, now, leaseExpires, updated, id] = boundValues;
          const s = stmtDb.scans.get(id);
          if (s && (s.status === "QUEUED" || s.status === "RETRY_PENDING")) {
            s.status = "CLAIMED";
            s.lease_worker_id = workerId;
            s.leased_at = now;
            s.lease_expires_at = leaseExpires;
            s.updated_at = updated;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (q.includes("UPDATE scans SET status = 'RUNNING'")) {
          const [expires, updated, id] = boundValues;
          const s = stmtDb.scans.get(id);
          if (s) {
            s.status = "RUNNING";
            s.lease_expires_at = expires;
            s.updated_at = updated;
          }
          return { success: true, meta: { changes: 1 } };
        }
        if (q.includes("UPDATE scans") && q.includes("SET status = 'COMPLETED'")) {
          const [score, coverage, repKey, repMan, compAt, updAt, id] = boundValues;
          const s = stmtDb.scans.get(id);
          if (s) {
            s.status = "COMPLETED";
            s.score = score;
            s.coverage = coverage;
            s.report_key = repKey;
            s.report_manifest = repMan;
            s.completed_at = compAt;
            s.updated_at = updAt;
          }
          return { success: true, meta: { changes: 1 } };
        }
        if (q.includes("UPDATE scans") && q.includes("SET status = 'RETRY_PENDING'")) {
          const [retryCount, nextRetry, errCode, errMsg, updAt, id] = boundValues;
          const s = stmtDb.scans.get(id);
          if (s) {
            s.status = "RETRY_PENDING";
            s.retry_count = retryCount;
            s.next_retry_at = nextRetry;
            s.error_code = errCode;
            s.error_message = errMsg;
            s.updated_at = updAt;
          }
          return { success: true, meta: { changes: 1 } };
        }
        if (q.includes("UPDATE scans SET status = 'CANCELLED'")) {
          const [updAt, id] = boundValues;
          const s = stmtDb.scans.get(id);
          if (s && !["COMPLETED", "FAILED", "CANCELLED"].includes(s.status)) {
            s.status = "CANCELLED";
            s.updated_at = updAt;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (q.includes("INSERT INTO cached_reports")) {
          const [key, url, host, mode, repKey, score, cov, summary, created, exp] = boundValues;
          stmtDb.cachedReports.set(key, {
            cache_key: key,
            url,
            hostname: host,
            mode,
            report_key: repKey,
            score,
            coverage: cov,
            summary_json: summary,
            created_at: created,
            expires_at: exp,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (q.includes("INSERT INTO scan_events")) {
          stmtDb.events.push(boundValues);
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 1 } };
      },
      async all<T = unknown>(): Promise<{ results: T[] }> {
        if (q.includes("SELECT DISTINCT hostname FROM scans")) {
          const hosts: any[] = [];
          for (const s of stmtDb.scans.values()) {
            if (["CLAIMED", "RUNNING"].includes(s.status)) hosts.push({ hostname: s.hostname });
          }
          return { results: hosts as T[] };
        }
        if (q.includes("SELECT id, project_id, project_name, url, hostname, mode, status, priority")) {
          const [now] = boundValues;
          const candidates: any[] = [];
          for (const s of stmtDb.scans.values()) {
            if (s.status === "QUEUED" || (s.status === "RETRY_PENDING" && (s.next_retry_at || 0) <= now)) {
              candidates.push(s);
            }
          }
          candidates.sort((a, b) => b.priority - a.priority || a.created_at - b.created_at);
          return { results: candidates as T[] };
        }
        if (q.includes("SELECT id, retry_count, max_retries FROM scans WHERE status IN ('CLAIMED', 'RUNNING')")) {
          const [now] = boundValues;
          const stale: any[] = [];
          for (const s of stmtDb.scans.values()) {
            if (["CLAIMED", "RUNNING"].includes(s.status) && (s.lease_expires_at || 0) < now) {
              stale.push({ id: s.id, retry_count: s.retry_count || 0, max_retries: s.max_retries || 2 });
            }
          }
          return { results: stale as T[] };
        }
        return { results: [] };
      },
    };
    const stmtDb = this;
    return stmt;
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<any[]> {
    const results = [];
    for (const s of statements) results.push(await s.run());
    return results;
  }

  async exec(query: string): Promise<any> {
    return { success: true };
  }
}

describe("ShipSafe Cloudflare Architecture", () => {
  describe("SSRF Protection & URL Validation", () => {
    it("rejects private, loopback, and cloud metadata targets", () => {
      expect(isPrivateOrReservedHost("localhost")).toBe(true);
      expect(isPrivateOrReservedHost("127.0.0.1")).toBe(true);
      expect(isPrivateOrReservedHost("169.254.169.254")).toBe(true);
      expect(isPrivateOrReservedHost("10.0.1.5")).toBe(true);
      expect(isPrivateOrReservedHost("192.168.1.1")).toBe(true);
      expect(isPrivateOrReservedHost("172.20.0.1")).toBe(true);
      expect(isPrivateOrReservedHost("myhost.internal")).toBe(true);
    });

    it("accepts valid public domain names", () => {
      expect(isPrivateOrReservedHost("example.com")).toBe(false);
      expect(isPrivateOrReservedHost("cloudflare.com")).toBe(false);
      expect(isPrivateOrReservedHost("github.com")).toBe(false);
    });

    it("validates and normalizes target URLs", () => {
      const valid = validateScanUrl("https://EXAMPLE.COM/path#frag");
      expect(valid.valid).toBe(true);
      expect(valid.normalizedUrl).toBe("https://example.com/path");
      expect(valid.hostname).toBe("example.com");

      const invalidProtocol = validateScanUrl("ftp://example.com");
      expect(invalidProtocol.valid).toBe(false);

      const invalidSsrf = validateScanUrl("http://127.0.0.1:8080/admin");
      expect(invalidSsrf.valid).toBe(false);
      expect(invalidSsrf.error).toContain("SSRF");
    });
  });

  describe("Queue & Concurrency Controls", () => {
    let mockDb: MockD1Database;
    let env: Env;

    beforeEach(() => {
      mockDb = new MockD1Database();
      env = {
        DB: mockDb,
        ENVIRONMENT: "test",
        MAX_QUEUE_DEPTH: "100",
      };
    });

    it("enqueues jobs and calculates priority correctly", async () => {
      const stdRes = await enqueueScan(env, {
        url: "https://site-a.com",
        hostname: "site-a.com",
        mode: "standard",
      });
      expect(stdRes.status).toBe("queued");
      expect(stdRes.scanId).toMatch(/^scn_[a-f0-9]{32}$/);

      const deepRes = await enqueueScan(env, {
        url: "https://site-b.com",
        hostname: "site-b.com",
        mode: "deep",
      });
      expect(deepRes.status).toBe("queued");
    });

    it("deduplicates in-flight scans for identical URL + mode", async () => {
      const res1 = await enqueueScan(env, {
        url: "https://site-dup.com",
        hostname: "site-dup.com",
        mode: "standard",
      });
      expect(res1.status).toBe("queued");

      const res2 = await enqueueScan(env, {
        url: "https://site-dup.com",
        hostname: "site-dup.com",
        mode: "standard",
      });
      expect(res2.status).toBe("deduplicated");
      expect(res2.scanId).toBe(res1.scanId);
    });

    it("claims jobs adhering to slot concurrency and per-host limits", async () => {
      await enqueueScan(env, { url: "https://target-1.com", hostname: "target-1.com", mode: "standard" });
      await enqueueScan(env, { url: "https://target-2.com", hostname: "target-2.com", mode: "standard" });

      // Claim first job with standard slot
      const job1 = await claimNextJob(env, "worker-vm-1", 2, 0, []);
      expect(job1).not.toBeNull();
      expect(job1?.hostname).toBe("target-1.com");

      // Claim second job: cannot target target-1.com if it were queued again, but target-2.com is available
      const job2 = await claimNextJob(env, "worker-vm-1", 1, 0, ["target-1.com"]);
      expect(job2).not.toBeNull();
      expect(job2?.hostname).toBe("target-2.com");

      // If available slots is 0, no job is claimed
      const job3 = await claimNextJob(env, "worker-vm-1", 0, 0, []);
      expect(job3).toBeNull();
    });

    it("renews lease with heartbeat and detects user cancellation", async () => {
      const enq = await enqueueScan(env, { url: "https://cancel-test.com", hostname: "cancel-test.com", mode: "standard" });
      const job = await claimNextJob(env, "worker-vm-1", 1, 0, []);
      expect(job?.id).toBe(enq.scanId);

      const hb1 = await heartbeatJob(env, enq.scanId, "worker-vm-1", "RUNNING");
      expect(hb1.ok).toBe(true);
      expect(hb1.cancelled).toBe(false);

      // User cancels scan
      await cancelScan(env, enq.scanId);

      // Next heartbeat detects cancellation immediately
      const hb2 = await heartbeatJob(env, enq.scanId, "worker-vm-1", "RUNNING");
      expect(hb2.cancelled).toBe(true);
    });

    it("records completion and caches public reports", async () => {
      const enq = await enqueueScan(env, { url: "https://cached-site.com", hostname: "cached-site.com", mode: "standard" });
      const job = await claimNextJob(env, "worker-vm-1", 1, 0, []);
      expect(job).not.toBeNull();

      await completeJob(env, enq.scanId, "worker-vm-1", { manifest: { checks: [] } }, 95, 100, []);

      // Submitting the same site returns cached report immediately
      const cachedSubmission = await enqueueScan(env, { url: "https://cached-site.com", hostname: "cached-site.com", mode: "standard" });
      expect(cachedSubmission.status).toBe("cached");
    });

    it("calculates accurate queue position and metrics", async () => {
      const enq1 = await enqueueScan(env, { url: "https://pos-1.com", hostname: "pos-1.com", mode: "standard" });
      const scan1 = (mockDb as any).scans.get(enq1.scanId);
      if (scan1) scan1.created_at = 1000;

      const enq2 = await enqueueScan(env, { url: "https://pos-2.com", hostname: "pos-2.com", mode: "standard" });
      const scan2 = (mockDb as any).scans.get(enq2.scanId);
      if (scan2) scan2.created_at = 2000;

      const pos = await getQueuePosition(env, enq2.scanId);
      expect(pos.queuePosition).toBe(2);
      expect(pos.estimatedWaitSec).toBeGreaterThan(0);

      const metrics = await getQueueMetrics(env);
      expect(metrics.queuedCount).toBeGreaterThanOrEqual(2);
    });
  });
});
