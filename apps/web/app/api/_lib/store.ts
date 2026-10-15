/**
 * Self-contained in-memory scan store for the web API layer.
 * Uses relative imports only (no cross-workspace imports). Mirrors the
 * `ScanStore` interface in `packages/db` so it can be swapped for the
 * Drizzle/Postgres implementation without changing route code.
 */

export type ScanStatus =
  | "QUEUED"
  | "PROVISIONING"
  | "RUNNING"
  | "PROCESSING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

export const TERMINAL_STATUSES: ReadonlySet<ScanStatus> = new Set<ScanStatus>([
  "COMPLETED",
  "FAILED",
  "CANCELLED",
]);

/** Quota: max concurrent (non-terminal) scans — mirrors InstaBox 5-VM limit. */
export const MAX_ACTIVE_SCANS = 5;

export interface ScanRecord {
  id: string;
  projectId: string;
  projectName?: string;
  url: string;
  status: ScanStatus;
  score?: number;
  coverage?: number;
  createdAt: string;
}

export interface FindingRecord {
  id: string;
  scanId: string;
  severity: string;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
}

export interface ScanEventRecord {
  id: string;
  scanId: string;
  stage: string;
  message: string;
  timestamp: string;
}

function newId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random()
    .toString(36)
    .slice(2, 10)}`;
}

class ApiScanStore {
  private scans = new Map<string, ScanRecord>();
  private findings = new Map<string, FindingRecord[]>();
  private events = new Map<string, ScanEventRecord[]>();

  createScan(input: {
    projectId: string;
    projectName?: string;
    url: string;
  }): ScanRecord {
    const record: ScanRecord = {
      id: newId("scn"),
      projectId: input.projectId,
      projectName: input.projectName,
      url: input.url,
      status: "QUEUED",
      createdAt: new Date().toISOString(),
    };
    this.scans.set(record.id, record);
    return { ...record };
  }

  getScan(id: string): ScanRecord | undefined {
    const found = this.scans.get(id);
    return found ? { ...found } : undefined;
  }

  updateScan(
    id: string,
    patch: Partial<Pick<ScanRecord, "status" | "score" | "coverage">>,
  ): ScanRecord | undefined {
    const existing = this.scans.get(id);
    if (!existing) return undefined;
    const updated = { ...existing, ...patch };
    this.scans.set(id, updated);
    return { ...updated };
  }

  addFinding(
    input: Omit<FindingRecord, "id"> & { id?: string },
  ): FindingRecord {
    const record: FindingRecord = { ...input, id: input.id ?? newId("fnd") };
    const list = this.findings.get(input.scanId) ?? [];
    list.push(record);
    this.findings.set(input.scanId, list);
    return { ...record };
  }

  listFindings(scanId: string): FindingRecord[] {
    return (this.findings.get(scanId) ?? []).map((f) => ({ ...f }));
  }

  addEvent(
    input: Omit<ScanEventRecord, "id" | "timestamp"> & {
      id?: string;
      timestamp?: string;
    },
  ): ScanEventRecord {
    const record: ScanEventRecord = {
      ...input,
      id: input.id ?? newId("evt"),
      timestamp: input.timestamp ?? new Date().toISOString(),
    };
    const list = this.events.get(input.scanId) ?? [];
    list.push(record);
    this.events.set(input.scanId, list);
    return { ...record };
  }

  listEvents(scanId: string): ScanEventRecord[] {
    return (this.events.get(scanId) ?? [])
      .slice()
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
      .map((e) => ({ ...e }));
  }

  countActive(): number {
    let n = 0;
    for (const scan of this.scans.values()) {
      if (!TERMINAL_STATUSES.has(scan.status)) n += 1;
    }
    return n;
  }

  /** Test-only: clear all state between tests. */
  reset(): void {
    this.scans.clear();
    this.findings.clear();
    this.events.clear();
  }
}

/** Module singleton: one store per serverless instance (MVP). */
export const apiStore = new ApiScanStore();
