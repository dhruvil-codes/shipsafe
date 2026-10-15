import type { ScanStatus } from "./schema.js";

export interface ScanRecord {
  id: string;
  projectId: string;
  sandboxId?: string;
  status: ScanStatus;
  score?: number;
  coverage?: number;
  createdAt: Date;
}

export interface FindingRecord {
  id: string;
  scanId: string;
  severity: string;
  title: string;
  description: string;
  /** JSON-stringified evidence payload. */
  evidence: string;
  remediation: string;
  cwe?: string;
}

export interface ScanEventRecord {
  id: string;
  scanId: string;
  stage: string;
  message: string;
  timestamp: Date;
}

export interface CreateScanInput {
  id?: string;
  projectId: string;
  sandboxId?: string;
}

export interface ScanStore {
  createScan(input: CreateScanInput): Promise<ScanRecord>;
  getScan(id: string): Promise<ScanRecord | undefined>;
  updateScan(
    id: string,
    patch: Partial<
      Pick<ScanRecord, "status" | "sandboxId" | "score" | "coverage">
    >,
  ): Promise<ScanRecord>;
  addFinding(
    input: Omit<FindingRecord, "id"> & { id?: string },
  ): Promise<FindingRecord>;
  listFindings(scanId: string): Promise<FindingRecord[]>;
  addEvent(
    input: Omit<ScanEventRecord, "id" | "timestamp"> & {
      id?: string;
      timestamp?: Date;
    },
  ): Promise<ScanEventRecord>;
  listEvents(scanId: string): Promise<ScanEventRecord[]>;
}

export class ScanNotFoundError extends Error {
  constructor(id: string) {
    super(`scan not found: ${id}`);
    this.name = "ScanNotFoundError";
  }
}

function newId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random()
    .toString(36)
    .slice(2, 10)}`;
}

/**
 * Map-based, zero-config store for tests and local development.
 * Production will swap this for a Drizzle/Postgres-backed implementation
 * behind the same interface.
 */
export class InMemoryScanStore implements ScanStore {
  private scans = new Map<string, ScanRecord>();
  private findingsByScan = new Map<string, FindingRecord[]>();
  private eventsByScan = new Map<string, ScanEventRecord[]>();

  async createScan(input: CreateScanInput): Promise<ScanRecord> {
    const record: ScanRecord = {
      id: input.id ?? newId("scn"),
      projectId: input.projectId,
      sandboxId: input.sandboxId,
      status: "QUEUED",
      createdAt: new Date(),
    };
    this.scans.set(record.id, record);
    return { ...record };
  }

  async getScan(id: string): Promise<ScanRecord | undefined> {
    const found = this.scans.get(id);
    return found ? { ...found } : undefined;
  }

  async updateScan(
    id: string,
    patch: Partial<
      Pick<ScanRecord, "status" | "sandboxId" | "score" | "coverage">
    >,
  ): Promise<ScanRecord> {
    const existing = this.scans.get(id);
    if (!existing) throw new ScanNotFoundError(id);
    const updated: ScanRecord = { ...existing, ...patch };
    this.scans.set(id, updated);
    return { ...updated };
  }

  async addFinding(
    input: Omit<FindingRecord, "id"> & { id?: string },
  ): Promise<FindingRecord> {
    if (!this.scans.has(input.scanId)) throw new ScanNotFoundError(input.scanId);
    const record: FindingRecord = { ...input, id: input.id ?? newId("fnd") };
    const list = this.findingsByScan.get(input.scanId) ?? [];
    list.push(record);
    this.findingsByScan.set(input.scanId, list);
    return { ...record };
  }

  async listFindings(scanId: string): Promise<FindingRecord[]> {
    return (this.findingsByScan.get(scanId) ?? []).map((f) => ({ ...f }));
  }

  async addEvent(
    input: Omit<ScanEventRecord, "id" | "timestamp"> & {
      id?: string;
      timestamp?: Date;
    },
  ): Promise<ScanEventRecord> {
    if (!this.scans.has(input.scanId)) throw new ScanNotFoundError(input.scanId);
    const record: ScanEventRecord = {
      ...input,
      id: input.id ?? newId("evt"),
      timestamp: input.timestamp ?? new Date(),
    };
    const list = this.eventsByScan.get(input.scanId) ?? [];
    list.push(record);
    this.eventsByScan.set(input.scanId, list);
    return { ...record };
  }

  async listEvents(scanId: string): Promise<ScanEventRecord[]> {
    return (this.eventsByScan.get(scanId) ?? [])
      .slice()
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime())
      .map((e) => ({ ...e }));
  }
}

/** Factory defaulting to the in-memory implementation (zero-config). */
export function createStore(kind: "memory" = "memory"): ScanStore {
  void kind;
  return new InMemoryScanStore();
}
