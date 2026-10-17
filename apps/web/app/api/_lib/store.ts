import { randomBytes } from "node:crypto";
import { mkdirSync, openSync, closeSync, readFileSync, writeFileSync, renameSync, unlinkSync, existsSync, fsyncSync } from "node:fs";
import { resolve, join } from "node:path";
import { z } from "zod";
import { assertDeepAuthorization, DEEP_AUTHORIZATION_TTL_MS, SecurityAuthorizationSchema, type SecurityAuthorization } from "./security-policy";

/**
 * Self-contained scan store for the web API layer, with opt-in local persistence.
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
  scopeAccepted?: boolean;
  reportManifest?: Record<string, unknown>;
  mode?: "standard" | "deep" | "website" | "lab";
  authorizationId?: string;
}

export interface Project {
  id: string;
  name: string;
  url: string;
  environment: "production" | "staging" | "development";
  securityAuthorization?: SecurityAuthorization;
  securityAuthorizationRevision?: number;
  verificationToken: string;
  verifiedAt: string | null;
  verificationExpiresAt: string | null;
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
  classification?: "hardening" | "vulnerability";
  checkId?: string;
}

export interface ScanEventRecord {
  id: string;
  scanId: string;
  stage: string;
  message: string;
  timestamp: string;
  checkId?: string;
  status?: "passed" | "observation" | "skipped";
}

function newId(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString("hex")}`;
}

const snapshotSchema = z.object({
  version: z.literal(1),
  projects: z.array(z.object({ id: z.string(), name: z.string(), url: z.string(), environment: z.enum(["production", "staging", "development"]), securityAuthorization: SecurityAuthorizationSchema.optional(), securityAuthorizationRevision: z.number().int().nonnegative().optional(), verificationToken: z.string(), verifiedAt: z.string().nullable(), verificationExpiresAt: z.string().nullable(), createdAt: z.string() }).strict()),
  owners: z.array(z.tuple([z.string(), z.string()])),
  scans: z.array(z.object({ id: z.string(), projectId: z.string(), projectName: z.string().optional(), url: z.string(), status: z.enum(["QUEUED", "PROVISIONING", "RUNNING", "PROCESSING", "COMPLETED", "FAILED", "CANCELLED"]), score: z.number().finite().optional(), coverage: z.number().finite().optional(), createdAt: z.string(), scopeAccepted: z.boolean().optional(), reportManifest: z.record(z.unknown()).optional(), mode: z.enum(["standard", "deep", "website", "lab"]).optional(), authorizationId: z.string().optional() }).strict()),
  findings: z.array(z.object({ id: z.string(), scanId: z.string(), severity: z.string(), title: z.string(), description: z.string(), evidence: z.string(), remediation: z.string(), cwe: z.string().optional(), classification: z.enum(["hardening", "vulnerability"]).optional(), checkId: z.string().optional() }).strict()),
  events: z.array(z.object({ id: z.string(), scanId: z.string(), stage: z.string(), message: z.string(), timestamp: z.string(), checkId: z.string().optional(), status: z.enum(["passed", "observation", "skipped"]).optional() }).strict()),
}).strict();

/** Single-process local store. Persistent mode deliberately rejects concurrent writers. */
export class ApiScanStore {
  private initialized = false;
  private closed = false;
  private failed = false;
  private lockToken?: string;
  private readonly dataDirectory?: string;
  constructor(dataDirectory: string | undefined = process.env.SHIPSAFE_DATA_DIR ?? (process.env.NODE_ENV !== "test" ? resolve(process.cwd(), ".artifacts/local-scans") : undefined)) {
    this.dataDirectory = dataDirectory ? resolve(dataDirectory) : undefined;
  }
  private projects = new Map<string, Project>();
  private owners = new Map<string, string>();
  private executions = new Map<string, AbortController>();
  private scans = new Map<string, ScanRecord>();
  private findings = new Map<string, FindingRecord[]>();
  private events = new Map<string, ScanEventRecord[]>();

  isPersistent(): boolean { return !!this.dataDirectory; }

  /** Operator repair is required before the shared VM can accept another job. */
  hasCleanupFailure(): boolean {
    this.initialize();
    return [...this.scans.values()].some(scan => scan.reportManifest?.cleanupState === "unverified");
  }

  private initialize(): void {
    if (this.closed || this.failed) throw new Error("Scan store is closed or failed; restart after repairing storage.");
    if (this.initialized) return;
    if (!this.dataDirectory) { this.initialized = true; return; }
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    const lockPath = join(this.dataDirectory, "store.lock");
    const token = randomBytes(16).toString("hex");
    try {
      for (let attempt = 0; ; attempt++) {
        try {
          const fd = openSync(lockPath, "wx", 0o600);
          try { writeFileSync(fd, JSON.stringify({ pid: process.pid, token })); fsyncSync(fd); }
          finally { closeSync(fd); }
          this.lockToken = token;
          break;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST" || attempt > 0) throw error;
          const recoveryPath = join(this.dataDirectory, "store.recovery.lock");
          const recoveryFd = openSync(recoveryPath, "wx", 0o600);
          try {
            const raw = readFileSync(lockPath, "utf8");
            const owner = z.object({ pid: z.number().int().positive(), token: z.string().min(1) }).strict().parse(JSON.parse(raw));
            try { process.kill(owner.pid, 0); throw new Error("Scan store already has an active writer."); }
            catch (probeError) {
              if ((probeError as NodeJS.ErrnoException).code !== "ESRCH") throw probeError;
            }
            // Serialize reclamation: never remove another writer's newly acquired lock.
            if (readFileSync(lockPath, "utf8") !== raw) throw new Error("Scan store lock changed during recovery.");
            unlinkSync(lockPath);
          } finally { closeSync(recoveryFd); unlinkSync(recoveryPath); }
        }
      }
      const path = join(this.dataDirectory, "store.json");
      if (existsSync(path)) {
        const state = snapshotSchema.parse(JSON.parse(readFileSync(path, "utf8")));
        const unique = (ids: string[]) => new Set(ids).size === ids.length;
        if (!unique(state.projects.map(p => p.id)) || !unique(state.scans.map(s => s.id)) || !unique(state.owners.map(o => o[0])) || !unique(state.findings.map(f => f.id)) || !unique(state.events.map(e => e.id))) throw new Error("Duplicate persisted record identifiers.");
        const projectIds = new Set(state.projects.map(p => p.id));
        const scanIds = new Set(state.scans.map(s => s.id));
        if (state.owners.length !== projectIds.size || state.owners.some(([id]) => !projectIds.has(id)) || state.scans.some(s => !projectIds.has(s.projectId)) || state.findings.some(f => !scanIds.has(f.scanId)) || state.events.some(e => !scanIds.has(e.scanId))) throw new Error("Invalid persisted record references.");
        this.projects = new Map(state.projects.map(p => [p.id, p]));
        this.owners = new Map(state.owners);
        this.scans = new Map(state.scans.map(s => [s.id, s]));
        for (const finding of state.findings) this.findings.set(finding.scanId, [...(this.findings.get(finding.scanId) ?? []), finding]);
        for (const event of state.events) this.events.set(event.scanId, [...(this.events.get(event.scanId) ?? []), event]);
        for (const scan of this.scans.values()) {
          if (["PROVISIONING", "RUNNING", "PROCESSING"].includes(scan.status)) {
            scan.status = "FAILED";
            this.events.set(scan.id, [...(this.events.get(scan.id) ?? []), { id: newId("evt"), scanId: scan.id, stage: "FAILED", message: "Local service restarted during execution. This scan was interrupted; no automatic rescan was started.", timestamp: new Date().toISOString() }]);
          }
        }
      }
      this.initialized = true;
      this.persist();
    } catch (error) { this.failed = true; this.releaseLock(); throw error; }
  }

  private persist(): void {
    if (!this.dataDirectory) return;
    const state = { version: 1, projects: [...this.projects.values()], owners: [...this.owners.entries()], scans: [...this.scans.values()], findings: [...this.findings.values()].flat(), events: [...this.events.values()].flat() };
    const temporary = join(this.dataDirectory, `store.${this.lockToken}.tmp`);
    try {
      const serialized = JSON.stringify(state);
      snapshotSchema.parse(JSON.parse(serialized));
      const fd = openSync(temporary, "w", 0o600);
      try { writeFileSync(fd, serialized); fsyncSync(fd); } finally { closeSync(fd); }
      renameSync(temporary, join(this.dataDirectory, "store.json"));
      // POSIX directory sync makes the rename durable; Windows does not allow it.
      if (process.platform !== "win32") {
        const directoryFd = openSync(this.dataDirectory, "r");
        try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
      }
    } catch (error) { this.failed = true; throw error; }
  }

  private releaseLock(): void {
    if (!this.lockToken || !this.dataDirectory) return;
    const path = join(this.dataDirectory, "store.lock");
    const owner = JSON.parse(readFileSync(path, "utf8"));
    if (owner.token === this.lockToken && owner.pid === process.pid) unlinkSync(path);
    this.lockToken = undefined;
  }

  /** Explicit shutdown for the local runtime and restart tests. */
  close(): void {
    for (const execution of this.executions.values()) execution.abort();
    this.executions.clear();
    this.releaseLock();
    this.closed = true;
  }

  createProject(owner: string, input: Pick<Project, "name" | "url" | "environment">): Project {
    this.initialize();
    const project: Project = {
      ...input,
      id: newId("prj"),
      verificationToken: randomBytes(32).toString("hex"),
      verifiedAt: null,
      verificationExpiresAt: null,
      createdAt: new Date().toISOString(),
    };
    this.projects.set(project.id, project);
    this.owners.set(project.id, owner);
    this.persist();
    return structuredClone(project);
  }

  getProject(owner: string | undefined, id: string): Project | undefined {
    this.initialize();
    const project = this.projects.get(id);
    return owner && this.owners.get(id) === owner && project ? structuredClone(project) : undefined;
  }

  hasOwner(owner: string): boolean {
    this.initialize();
    return [...this.owners.values()].includes(owner);
  }

  /** Internal dispatch lookup; HTTP handlers must continue to use owner-scoped access. */
  getExecutionProject(scanId: string): Project | undefined {
    this.initialize();
    const scan = this.scans.get(scanId);
    const target = scan && this.projects.get(scan.projectId);
    return target ? structuredClone(target) : undefined;
  }

  listProjects(owner: string): Project[] {
    this.initialize();
    return [...this.projects.values()].filter((project) => this.owners.get(project.id) === owner)
      .map((project) => structuredClone(project)).reverse();
  }

  setVerification(id: string, verified: boolean): Project | undefined {
    this.initialize();
    const project = this.projects.get(id);
    if (!project) return undefined;
    project.verifiedAt = verified ? new Date().toISOString() : null;
    project.verificationExpiresAt = verified ? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() : null;
    this.persist();
    return structuredClone(project);
  }

  /** Grant only the supported classes after a fresh ownership check in the route. */
  authorizeDeep(owner: string, id: string, classes: SecurityAuthorization["classes"], expectedRevision?: number): SecurityAuthorization | undefined {
    const project = this.getProject(owner, id);
    if (!project) return undefined;
    if (expectedRevision !== undefined && (project.securityAuthorizationRevision ?? 0) !== expectedRevision) return undefined;
    const now = Date.now();
    const grant = SecurityAuthorizationSchema.parse({ id: newId("auth"), hostname: new URL(project.url).hostname,
      classes, createdAt: new Date(now).toISOString(), expiresAt: new Date(Math.min(now + DEEP_AUTHORIZATION_TTL_MS, Date.parse(project.verificationExpiresAt ?? ""))).toISOString() });
    assertDeepAuthorization({ ...project, securityAuthorization: grant }, undefined, now);
    this.projects.get(id)!.securityAuthorization = structuredClone(grant);
    this.projects.get(id)!.securityAuthorizationRevision = (project.securityAuthorizationRevision ?? 0) + 1;
    this.persist();
    return structuredClone(grant);
  }

  /** Revoke and persist cancellation before returning; standard jobs retain their scope. */
  revokeDeep(owner: string, id: string): string[] | undefined {
    if (!this.getProject(owner, id)) return undefined;
    const project = this.projects.get(id)!;
    project.securityAuthorizationRevision = (project.securityAuthorizationRevision ?? 0) + 1;
    if (project.securityAuthorization) project.securityAuthorization.revokedAt = new Date().toISOString();
    const cancelled: string[] = [];
    for (const scan of this.scans.values()) {
      if (scan.projectId !== id || scan.mode !== "deep" || TERMINAL_STATUSES.has(scan.status)) continue;
      this.executions.get(scan.id)?.abort();
      scan.status = "CANCELLED";
      cancelled.push(scan.id);
      const event: ScanEventRecord = { id: newId("evt"), scanId: scan.id, stage: "CANCELLED", message: "Deep authorization was revoked. Queued and active Deep work has been cancelled.", timestamp: new Date().toISOString() };
      this.events.set(scan.id, [...(this.events.get(scan.id) ?? []), event]);
    }
    this.persist();
    return cancelled;
  }

  ownedScan(owner: string | undefined, id: string): ScanRecord | undefined {
    this.initialize();
    const scan = this.getScan(id);
    return scan && this.getProject(owner, scan.projectId) ? scan : undefined;
  }

  listScans(owner: string, projectId?: string): ScanRecord[] {
    this.initialize();
    return [...this.scans.values()]
      .filter((scan) => this.owners.get(scan.projectId) === owner && (!projectId || scan.projectId === projectId))
      .map((scan) => structuredClone(scan)).reverse();
  }

  /** Reserve execution synchronously so concurrent subscribers cannot start it twice. */
  claimExecution(id: string): AbortController | undefined {
    this.initialize();
    const scan = this.scans.get(id);
    if (!scan || scan.status !== "QUEUED" || this.executions.has(id)) return undefined;
    const controller = new AbortController();
    this.executions.set(id, controller);
    scan.status = "PROVISIONING";
    this.persist();
    return controller;
  }

  abortExecution(id: string): void {
    this.initialize();
    this.executions.get(id)?.abort();
    this.executions.delete(id);
  }

  /** Completed executions must release process-local cancellation handles. */
  releaseExecution(id: string): void {
    this.initialize();
    this.executions.delete(id);
  }

  /** FIFO jobs survive a local service restart without starting automatically. */
  listQueuedScans(): ScanRecord[] {
    this.initialize();
    return [...this.scans.values()].filter(scan => scan.status === "QUEUED")
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt)).map(scan => structuredClone(scan));
  }

  createScan(input: {
    projectId: string;
    projectName?: string;
    url: string;
    scopeAccepted?: boolean;
    mode?: "standard" | "deep" | "website" | "lab";
  authorizationId?: string;
  }): ScanRecord {
    this.initialize();
    const record: ScanRecord = {
      id: newId("scn"),
      projectId: input.projectId,
      projectName: input.projectName,
      url: input.url,
      status: "QUEUED",
      createdAt: new Date().toISOString(),
      scopeAccepted: input.scopeAccepted,
      mode: input.mode,
      authorizationId: input.authorizationId,
    };
    this.scans.set(record.id, record);
    this.persist();
    return { ...record };
  }

  getScan(id: string): ScanRecord | undefined {
    this.initialize();
    const found = this.scans.get(id);
    return found ? structuredClone(found) : undefined;
  }

  updateScan(
    id: string,
    patch: Partial<Pick<ScanRecord, "status" | "score" | "coverage" | "reportManifest">>,
  ): ScanRecord | undefined {
    this.initialize();
    const existing = this.scans.get(id);
    if (!existing) return undefined;
    const updated = structuredClone({ ...existing, ...patch });
    this.scans.set(id, updated);
    this.persist();
    return structuredClone(updated);
  }

  addFinding(
    input: Omit<FindingRecord, "id"> & { id?: string },
  ): FindingRecord {
    this.initialize();
    const record: FindingRecord = { ...input, id: input.id ?? newId("fnd") };
    const list = this.findings.get(input.scanId) ?? [];
    list.push(record);
    this.findings.set(input.scanId, list);
    this.persist();
    return { ...record };
  }

  listFindings(scanId: string): FindingRecord[] {
    this.initialize();
    return (this.findings.get(scanId) ?? []).map((f) => ({ ...f }));
  }

  addEvent(
    input: Omit<ScanEventRecord, "id" | "timestamp"> & {
      id?: string;
      timestamp?: string;
    },
  ): ScanEventRecord {
    this.initialize();
    const record: ScanEventRecord = {
      ...input,
      id: input.id ?? newId("evt"),
      timestamp: input.timestamp ?? new Date().toISOString(),
    };
    const list = this.events.get(input.scanId) ?? [];
    list.push(record);
    this.events.set(input.scanId, list);
    this.persist();
    return { ...record };
  }

  listEvents(scanId: string): ScanEventRecord[] {
    this.initialize();
    // Keep scanner append order: VM and control-plane timestamps have different precision.
    return (this.events.get(scanId) ?? []).map((e) => ({ ...e }));
  }

  countActive(): number {
    this.initialize();
    let n = 0;
    for (const scan of this.scans.values()) {
      if (!TERMINAL_STATUSES.has(scan.status)) n += 1;
    }
    return n;
  }

  /** Test-only: clear all state between tests. */
  reset(): void {
    this.initialize();
    for (const execution of this.executions.values()) execution.abort();
    this.executions.clear();
    this.projects.clear();
    this.owners.clear();
    this.scans.clear();
    this.findings.clear();
    this.events.clear();
    this.persist();
  }
}

/** Lazily initialized; local disk persistence is opt-in and never distributed. */
const processState = globalThis as typeof globalThis & { shipSafeApiStore?: ApiScanStore };
export const apiStore = processState.shipSafeApiStore ??= new ApiScanStore();
