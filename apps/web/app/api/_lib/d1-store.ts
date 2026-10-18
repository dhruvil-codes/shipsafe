import { createHash } from "node:crypto";
import { ApiScanStore, TERMINAL_STATUSES, type ScanRecord, type FindingRecord } from "./store";

const ownerKey = (owner: string | undefined) => owner ? createHash("sha256").update(owner).digest("hex") : undefined;

const DEFAULT_WORKER_URL = "https://shipsafe.dhruvilmistry16.workers.dev";
const DEFAULT_VM_SECRET = "shipsafe-local-vm-secret";

export class QueueAdmissionError extends Error {
  constructor(readonly code: "QUEUE_FULL" | "RATE_LIMITED") {
    super(code === "QUEUE_FULL" ? "The scan queue is full." : "Please wait before submitting another scan.");
  }
}

export class D1ScanStore {
  private readonly workerUrl: string;
  private readonly secret: string;

  constructor(workerUrl = process.env.CLOUDFLARE_WORKER_URL || DEFAULT_WORKER_URL, secret = process.env.VM_WORKER_SECRET || DEFAULT_VM_SECRET) {
    this.workerUrl = workerUrl.replace(/\/+$/, "");
    this.secret = secret;
  }

  private async fetchState(): Promise<{ value: unknown; revision: number }> {
    const res = await fetch(`${this.workerUrl}/api/state`, {
      headers: { "X-VM-Token": this.secret },
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`Cloudflare D1 state read failed with status ${res.status}`);
    return res.json() as Promise<{ value: unknown; revision: number }>;
  }

  private async updateState(value: unknown, expectedRevision: number): Promise<{ ok: boolean; conflict?: boolean; currentRevision?: number }> {
    const res = await fetch(`${this.workerUrl}/api/state`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VM-Token": this.secret,
      },
      body: JSON.stringify({ value, expectedRevision }),
      cache: "no-store",
    });
    if (res.status === 409) return { ok: false, conflict: true };
    if (!res.ok) throw new Error(`Cloudflare D1 state update failed with status ${res.status}`);
    return res.json() as Promise<{ ok: boolean }>;
  }

  private async transaction<T>(operation: (store: ApiScanStore) => Promise<T> | T, maxRetries = 5): Promise<T> {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const { value, revision } = await this.fetchState();
      const store = ApiScanStore.fromSnapshot(value);
      const result = await operation(store);
      const update = await this.updateState(store.exportSnapshot(), revision);
      if (update.ok) return result;
      // Stale revision; jitter backoff and retry
      await new Promise(resolve => setTimeout(resolve, Math.random() * 50 + 20));
    }
    throw new Error("Cloudflare D1 transaction retry limit exceeded due to concurrency.");
  }

  private async read<T>(operation: (store: ApiScanStore) => T): Promise<T> {
    const { value } = await this.fetchState();
    return operation(ApiScanStore.fromSnapshot(value));
  }

  async isPersistent() { return true; }
  async hasCleanupFailure() { return this.read(store => store.hasCleanupFailure()); }
  async createProject(owner: string, input: Parameters<ApiScanStore["createProject"]>[1]) {
    return this.transaction(store => store.createProject(ownerKey(owner)!, input));
  }
  async getProject(owner: string | undefined, id: string) { return this.read(store => store.getProject(ownerKey(owner), id)); }
  async hasOwner(owner: string) { return this.read(store => store.hasOwner(ownerKey(owner)!)); }
  async getExecutionProject(id: string) { return this.read(store => store.getExecutionProject(id)); }
  async listProjects(owner: string) { return this.read(store => store.listProjects(ownerKey(owner)!)); }
  async setVerification(id: string, verified: boolean) { return this.transaction(store => store.setVerification(id, verified)); }
  async authorizeDeep(owner: string, id: string, classes: Parameters<ApiScanStore["authorizeDeep"]>[2], revision?: number) {
    return this.transaction(store => store.authorizeDeep(ownerKey(owner)!, id, classes, revision));
  }
  async revokeDeep(owner: string, id: string) {
    return this.transaction(store => store.revokeDeep(ownerKey(owner)!, id));
  }
  async ownedScan(owner: string | undefined, id: string) { return this.read(store => store.ownedScan(ownerKey(owner), id)); }
  async listScans(owner: string, id?: string) { return this.read(store => store.listScans(ownerKey(owner)!, id)); }
  async listQueuedScans() { return this.read(store => store.listQueuedScans()); }
  async getScan(id: string) { return this.read(store => store.getScan(id)); }
  async countActive() { return this.read(store => store.countActive()); }

  async createScan(input: Parameters<ApiScanStore["createScan"]>[0]) {
    return this.transaction(store => {
      if (store.countActive() >= 5) throw new QueueAdmissionError("QUEUE_FULL");
      const owner = store.exportSnapshot().owners.find(([id]) => id === input.projectId)?.[1];
      if (!owner) throw new Error("Project not found.");
      if (store.listScans(owner).filter(scan => Date.parse(scan.createdAt) > Date.now() - 60_000).length >= 3) {
        throw new QueueAdmissionError("RATE_LIMITED");
      }
      return store.createScan(input);
    });
  }

  async updateScan(id: string, patch: Parameters<ApiScanStore["updateScan"]>[1]) {
    return this.transaction(store => {
      const current = store.getScan(id);
      if (!current) return undefined;
      if (patch.status && TERMINAL_STATUSES.has(current.status) && patch.status !== current.status) return current;
      return store.updateScan(id, patch);
    });
  }

  async completeExecution(id: string, patch: Partial<Pick<ScanRecord, "score" | "coverage" | "reportManifest">>, findings: Omit<FindingRecord, "id">[], message: string) {
    return this.transaction(store => {
      const current = store.getScan(id);
      if (!current || TERMINAL_STATUSES.has(current.status)) return false;
      for (const finding of findings) store.addFinding(finding);
      store.updateScan(id, { ...patch, status: "COMPLETED" });
      store.addEvent({ scanId: id, stage: "COMPLETED", message });
      return true;
    });
  }

  private readonly executions = new Map<string, AbortController>();

  async claimExecution(id: string): Promise<AbortController | undefined> {
    if (this.executions.has(id)) return undefined;
    const claimed = await this.transaction(store => {
      const scan = store.getScan(id);
      if (!scan || scan.status !== "QUEUED") return false;
      store.updateScan(id, { status: "PROVISIONING" });
      return true;
    });
    if (!claimed) return undefined;
    const controller = new AbortController();
    this.executions.set(id, controller);
    return controller;
  }

  async abortExecution(id: string): Promise<void> {
    this.executions.get(id)?.abort();
    this.executions.delete(id);
    await this.transaction(store => {
      const scan = store.getScan(id);
      if (scan && !TERMINAL_STATUSES.has(scan.status)) {
        store.updateScan(id, { status: "CANCELLED" });
      }
    });
  }

  async releaseExecution(id: string): Promise<void> {
    this.executions.delete(id);
  }

  async heartbeatExecution(_id: string) { return true; }
  async reserveDispatch(_id: string) { return undefined; }
  async recordDispatch(_id: string, _token: string, _runId: string) {}
  async releaseDispatch(_id: string, _token: string) {}
  async reserveRecovery() { return undefined; }
  async releaseRecovery(_token: string) {}
  async heartbeatRecovery(_token: string) { return true; }
  async reapExpiredExecutions() {}
  async expireQueuedScan(id: string) {
    await this.transaction(store => {
      const scan = store.getScan(id);
      if (!scan || TERMINAL_STATUSES.has(scan.status)) return;
      store.updateScan(id, { status: "FAILED" });
      store.addEvent({ scanId: id, stage: "EXPIRED", message: "Scan was not claimed within the allowed execution window." });
    });
  }

  async addEvent(event: Parameters<ApiScanStore["addEvent"]>[0]) {
    return this.transaction(store => store.addEvent(event));
  }

  async addFinding(finding: Parameters<ApiScanStore["addFinding"]>[0]) {
    return this.transaction(store => store.addFinding(finding));
  }

  async listEvents(id: string) { return this.read(store => store.listEvents(id)); }
  async listFindings(id: string) { return this.read(store => store.listFindings(id)); }
}

let d1StoreInstance: D1ScanStore | null = null;
export function getD1Store(): D1ScanStore {
  if (!d1StoreInstance) d1StoreInstance = new D1ScanStore();
  return d1StoreInstance;
}
