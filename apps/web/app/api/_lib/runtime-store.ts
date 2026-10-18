import { apiStore, type ApiScanStore, type ScanRecord, type FindingRecord } from "./store";
import { getD1Store } from "./d1-store";

type AsyncMethods<T> = { [K in keyof T as T[K] extends (...args: never[]) => unknown ? K : never]: T[K] extends (...args: infer A) => infer R ? (...args: A) => Promise<Awaited<R>> : never };
export type RuntimeStore = AsyncMethods<Omit<ApiScanStore, "reset" | "close" | "exportSnapshot">> & {
  storageKind(): "cloudflare-d1" | "local-file" | "memory";
  heartbeatExecution(id: string): Promise<boolean>;
  completeExecution(id: string, patch: Partial<Pick<ScanRecord, "score" | "coverage" | "reportManifest">>, findings: Omit<FindingRecord, "id">[], message: string): Promise<boolean>;
  reserveDispatch(id: string): Promise<string | undefined>;
  recordDispatch(id: string, token: string, runId: string): Promise<void>;
  releaseDispatch(id: string, token: string): Promise<void>;
  reserveRecovery(): Promise<string | undefined>;
  releaseRecovery(token: string): Promise<void>;
  heartbeatRecovery(token: string): Promise<boolean>;
  reapExpiredExecutions(): Promise<void>;
  expireQueuedScan(id: string): Promise<void>;
};

/** Select shared storage per invocation; production uses Cloudflare D1. */
export const runtimeStore = new Proxy({} as RuntimeStore, {
  get(_target, property: string) {
    if (property === "storageKind") {
      return () => process.env.CLOUDFLARE_WORKER_URL ? "cloudflare-d1" : process.env.VERCEL ? "unconfigured" : apiStore.isPersistent() ? "local-file" : "memory";
    }
    return async (...args: unknown[]) => {
      if (process.env.CLOUDFLARE_WORKER_URL) {
        const store = getD1Store();
        const method = (store as unknown as Record<string, (...values: unknown[]) => unknown>)[property];
        if (!method) throw new Error("Unsupported Cloudflare D1 storage operation.");
        return method.apply(store, args);
      }
      if (process.env.VERCEL) throw new Error("Shared scan storage is not configured.");
      if (property === "heartbeatExecution") return true;
      const method = (apiStore as unknown as Record<string, (...values: unknown[]) => unknown>)[property];
      if (!method) throw new Error("Unsupported local storage operation.");
      return method.apply(apiStore, args);
    };
  },
});
