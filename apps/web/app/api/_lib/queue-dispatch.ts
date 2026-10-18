import { start } from "workflow/api";
import { runtimeStore } from "./runtime-store";
import { kickQueue } from "./baseline-runtime";
import { scanRecoveryWorkflow, scanWorkflow } from "../../../workflows/scan";

export class QueueDispatchError extends Error {
  readonly code = "DISPATCH_UNAVAILABLE";

  constructor() {
    super("The durable scan dispatcher could not accept queued work.");
    this.name = "QueueDispatchError";
  }
}

function durableDispatchEnabled(): boolean {
  return Boolean(process.env.VERCEL)
    && Boolean(process.env.DATABASE_URL)
    && process.env.SHIPSAFE_DURABLE_DISPATCH === "workflow";
}

import { after } from "next/server";

export async function dispatchQueue(): Promise<void> {
  if (process.env.CLOUDFLARE_WORKER_URL || !process.env.VERCEL) {
    try {
      if (process.env.VERCEL) {
        after(async () => {
          await kickQueue();
        });
      } else {
        void kickQueue();
      }
    } catch {
      void kickQueue();
    }
    return;
  }

  if (!durableDispatchEnabled()) throw new QueueDispatchError();

  try {
    const recoveryToken = await runtimeStore.reserveRecovery();
    if (recoveryToken) {
      try {
        await start(scanRecoveryWorkflow, [recoveryToken]);
      } catch {
        try { await runtimeStore.releaseRecovery(recoveryToken); } catch {}
        throw new QueueDispatchError();
      }
    }
    await dispatchQueuedScans();
  } catch (error) {
    if (error instanceof QueueDispatchError) throw error;
    throw new QueueDispatchError();
  }
}

/** Retry the shared DB outbox without creating another recovery workflow. */
export async function dispatchQueuedScans(): Promise<void> {
  if (await runtimeStore.hasCleanupFailure()) return;

  let scans;
  try {
    scans = await runtimeStore.listQueuedScans();
  } catch {
    throw new QueueDispatchError();
  }

  for (const scan of scans) {
    let reservation: string | undefined;
    try {
      reservation = await runtimeStore.reserveDispatch(scan.id);
      if (!reservation) continue;
      const run = await start(scanWorkflow, [scan.id]);
      await runtimeStore.recordDispatch(scan.id, reservation, run.runId);
    } catch {
      if (reservation) {
        try { await runtimeStore.releaseDispatch(scan.id, reservation); } catch {}
      }
      throw new QueueDispatchError();
    }
  }
}
