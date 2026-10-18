import { sleep } from "workflow";
import { start } from "workflow/api";

const MAX_BUSY_POLLS = 360;
const RECOVERY_INTERVAL = "30s";
const RECOVERY_CYCLES = 360;

/** Execute one claimed scan or report that another workflow currently owns it. */
export async function executeScanStep(scanId: string): Promise<"busy" | "done"> {
  "use step";

  // Keep the VM, Postgres and InstaBox dependencies inside the Node step bundle.
  const { executeDurableScan } = await import("../app/api/_lib/baseline-runtime");
  return executeDurableScan(scanId);
}

Object.assign(executeScanStep, { maxRetries: 2 });

/** Expire only work that remains queued after its duplicate-delivery wait. */
export async function expireQueuedScanStep(scanId: string): Promise<void> {
  "use step";

  const { runtimeStore } = await import("../app/api/_lib/runtime-store");
  await runtimeStore.expireQueuedScan(scanId);
}

Object.assign(expireQueuedScanStep, { maxRetries: 2 });

/** Renew the singleton lease and redispatch queued outbox entries. */
export async function recoverDispatchStep(token: string): Promise<boolean> {
  "use step";

  const { runtimeStore } = await import("../app/api/_lib/runtime-store");
  if (!await runtimeStore.heartbeatRecovery(token)) return false;
  await runtimeStore.reapExpiredExecutions();
  const { dispatchQueuedScans } = await import("../app/api/_lib/queue-dispatch");
  await dispatchQueuedScans();
  return true;
}

Object.assign(recoverDispatchStep, { maxRetries: 2 });

/** Chain a fresh bounded run so recovery does not depend on another user request. */
export async function continueRecoveryStep(token: string): Promise<void> {
  "use step";

  const { runtimeStore } = await import("../app/api/_lib/runtime-store");
  if (!await runtimeStore.heartbeatRecovery(token)) return;
  await start(scanRecoveryWorkflow, [token]);
}

Object.assign(continueRecoveryStep, { maxRetries: 2 });

/** A durable run waits for the cross-instance scan mutex and retries its claim. */
export async function scanWorkflow(scanId: string): Promise<void> {
  "use workflow";

  for (let attempt = 0; attempt < MAX_BUSY_POLLS; attempt += 1) {
    const result = await executeScanStep(scanId);
    if (result === "done") return;
    await sleep("5s");
  }
  await expireQueuedScanStep(scanId);
}

/** A leased, durable outbox sweeper that rolls into a fresh run every 3 hours. */
export async function scanRecoveryWorkflow(token: string): Promise<void> {
  "use workflow";

  for (let cycle = 0; cycle < RECOVERY_CYCLES; cycle += 1) {
    if (!await recoverDispatchStep(token)) return;
    await sleep(RECOVERY_INTERVAL);
  }
  await continueRecoveryStep(token);
}
