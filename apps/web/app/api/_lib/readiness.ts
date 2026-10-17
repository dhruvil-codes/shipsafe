import { apiStore } from "./store";

/** Local runtime is explicit; the legacy runner is never selected by credentials alone. */
export function executionReadiness() {
  const configured = process.env.SHIPSAFE_RUNTIME === "local" && apiStore.isPersistent() && Boolean(process.env.INSTABOX_API_KEY && process.env.INSTABOX_SANDBOX_ID) && !process.env.VERCEL && !process.env.CF_PAGES && !apiStore.hasCleanupFailure();
  return {
    executionConfigured: configured,
    labEnabled: configured && process.env.SHIPSAFE_LAB_ENABLED === "1",
    executionBlockers: configured ? [] : ["Local scanning requires SHIPSAFE_RUNTIME=local, SHIPSAFE_DATA_DIR and InstaBox credentials. Cloudflare execution requires a separate durable storage/worker adapter; credentials alone never enable it."],
  };
}

export function executionUnavailable() {
  return {
    error: "The scan worker is not configured for this runtime. No scan was run.",
    code: "EXECUTION_NOT_READY",
    ...executionReadiness(),
  };
}
