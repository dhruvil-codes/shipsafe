import fs from "node:fs";
import path from "node:path";
import { runtimeStore } from "./runtime-store";

function ensureLocalEnvLoaded() {
  if (process.env.INSTABOX_API_KEY && process.env.INSTABOX_SANDBOX_ID) return;
  const roots = [
    process.cwd(),
    path.resolve(process.cwd(), ".."),
    path.resolve(process.cwd(), "../.."),
  ];
  for (const root of roots) {
    for (const filename of [".env.local", ".env"]) {
      const file = path.join(root, filename);
      if (fs.existsSync(file)) {
        try {
          const content = fs.readFileSync(file, "utf8");
          for (const line of content.split("\n")) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith("#")) continue;
            const eq = trimmed.indexOf("=");
            if (eq > 0) {
              const key = trimmed.slice(0, eq).trim();
              let val = trimmed.slice(eq + 1).trim();
              if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                val = val.slice(1, -1);
              }
              if (!process.env[key]) process.env[key] = val;
            }
          }
        } catch {}
      }
    }
  }
}

ensureLocalEnvLoaded();

export async function executionReadiness() {
  ensureLocalEnvLoaded();
  const hasInstaBoxCreds = Boolean(
    process.env.INSTABOX_API_KEY &&
    process.env.INSTABOX_SANDBOX_ID &&
    !process.env.INSTABOX_API_KEY.startsWith("fixture-")
  );
  const isExplicitLocal = process.env.SHIPSAFE_RUNTIME === "local";
  const isVercel = Boolean(process.env.VERCEL);
  const deploymentIdAvailable = Boolean(process.env.VERCEL_DEPLOYMENT_ID);
  const databaseConfigured = Boolean(process.env.DATABASE_URL || process.env.CLOUDFLARE_WORKER_URL);
  const durableDispatchConfigured = process.env.SHIPSAFE_DURABLE_DISPATCH === "workflow";
  let persistenceReady = false;
  let cleanupFailure = false;
  let storageCheckFailed = false;
  try {
    persistenceReady = await runtimeStore.isPersistent();
    cleanupFailure = await runtimeStore.hasCleanupFailure();
  } catch {
    // Storage errors can include connection details. Readiness reports a stable
    // blocker and never exposes the underlying error to the browser.
    storageCheckFailed = true;
  }
  const localConfigured = (hasInstaBoxCreds || isExplicitLocal) && persistenceReady;
  const productionConfigured = isVercel && databaseConfigured && (Boolean(process.env.CLOUDFLARE_WORKER_URL) || (durableDispatchConfigured && deploymentIdAvailable)) && hasInstaBoxCreds && persistenceReady;
  const configured = !cleanupFailure && !storageCheckFailed && (isVercel ? productionConfigured : localConfigured);
  return {
    executionConfigured: configured,
    labEnabled: configured && process.env.SHIPSAFE_LAB_ENABLED === "1",
    executionBlockers: configured
      ? []
      : isVercel
        ? [
            ...(!databaseConfigured ? ["Scanning requires DATABASE_URL for durable production storage."] : []),
            ...(!durableDispatchConfigured && !process.env.CLOUDFLARE_WORKER_URL ? ["Scanning requires SHIPSAFE_DURABLE_DISPATCH=workflow for durable dispatch."] : []),
            ...(!deploymentIdAvailable && !process.env.CLOUDFLARE_WORKER_URL ? ["Scanning requires VERCEL_DEPLOYMENT_ID so durable workflow dispatch can identify this deployment."] : []),
            ...(!hasInstaBoxCreds ? ["Scanning requires InstaBox credentials (INSTABOX_API_KEY, INSTABOX_SANDBOX_ID)."] : []),
            ...(!persistenceReady ? ["Scanning requires the persistent database runtime store; temporary filesystem storage is not production-ready."] : []),
            ...(storageCheckFailed ? ["Scanning cannot verify persistent storage readiness."] : []),
            ...(cleanupFailure ? ["Scanning is blocked until the recorded cleanup failure is repaired."] : []),
          ]
        : [
            ...(!isExplicitLocal ? ["Scanning requires explicit local runtime configuration."] : []),
            ...(!hasInstaBoxCreds ? ["Scanning requires InstaBox credentials (INSTABOX_API_KEY, INSTABOX_SANDBOX_ID)."] : []),
            ...(!persistenceReady ? ["Scanning requires persistent storage; in-memory storage is not durable."] : []),
            ...(storageCheckFailed ? ["Scanning cannot verify persistent storage readiness."] : []),
            ...(cleanupFailure ? ["Scanning is blocked until the recorded cleanup failure is repaired."] : []),
          ],
  };
}

export async function executionUnavailable() {
  return {
    error: "The scan worker is not configured for this runtime. No scan was run.",
    code: "EXECUTION_NOT_READY",
    ...await executionReadiness(),
  };
}
