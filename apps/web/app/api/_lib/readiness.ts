import { apiStore } from "./store";

export function executionReadiness() {
  const isCloudPlatform = Boolean(process.env.VERCEL || process.env.CF_PAGES);
  const hasInstaBoxCreds = Boolean(
    process.env.INSTABOX_API_KEY &&
    process.env.INSTABOX_SANDBOX_ID &&
    !process.env.INSTABOX_API_KEY.startsWith("fixture-") // Allow tests to mock/override
  );
  const isExplicitLocal = process.env.SHIPSAFE_RUNTIME === "local";
  const isLocalDev = !isCloudPlatform && (isExplicitLocal || process.env.NODE_ENV !== "production" || hasInstaBoxCreds);
  const configured = isLocalDev && (hasInstaBoxCreds || isExplicitLocal) && !apiStore.hasCleanupFailure();
  return {
    executionConfigured: configured,
    labEnabled: configured,
    executionBlockers: configured
      ? []
      : ["Scanning requires InstaBox credentials (INSTABOX_API_KEY, INSTABOX_SANDBOX_ID) in .env.local."],
  };
}

export function executionUnavailable() {
  return {
    error: "The scan worker is not configured for this runtime. No scan was run.",
    code: "EXECUTION_NOT_READY",
    ...executionReadiness(),
  };
}