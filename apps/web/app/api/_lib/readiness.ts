import fs from "node:fs";
import path from "node:path";
import { apiStore } from "./store";

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

export function executionReadiness() {
  ensureLocalEnvLoaded();
  const hasInstaBoxCreds = Boolean(
    process.env.INSTABOX_API_KEY &&
    process.env.INSTABOX_SANDBOX_ID &&
    !process.env.INSTABOX_API_KEY.startsWith("fixture-")
  );
  const isExplicitLocal = process.env.SHIPSAFE_RUNTIME === "local";
  const configured = (hasInstaBoxCreds || isExplicitLocal) && apiStore.isPersistent() && !apiStore.hasCleanupFailure();
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