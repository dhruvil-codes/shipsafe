import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executionReadiness } from "./readiness";

function setVercelEnv() {
  vi.stubEnv("VERCEL", "1");
  vi.stubEnv("DATABASE_URL", "");
  vi.stubEnv("VERCEL_DEPLOYMENT_ID", "");
  vi.stubEnv("SHIPSAFE_DURABLE_DISPATCH", "workflow");
  vi.stubEnv("SHIPSAFE_RUNTIME", "local");
  vi.stubEnv("SHIPSAFE_LAB_ENABLED", "1");
  vi.stubEnv("INSTABOX_API_KEY", "fixture-not-a-credential");
  vi.stubEnv("INSTABOX_SANDBOX_ID", "fixture-not-a-machine");
}

beforeEach(() => setVercelEnv());
afterEach(() => vi.unstubAllEnvs());

describe("execution readiness", () => {
  it("does not let stale local runtime settings enable scans on Vercel", async () => {
    const result = await executionReadiness();
    expect(result.executionConfigured).toBe(false);
    expect(result.labEnabled).toBe(false);
    expect(result.executionBlockers).toContain("Scanning requires DATABASE_URL for durable production storage.");
    expect(result.executionBlockers).toContain("Scanning requires InstaBox credentials (INSTABOX_API_KEY, INSTABOX_SANDBOX_ID).");
    expect(result.executionBlockers).toContain("Scanning requires VERCEL_DEPLOYMENT_ID so durable workflow dispatch can identify this deployment.");
  });

  it("fails closed when Vercel storage is unavailable", async () => {
    const result = await executionReadiness();
    expect(result.executionConfigured).toBe(false);
    expect(result.executionBlockers).toContain("Scanning requires the persistent database runtime store; temporary filesystem storage is not production-ready.");
    expect(result.executionBlockers).toContain("Scanning cannot verify persistent storage readiness.");
    expect(JSON.stringify(result)).not.toContain("fixture-not-a");
  });
});
