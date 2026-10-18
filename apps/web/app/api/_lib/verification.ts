import { Resolver } from "node:dns/promises";
import { runtimeStore } from "./runtime-store";
import type { Project } from "./store";
import { publicProjectUrl } from "./url";

export const DNS_TIMEOUT_MS = 5_000;

/** Check exact-host TXT ownership; no HTTP requests or scanner probes occur here. */
export async function verifyProject(project: Project): Promise<{ ok: true; project: Project } | { ok: false; error: string }> {
  if (!publicProjectUrl(project.url)) {
    await runtimeStore.setVerification(project.id, false);
    return { ok: false, error: "Project URL is not a supported public domain." };
  }
  const hostname = new URL(project.url).hostname;
  const record = `_shipsafe.${hostname}`;
  const expected = `shipsafe-verification=${project.verificationToken}`;
  const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  let timer: ReturnType<typeof setTimeout> | undefined;
  let records: string[][];
  try {
    records = await Promise.race([
      resolver.resolveTxt(record),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          resolver.cancel();
          reject(new Error("DNS verification timed out. Try again once the TXT record has propagated."));
        }, DNS_TIMEOUT_MS);
      }),
    ]);
  } catch (error) {
    await runtimeStore.setVerification(project.id, false);
    const code = (error as NodeJS.ErrnoException).code;
    return { ok: false, error: code === "ENOTFOUND" || code === "ENODATA"
      ? `No verification TXT record found at ${record}. Add ${expected} and try again after DNS propagation.`
      : "DNS verification could not complete. Check the TXT record and retry; the project remains unverified." };
  } finally {
    if (timer) clearTimeout(timer);
  }
  if (!records.some((chunks) => chunks.join("") === expected)) {
    await runtimeStore.setVerification(project.id, false);
    return { ok: false, error: `Add TXT ${record} with value ${expected}, then verify again. DNS propagation may take time.` };
  }
  const updated = await runtimeStore.setVerification(project.id, true);
  if (!updated) return { ok: false, error: "Project no longer exists. Refresh and try again." };
  return { ok: true, project: updated };
}
