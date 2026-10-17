import { normalizeUrlInput } from "./scan-flow";
import type { ScanRecord } from "@/components/product/data";

/** Browser-side convenience validation; the API remains authoritative. */
export function inlineTarget(raw: string): { url: string; hostname: string } {
  const result = normalizeUrlInput(raw);
  if (!result.ok) throw new Error(result.error);
  const url = new URL(result.url);
  if (!url.hostname.includes(".") || url.username || url.password || url.hash || url.port) {
    throw new Error("Enter a public website URL without credentials, fragments or custom ports.");
  }
  return { url: url.href, hostname: url.hostname };
}

/** Group only the exact hosts a browser owns; a subdomain is a separate target. */
export function scanBranches(scans: ScanRecord[]) {
  const branches = new Map<string, ScanRecord[]>();
  for (const scan of scans) {
    const hostname = new URL(scan.url).hostname;
    branches.set(hostname, [...(branches.get(hostname) ?? []), scan]);
  }
  return [...branches].map(([hostname, items]) => ({ hostname, scans: items }));
}

/** A dropped stream, empty findings, or missing score never imply success. */
export function recordedSummary(status: string, findings: number): string {
  if (status === "COMPLETED") return `${findings} recorded finding${findings === 1 ? "" : "s"}. Review coverage and assessment limits.`;
  if (status === "FAILED" || status === "CANCELLED") return "Partial evidence only. Checks that did not finish receive no credit.";
  return "Awaiting recorded results. No successful outcome is inferred.";
}
