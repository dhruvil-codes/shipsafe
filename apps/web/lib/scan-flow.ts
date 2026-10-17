/**
 * Pure scan-flow helpers for the single-screen terminal experience.
 * DOM-free and framework-free so they are unit-testable under vitest.
 */

export type ScanPhase = "idle" | "scanning" | "completed";

export type EngineState = "pending" | "running" | "passed" | "warning";

export interface EngineCheck {
  id: string;
  label: string;
  state: EngineState;
  detail: string;
}

export type UiSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface UiFinding {
  id: string;
  severity: UiSeverity;
  title: string;
  summary: string;
  affected: string;
  evidence: string;
  fix: string;
  source: "web" | "osint";
  cwe?: string;
}

export interface OsintHost {
  host: string;
  status: number | null;
  tech: string;
}

export interface OsintSummary {
  subdomains: OsintHost[];
  dmarc: { status: "pass" | "fail" | "unknown"; detail: string };
  spf: { status: "pass" | "fail" | "unknown"; detail: string };
  whois: { registrar: string; expiry: string; privacy: string };
}

export const ENGINE_DEFS: { id: string; label: string }[] = [
  { id: "dns-email", label: "DNS & Email Security (DMARC/SPF)" },
  { id: "attack-surface", label: "Attack Surface (crt.sh / subfinder)" },
  { id: "tls", label: "SSL/TLS Encryption & Ciphers" },
  { id: "headers", label: "HTTP Security Headers & CORS" },
  { id: "files", label: "Sensitive File Probes (/.env, /.git)" },
];

export function initialEngines(): EngineCheck[] {
  return ENGINE_DEFS.map((d) => ({
    id: d.id,
    label: d.label,
    state: "pending" as EngineState,
    detail: "queued",
  }));
}

/** Normalize + validate raw user input. Auto-prepends https:// when missing. */
export function normalizeUrlInput(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, error: "Enter a URL to scan." };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) && !/^https?:\/\//i.test(trimmed)) {
    return { ok: false, error: "Only http and https URLs are allowed." };
  }
  const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withProto);
  } catch {
    return { ok: false, error: "Enter a valid http(s) URL, e.g. https://example.com" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, error: "Only http and https URLs are allowed." };
  }
  if (!parsed.hostname) {
    return { ok: false, error: "Enter a valid http(s) URL, e.g. https://example.com" };
  }
  return { ok: true, url: parsed.href };
}

export type StreamEvent =
  | { kind: "sandbox"; sandboxId: string }
  | { kind: "vmstatus"; status: string }
  | { kind: "log"; stage: string; message: string; checkId?: string; status?: "passed" | "observation" | "skipped"; timestamp?: string }
  | { kind: "stdout"; text: string }
  | { kind: "error"; message: string }
  | { kind: "result"; status: string; score: number | null; coverage: number | null; findingsCount: number }
  | { kind: "done" }
  | { kind: "line"; text: string };

/**
 * Parse one SSE `data:` payload from /api/scans/:id/stream.
 * Handles the JSON envelope ({type: event|log|result}) plus the legacy
 * __sandbox: / __status: / __done control lines; anything else is a raw line.
 */
export function parseStreamPayload(data: string): StreamEvent {
  const text = data.trim();
  if (text.startsWith("__sandbox:")) {
    return { kind: "sandbox", sandboxId: text.slice("__sandbox:".length).trim() };
  }
  if (text.startsWith("__status:")) {
    return { kind: "vmstatus", status: text.slice("__status:".length).trim() };
  }
  if (text.startsWith("__done")) return { kind: "done" };
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    if (obj["type"] === "event" || obj["type"] === "log") {
      return {
        kind: "log",
        stage: String(obj["stage"] ?? ""),
        message: String(obj["message"] ?? ""),
        ...(typeof obj["checkId"] === "string" ? { checkId: obj["checkId"] } : {}),
        ...(obj["status"] === "passed" || obj["status"] === "observation" || obj["status"] === "skipped" ? { status: obj["status"] } : {}),
        ...(typeof obj["timestamp"] === "string" ? { timestamp: obj["timestamp"] } : {}),
      };
    }
    if (obj["type"] === "stdout") {
      return { kind: "stdout", text: String(obj["text"] ?? "") };
    }
    if (obj["type"] === "error") {
      return { kind: "error", message: String(obj["message"] ?? "Unknown VM error") };
    }
    if (obj["type"] === "result") {
      const num = (v: unknown): number | null =>
        typeof v === "number" && Number.isFinite(v) ? v : null;
      return {
        kind: "result",
        status: String(obj["status"] ?? ""),
        score: num(obj["score"]),
        coverage: num(obj["coverage"]),
        findingsCount: typeof obj["findingsCount"] === "number" ? obj["findingsCount"] : 0,
      };
    }
  } catch {
    // not JSON — fall through to raw line
  }
  return { kind: "line", text: data };
}

const ENGINE_KEYWORDS: Record<string, RegExp> = {
  "dns-email": /dmarc|spf|dns|email|checkdmarc|\bmx\b|\btxt\b/i,
  "attack-surface": /subfinder|crt\.sh|subdomain|httpx|takeover|subzy|amass|port scan|nmap/i,
  tls: /tls|ssl|cert|certificate|cipher|handshake/i,
  headers: /header|csp|hsts|cors|x-frame|x-content-type|csp|cookie/i,
  files: /sensitive|\/\.env|\/\.git|wp-config|server-status|api\/docs|probe|dirb|ffuf|gobuster/i,
};

const WARN_RE = /warn|missing|misconfig|vulnerab|exposed|leak|failed|error|open(?!\s*source)/i;
const OK_RE = /\bok\b|passed|complete|valid|secure|no .*expos|404|not found|done/i;

/** Fold one stream log line into the engine checklist (pure, deterministic). */
export function advanceEngines(checks: EngineCheck[], stage: string, message: string): EngineCheck[] {
  const text = `${stage} ${message}`;
  return checks.map((c) => {
    const pattern = ENGINE_KEYWORDS[c.id];
    if (!pattern?.test(text)) return c;
    if (WARN_RE.test(message)) {
      return { ...c, state: "warning" as EngineState, detail: message.slice(0, 90) };
    }
    if (c.state === "warning") return c; // a warning sticks — never downgraded by later lines
    if (OK_RE.test(message)) {
      return { ...c, state: "passed" as EngineState, detail: message.slice(0, 90) };
    }
    return {
      ...c,
      state: "running" as EngineState,
      detail: c.state === "pending" ? message.slice(0, 90) : c.detail,
    };
  });
}

/** Mark every still-running engine passed at stream end; pending stays pending. */
export function finalizeEngines(checks: EngineCheck[]): EngineCheck[] {
  return checks.map((c) =>
    c.state === "running" ? { ...c, state: "passed" as EngineState, detail: "assessed" } : c,
  );
}

const SEVERITIES: UiSeverity[] = ["critical", "high", "medium", "low", "info"];

function toSeverity(value: unknown): UiSeverity {
  const v = String(value ?? "").toLowerCase();
  return (SEVERITIES as string[]).includes(v) ? (v as UiSeverity) : "info";
}

export interface ApiFindingRecord {
  id: string;
  scanId: string;
  severity: string;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  classification?: "hardening" | "vulnerability";
  checkId?: string;
}

/** Map API FindingRecords to UI findings (source: web). */
export function mapApiFindings(records: ApiFindingRecord[]): UiFinding[] {
  return records.map((r) => ({
    id: r.id,
    severity: toSeverity(r.severity),
    title: r.title,
    summary: r.description,
    affected: r.title,
    evidence: r.evidence,
    fix: r.remediation,
    source: "web" as const,
    cwe: r.cwe,
  }));
}

/**
 * Build the ready-to-paste AI fix prompt for Cursor / Claude Code / ChatGPT.
 * Deterministic: same inputs always yield the same prompt.
 */
export function buildAiFixPrompt(
  target: string,
  score: number | null,
  findings: UiFinding[],
): string {
  const head =
    `Here are the security issues ShipSafe identified on my web application (${target}` +
    (score === null ? "" : ` — score ${score}/100`) +
    "):";
  if (findings.length === 0) {
    return (
      `${head}\n\nNo confirmed findings — the scan assessed the target and found no ` +
      `evidence-backed issues.\n\nPlease confirm which additional controls I should enable ` +
      `for a deeper assessment.`
    );
  }
  const order: Record<UiSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort(
    (a, b) => order[a.severity] - order[b.severity] || a.title.localeCompare(b.title),
  );
  const items = sorted
    .map((f, i) => {
      const cwe = f.cwe ? ` (${f.cwe})` : "";
      const fix = f.fix.length > 220 ? `${f.fix.slice(0, 220)}…` : f.fix;
      return `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${cwe}\n   Fix: ${fix}`;
    })
    .join("\n\n");
  return `${head}\n\n${items}\n\nPlease generate the exact configuration code for my project to resolve these issues.`;
}
