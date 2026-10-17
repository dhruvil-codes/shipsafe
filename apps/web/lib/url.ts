/**
 * URL normalization and validation helpers for the browser.
 * DOM-free and framework-free so they are unit-testable under vitest.
 */

function isPrivateOrReservedHost(hostname: string): boolean {
  const host = hostname.toLowerCase().trim();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "0.0.0.0" ||
    host === "::" ||
    host === "::1"
  ) {
    return true;
  }
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 0 || a >= 224) return true;
  }
  return false;
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
  if (parsed.username || parsed.password) {
    return { ok: false, error: "Credentials in URLs are not allowed." };
  }
  if (isPrivateOrReservedHost(parsed.hostname)) {
    return { ok: false, error: "Target host is private, loopback, or reserved (SSRF protection)" };
  }
  // Strip credentials, fragments, queries, default ports, and extraneous paths to isolate origin.
  const port = parsed.port ? (parsed.port === "443" || parsed.port === "80" ? "" : `:${parsed.port}`) : "";
  const host = parsed.hostname.toLowerCase();
  const scheme = parsed.protocol;
  return { ok: true, url: `${scheme}//${host}${port}/` };
}

export default normalizeUrlInput;