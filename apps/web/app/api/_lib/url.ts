import { z } from "zod";

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isPrivateIpv4(host: string): boolean {
  const m = IPV4_RE.exec(host);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true; // RFC 1918
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local + cloud metadata
  if (a === 0) return true; // unspecified
  return false;
}

function isBlockedHostname(host: string): string | null {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return "loopback host";
  if (h === "::1" || h === "[::1]") return "loopback address";
  // Bracketed IPv6 from URL parsing keeps brackets; strip for checks.
  const bare = h.replace(/^\[(.*)\]$/, "$1");
  if (bare === "::1") return "loopback address";
  if (bare.startsWith("fe80:")) return "link-local address";
  if (bare.startsWith("fc00:") || bare.startsWith("fd00:")) {
    return "private address";
  }
  if (bare.startsWith("::ffff:")) {
    // IPv4-mapped IPv6: check the embedded IPv4 address.
    const embedded = bare.slice("::ffff:".length);
    if (isPrivateIpv4(embedded)) return "private address";
  }
  if (isPrivateIpv4(h)) return "private address";
  if (
    h === "metadata.google.internal" ||
    h === "instance-data" ||
    h.endsWith(".internal")
  ) {
    return "metadata/blocked host";
  }
  return null;
}

/**
 * MVP authorization stub: accept any well-formed public http(s) URL.
 * Validates shape (protocol, parseable host) and best-effort blocks
 * private/loopback/link-local/metadata ranges (S-07). Full DNS-resolution
 * and redirect-rebinding checks live in `packages/safe-fetch` (Agent 2/WS-2
 * scope) and MUST gate real scan execution.
 */
export const CreateScanSchema = z.object({
  url: z
    .string()
    .min(1, "url is required")
    .refine(
      (value) => {
        let parsed: URL;
        try {
          parsed = new URL(value);
        } catch {
          return false;
        }
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          return false;
        }
        if (!parsed.hostname) return false;
        return isBlockedHostname(parsed.hostname) === null;
      },
      (value) => {
        let reason = "must be a valid http(s) URL";
        try {
          const parsed = new URL(value);
          if (
            parsed.protocol !== "http:" &&
            parsed.protocol !== "https:"
          ) {
            reason = "only http and https URLs are allowed";
          } else {
            const blocked = isBlockedHostname(parsed.hostname);
            if (blocked) reason = `blocked target: ${blocked}`;
          }
        } catch {
          reason = "must be a valid http(s) URL";
        }
        return { message: `Invalid scan target: ${reason}` };
      },
    ),
  projectName: z.string().min(1).max(120).optional(),
});

export type CreateScanInput = z.infer<typeof CreateScanSchema>;
