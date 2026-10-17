import { isIP } from "node:net";
import { z } from "zod";

/** DNS ownership applies to a public hostname, never an IP or local service. */
export function publicProjectUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    return ["https:", "http:"].includes(url.protocol) &&
      !url.username && !url.password && !url.hash && !url.search &&
      (!url.port || url.port === (url.protocol === "https:" ? "443" : "80")) &&
      !isIP(host) && !host.includes(":") && host.length <= 253 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(host) &&
      host.split(".").every((label) => label.length <= 63) &&
      !["localhost", "local", "internal", "test", "invalid", "example", "onion", "home", "lan"].some(
        (suffix) => host === suffix || host.endsWith(`.${suffix}`),
      ) && !/^\d+$/.test(host.split(".").at(-1) ?? "");
  } catch {
    return false;
  }
}

export const ProjectSchema = z.object({
  name: z.string().trim().min(1).max(120),
  url: z.string().max(2048).refine(publicProjectUrl, "Use a public http(s) domain URL without credentials, fragments, or custom ports"),
  environment: z.enum(["production", "staging", "development"]),
}).strict();

export const CreateScanSchema = z.object({
  projectId: z.string().min(1).max(128),
  scopeAccepted: z.literal(true),
  mode: z.enum(["standard", "deep"]).default("standard"),
  authorizationId: z.string().min(1).max(128).optional(),
}).strict().superRefine((value, context) => {
  if (value.mode === "deep" && !value.authorizationId) context.addIssue({ code: z.ZodIssueCode.custom, message: "Deep scans require a verified authorizationId" });
  if (value.mode === "standard" && value.authorizationId) context.addIssue({ code: z.ZodIssueCode.custom, message: "Authorization applies only to Deep scans" });
});
