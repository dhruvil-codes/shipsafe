import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";
import { getLiveSandbox, type SandboxLike } from "@shipsafe/sandbox/live-runner";
import { scoreUrlBaseline } from "../../../lib/baseline-score";
import { TERMINAL_STATUSES, type ScanRecord } from "./store";
import { runtimeStore } from "./runtime-store";
import { verifyProject } from "./verification";
import { assertDeepAuthorization } from "./security-policy";
import { validateSecurityReport, securityPosture } from "./security-report";

const Check = z.object({ id: z.string().max(80), title: z.string().max(300), status: z.enum(["passed", "observation", "skipped", "failed"]), evidence: z.string().max(12000), remediation: z.string().max(4000).optional() });
const Report = z.object({ type: z.literal("report"), checks: z.array(Check).max(128), findings: z.array(z.object({ checkId: z.string().max(80), title: z.string().max(300), severity: z.enum(["info", "low", "medium", "high", "critical"]), classification: z.enum(["hardening", "vulnerability"]), description: z.string().max(4000), evidence: z.string().max(12000), remediation: z.string().max(4000) })).max(128), manifest: z.record(z.unknown()) });
export type BaselineReport = z.infer<typeof Report>;
export class CleanupError extends Error {}
export class BaselineExecutionError extends Error {
  constructor(readonly code: "SCOPE_REJECTED" | "BASELINE_FAILED", readonly reason?: BaselineFailureReason) {
    super(code === "SCOPE_REJECTED" ? "The request was rejected by the approved scan scope." : "The baseline request could not complete.");
    this.name = "BaselineExecutionError";
  }
}
const BaselineFailureReason = z.enum(["URL_POLICY", "DNS_POLICY", "REDIRECT_POLICY", "REDIRECT_INVALID", "REDIRECT_PATH", "REDIRECT_HOST", "HTTPS_DOWNGRADE", "REDIRECT_MISSING", "REDIRECT_AMBIGUOUS", "REDIRECT_LIMIT", "RESPONSE_LIMIT", "LAB_POLICY", "CONFIG_POLICY", "SCOPE_POLICY"]);
type BaselineFailureReason = z.infer<typeof BaselineFailureReason>;
const failureCopy: Record<BaselineFailureReason, string> = {
  URL_POLICY: "The URL did not meet the supported exact-host baseline rules.",
  DNS_POLICY: "DNS resolution did not produce only approved public addresses.",
  REDIRECT_POLICY: "The site redirected away from the exact approved hostname, downgraded HTTPS, or returned an ambiguous target. ShipSafe stopped without testing another host. If you are authorized for the destination, submit its final canonical HTTPS hostname directly.",
  REDIRECT_PATH: "A redirect requested an action-like path outside the safe read-only profile. ShipSafe stopped before requesting it.",
  REDIRECT_INVALID: "The site returned a redirect destination that is invalid or outside the supported URL format. ShipSafe stopped without following it.",
  REDIRECT_HOST: "The site redirected to a different hostname. ShipSafe stopped without testing that hostname. If you are authorized for it, submit that final canonical HTTPS hostname directly.",
  HTTPS_DOWNGRADE: "The site redirected from HTTPS to HTTP. ShipSafe stopped to protect the approved transport scope; configure the site to keep the redirect on HTTPS.",
  REDIRECT_MISSING: "The site returned a redirect without a Location destination, so ShipSafe could not safely continue.",
  REDIRECT_AMBIGUOUS: "The site returned multiple redirect destinations. ShipSafe stopped because the destination is ambiguous.",
  REDIRECT_LIMIT: "The site exceeded the baseline redirect limit.",
  RESPONSE_LIMIT: "The response headers exceeded the baseline's 32 KiB safety cap.",
  LAB_POLICY: "The request did not match the fixed private lab scope.",
  CONFIG_POLICY: "The assessment configuration did not meet the baseline policy.",
  SCOPE_POLICY: "The request was rejected by an exact-host scope safeguard.",
};
const LAB_IMAGE = "ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6";
import { getSourceContent } from "./runner-sources";

const shell = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
const python = (source: string) => `python3 -c ${shell(source)}`;
const state = globalThis as typeof globalThis & { shipSafeQueue?: Promise<void> };

async function exec(vm: SandboxLike, command: string, timeoutMs = 20000): Promise<string> {
  const result = await vm.commands.run(command, { timeoutMs }) as { stdout?: string; exitCode?: number };
  if (result.exitCode && result.exitCode !== 0) throw new Error("VM control command failed; no successful result inferred.");
  return result.stdout ?? "";
}

/** A trusted, bounded transport runs on the VM. Lab code runs without external networking. */
export async function runBaseline(
  scan: ScanRecord,
  signal: AbortSignal,
  emit: (stage: string, message: string, metadata?: { checkId?: string; status?: "passed" | "observation" | "skipped"; timestamp?: string }) => void | Promise<unknown>,
  connect = getLiveSandbox,
  emitBatch?: (events: Array<{ stage: string; message: string; checkId?: string; status?: "passed" | "observation" | "skipped"; timestamp?: string }>) => void | Promise<unknown>,
): Promise<BaselineReport> {
  if (!/^scn_[a-f0-9]{32}$/.test(scan.id)) throw new Error("Invalid scan identity");
  const securityMode = scan.mode === "standard" || scan.mode === "deep";
  const authorization = scan.mode === "deep" ? assertDeepAuthorization((await runtimeStore.getExecutionProject(scan.id))!, scan) : undefined;
  const batchSender = emitBatch ?? (async (items) => {
    for (const item of items) {
      const metadata = { ...(item.checkId ? { checkId: item.checkId } : {}), ...(item.status ? { status: item.status } : {}), ...(item.timestamp ? { timestamp: item.timestamp } : {}) };
      if (Object.keys(metadata).length) await emit(item.stage, item.message, metadata);
      else await emit(item.stage, item.message);
    }
  });
  const requireCurrentAuthorization = async () => {
    if (process.env.DATABASE_URL) {
      const current = await runtimeStore.getScan(scan.id);
      if (!current || TERMINAL_STATUSES.has(current.status) || !(await runtimeStore.heartbeatExecution(scan.id))) {
        throw new Error("Scan cancelled or execution lease lost");
      }
    }
    if (scan.mode === "deep") assertDeepAuthorization((await runtimeStore.getExecutionProject(scan.id))!, scan);
    if (signal.aborted) throw new Error("Scan cancelled");
  };
  await requireCurrentAuthorization();
  const vm = await connect();
  const directory = `/tmp/shipsafe-baseline-${scan.id}`;
  const container = `shipsafe-${scan.id}`;
  let prepared = false;
  let report: BaselineReport | undefined;
  let pending = "";
  let offset = 0;
  let finished = false;
  try {
    const engineHash = createHash("sha256")
      .update(getSourceContent("baseline.py"))
      .update(getSourceContent("security_engine.py"))
      .update(getSourceContent("security_registry.py"))
      .update(getSourceContent("security_registry.json"))
      .update(getSourceContent("security_dns.py"))
      .digest("hex").slice(0, 10);
    const sharedDir = `/tmp/shipsafe-shared-${engineHash}`;

    const requiredFiles = securityMode
      ? ["baseline.py", "security_engine.py", "security_registry.py", "security_registry.json", "security_dns.py"]
      : ["baseline.py"];

    await requireCurrentAuthorization();
    const checkShared = await exec(vm, python(`import os,time,re,shutil
for name in os.listdir('/tmp'):
 if not re.fullmatch(r'shipsafe-baseline-scn_[a-f0-9]{32}',name): continue
 p='/tmp/'+name
 if os.path.islink(p) or not os.path.isdir(p) or time.time()-os.stat(p).st_mtime<180: continue
 try:
  pid=int(open(p+'/pid').read());cmd=open('/proc/'+str(pid)+'/cmdline','rb').read()
  if p.encode() in cmd or name.replace('shipsafe-baseline-','shipsafe-').encode() in cmd: continue
 except (FileNotFoundError,ProcessLookupError): pass
 shutil.rmtree(p)
d=${JSON.stringify(directory)}
if not os.path.exists(d): os.makedirs(d, mode=0o700, exist_ok=True)
s=${JSON.stringify(sharedDir)}
req=${JSON.stringify(requiredFiles)}
all_present=os.path.isdir(s) and all(os.path.isfile(os.path.join(s,f)) and os.path.getsize(os.path.join(s,f))>0 for f in req)
print('READY' if all_present else 'NEED_SEED')`));
    if (!checkShared.includes("READY")) {
      const stagingDir = `${sharedDir}-staging-${Date.now()}`;
      await exec(vm, python(`import os,shutil
s=${JSON.stringify(stagingDir)}
if os.path.exists(s): shutil.rmtree(s)
os.makedirs(s, mode=0o700, exist_ok=True)`));
      await vm.files.write(`${stagingDir}/baseline.py`, getSourceContent("baseline.py").replaceAll("\r\n", "\n"));
      if (securityMode) {
        for (const file of ["security_engine.py", "security_registry.py", "security_registry.json", "security_dns.py"]) {
          await vm.files.write(`${stagingDir}/${file}`, getSourceContent(file).replaceAll("\r\n", "\n"));
        }
      }
      await exec(vm, python(`import os,shutil
s=${JSON.stringify(stagingDir)}
t=${JSON.stringify(sharedDir)}
if os.path.exists(t): shutil.rmtree(t)
os.rename(s, t)
for name in os.listdir('/tmp'):
 if (name.startswith('shipsafe-shared-') or name.startswith('shipsafe-shared-v')) and name != os.path.basename(t):
  try: shutil.rmtree('/tmp/' + name)
  except: pass`));
    }
    await exec(vm, python(`import os,shutil
s=${JSON.stringify(sharedDir)}
d=${JSON.stringify(directory)}
for f in os.listdir(s):
 src=os.path.join(s,f); dst=os.path.join(d,f)
 try: os.symlink(src,dst)
 except: shutil.copy2(src,dst)`));
    await vm.files.write(`${directory}/input.json`, JSON.stringify({ mode: scan.mode ?? "website", url: scan.mode === "lab" ? "https://fixture.invalid/" : scan.url, ...(authorization ? { authorization: { hostname: authorization.hostname, expiresAt: authorization.expiresAt, classes: authorization.classes } } : {}) }));
    await requireCurrentAuthorization();
    const args = scan.mode === "lab"
      ? ["timeout", "80s", "docker", "run", "--rm", "--name", container, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", "--cpus", "1", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "--env", "HOME=/tmp", "--entrypoint", "python3", "-i", LAB_IMAGE, "-u", "-c", `import base64;exec(base64.b64decode("${Buffer.from(getSourceContent("baseline.py")).toString("base64")}"))`]
      : securityMode
        ? ["prlimit", "--as=268435456", "--cpu=45", "--nproc=128", "--fsize=1048576", "--nofile=64", "--", "timeout", "50s", "python3", "-u", `${directory}/security_engine.py`]
        : ["timeout", "70s", "python3", "-u", `${directory}/baseline.py`];
    // No shell evaluates user data. The guest receives no control-plane credentials.
    await exec(vm, python(`import subprocess,json,os\nd=${JSON.stringify(directory)}\np=subprocess.Popen(['flock','-w','75','/tmp/shipsafe-baseline-worker.lock']+${JSON.stringify(args)},stdin=open(d+'/input.json','rb'),stdout=open(d+'/events.jsonl','wb'),stderr=open(d+'/stderr.log','wb'),env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/tmp','LANG':'C.UTF-8'},start_new_session=True)\nopen(d+'/pid','w').write(str(p.pid))`));
    prepared = true;
    await requireCurrentAuthorization();
    await emit("RUNNING", scan.mode === "lab" ? "Running the owned synthetic fixture on InstaBox. External networking is disabled." : securityMode ? "Running the registered security checks on the exact hostname with pinned public addresses and shared request limits." : "Running the exact-host baseline on InstaBox with pinned public addresses. No exploit templates or path discovery.");
    const deadline = Date.now() + 165_000;
    while (Date.now() < deadline) {
      await requireCurrentAuthorization();
      const chunk = JSON.parse(await exec(vm, python(`import json,os\nd=${JSON.stringify(directory)}\nf=open(d+'/events.jsonl','rb');f.seek(${offset});b=f.read(65536)\nprint(json.dumps({'data':b.decode('utf-8'),'bytes':len(b)}))`))) as { data: string; bytes: number };
      await requireCurrentAuthorization();
      offset += chunk.bytes;
      if (offset > 1_000_000) throw new Error("Scanner output exceeded its limit");
      pending += chunk.data;
      const lines = pending.split("\n"); pending = lines.pop() ?? "";
      const chunkEvents: Array<{ stage: string; message: string; checkId?: string; status?: "passed" | "observation" | "skipped"; timestamp?: string }> = [];
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        const jsonValues: unknown[] = [];
        try {
          jsonValues.push(JSON.parse(line));
        } catch {
          let depth = 0;
          let start = -1;
          let inString = false;
          let escape = false;
          for (let i = 0; i < line.length; i++) {
            const char = line[i];
            if (escape) { escape = false; continue; }
            if (char === "\\") { escape = true; continue; }
            if (char === '"') { inString = !inString; continue; }
            if (!inString) {
              if (char === "{" || char === "[") {
                if (depth === 0) start = i;
                depth++;
              } else if (char === "}" || char === "]") {
                depth--;
                if (depth === 0 && start !== -1) {
                  try { jsonValues.push(JSON.parse(line.slice(start, i + 1))); } catch {}
                  start = -1;
                }
              }
            }
          }
        }
        for (const value of jsonValues) {
          const envelope = z.object({ type: z.string() }).passthrough().safeParse(value);
          if (!envelope.success) continue;
          if (envelope.data.type === "report") {
            report = Report.parse(value);
            if (securityMode) validateSecurityReport(report, scan, JSON.parse(getSourceContent("security_registry.json")), authorization?.classes);
            finished = true;
          } else if (envelope.data.type === "error") {
            const failure = z.object({ type: z.literal("error"), code: z.enum(["SCOPE_REJECTED", "BASELINE_FAILED", "SECURITY_FAILED"]), reason: BaselineFailureReason.optional() }).safeParse(value);
            throw new BaselineExecutionError(failure.success && failure.data.code === "SCOPE_REJECTED" ? "SCOPE_REJECTED" : "BASELINE_FAILED", failure.success ? failure.data.reason : undefined);
          } else {
            const event = z.object({ stage: z.string().max(80), message: z.string().max(16000), checkId: z.string().regex(/^[a-z0-9-]{1,80}$/).optional(), status: z.enum(["passed", "observation", "skipped"]).optional(), timestamp: z.string().datetime({ offset: true }).optional() }).safeParse(value);
            if (event.success) {
              chunkEvents.push({
                stage: event.data.stage,
                message: event.data.message,
                ...(event.data.checkId ? { checkId: event.data.checkId } : {}),
                ...(event.data.status ? { status: event.data.status } : {}),
                ...(event.data.timestamp ? { timestamp: event.data.timestamp } : {}),
              });
            }
          }
        }
      }
      if (chunkEvents.length > 0) {
        await batchSender(chunkEvents);
      }
      if (finished) break;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    if (!report) throw new Error("Scanner deadline reached without a validated report");
    return report;
  } finally {
    if (prepared) {
      // Check job identity before signalling; never kill the shared VM.
      try { await exec(vm, python(`import os,signal,subprocess,shutil,time
d=${JSON.stringify(directory)}
try:
 p=int(open(d+'/pid').read())
 def members():
  found=[]
  for name in os.listdir('/proc'):
   if not name.isdigit(): continue
   try:
    if os.getpgid(int(name))!=p: continue
    stat=open('/proc/'+name+'/stat').read().rsplit(')',1)[1].split()
    if stat[0]!='Z': found.append(int(name))
   except (FileNotFoundError,ProcessLookupError): pass
  return found
 live=members()
 if live:
  cmd=b' '.join(open('/proc/'+str(n)+'/cmdline','rb').read() for n in live)
  if d.encode() not in cmd and ${JSON.stringify(container)}.encode() not in cmd: raise RuntimeError('Process identity changed')
  os.killpg(p,signal.SIGTERM)
  until=time.monotonic()+2
  while members() and time.monotonic()<until: time.sleep(.05)
  if members():
   os.killpg(p,signal.SIGKILL)
   until=time.monotonic()+2
   while members() and time.monotonic()<until: time.sleep(.05)
  if members(): raise RuntimeError('Process cleanup was not verified')
except (FileNotFoundError,ProcessLookupError): pass
r=subprocess.run(['docker','rm','-f',${JSON.stringify(container)}],capture_output=True,timeout=10)
left=subprocess.run(['docker','ps','-aq','--filter','name=^/'+${JSON.stringify(container)}+'$'],capture_output=True,text=True,timeout=10)
if left.returncode or left.stdout.strip(): raise RuntimeError('Container cleanup was not verified')
if os.path.exists(d): shutil.rmtree(d)`), 30000); }
      catch { throw new CleanupError("Job cleanup could not be verified"); }
      await emit("CLEANUP", "Temporary job files and any lab container were removed; the shared VM remains available.");
    } else {
      try {
        await exec(vm, python(`import os,shutil\nd=${JSON.stringify(directory)}\nif os.path.exists(d): shutil.rmtree(d)`), 15000);
      } catch {}
    }
  }
}

/** Execute one claimed job; the DB lease fences competing workflow deliveries. */
async function executeClaimedScan(scan: ScanRecord, controller: AbortController): Promise<void> {
  const emit = async (stage: string, message: string, metadata?: { checkId?: string; status?: "passed" | "observation" | "skipped"; timestamp?: string }) => {
    if (stage === "RUNNING" && !controller.signal.aborted && !TERMINAL_STATUSES.has((await runtimeStore.getScan(scan.id))!.status)) await runtimeStore.updateScan(scan.id, { status: "RUNNING" });
    return await runtimeStore.addEvent({ scanId: scan.id, stage, message, ...metadata });
  };
  const emitBatch = async (events: Array<{ stage: string; message: string; checkId?: string; status?: "passed" | "observation" | "skipped"; timestamp?: string }>) => {
    if (!events.length) return;
    return await runtimeStore.addEvents(events.map(ev => ({ scanId: scan.id, ...ev })));
  };
  try {
    if (scan.mode !== "lab") {
      const project = await runtimeStore.getExecutionProject(scan.id);
      if (!project || scan.scopeAccepted !== true || new URL(project.url).hostname !== new URL(scan.url).hostname) throw new Error("The exact-host authorization attestation is missing or does not match the queued target");
    }
    if (scan.mode === "deep") {
      const project = await runtimeStore.getExecutionProject(scan.id);
      if (!project) throw new Error("Deep authorization target is missing");
      assertDeepAuthorization(project, scan);
      const proof = await verifyProject(project);
      if (!proof.ok) throw new Error("Domain control could not be reverified before execution");
      assertDeepAuthorization(proof.project, scan);
    }
    await emit("PROVISIONING", "Connecting to the shared InstaBox VM. This job has exclusive use of the scan worker.");
    const report = await runBaseline(scan, controller.signal, emit, getLiveSandbox, emitBatch);
    if (controller.signal.aborted) return;
    if (scan.mode === "deep") assertDeepAuthorization((await runtimeStore.getExecutionProject(scan.id))!, scan);
    const checks = report.checks;
    const scopeLimited = report.manifest.scopeLimited === true;
    const posture = scan.mode === "standard" || scan.mode === "deep" ? securityPosture(report.manifest.unifiedResults, JSON.parse(getSourceContent("security_registry.json")), scan.mode) : null;
    const calculatedBaseline = (!scopeLimited && report.manifest.profile === "bounded-http-hardening") ? scoreUrlBaseline(checks) : null;
    const completionPatch = {
      reportManifest: { ...report.manifest, checks, cleanupState: "verified" },
      ...(scopeLimited ? {} : {
        score: posture?.value ?? calculatedBaseline?.value,
        coverage: posture?.coverage ?? Math.round(checks.filter(check => check.status === "passed" || check.status === "observation").length / Math.max(1, checks.length) * 100),
      }),
    };
    const stopReason = BaselineFailureReason.safeParse(report.manifest.scopeStopReason);
    const completionMessage = scopeLimited
      ? `${stopReason.success ? failureCopy[stopReason.data] : "The submitted hostname returned a redirect that ShipSafe did not follow."} A partial report of that hostname's redirect response was saved. The redirect destination was not contacted; no baseline score was assigned.`
      : "Report generated and saved. Coverage applies only to the baseline profile; deeper application controls were not tested.";
    if (process.env.DATABASE_URL || process.env.CLOUDFLARE_WORKER_URL) {
      await runtimeStore.completeExecution(scan.id, completionPatch, report.findings.map(finding => ({ ...finding, scanId: scan.id })), completionMessage);
    } else {
      for (const finding of report.findings) await runtimeStore.addFinding({ ...finding, scanId: scan.id });
      await runtimeStore.updateScan(scan.id, { ...completionPatch, status: "COMPLETED" });
      await emit("COMPLETED", completionMessage);
    }
  } catch (error) {
    console.error("Scan execution failed; no successful result inferred.");
    if ((await runtimeStore.getScan(scan.id))?.status === "CANCELLED") controller.abort();
    if (!controller.signal.aborted) await runtimeStore.updateScan(scan.id, { status: "FAILED" });
    if (error instanceof CleanupError) {
      await runtimeStore.updateScan(scan.id, { reportManifest: { cleanupState: "unverified" } });
      await emit("CLEANUP_FAILED", "Cleanup could not be verified. The shared worker is blocked until the operator repairs it, including after cancellation.");
    } else if (error instanceof BaselineExecutionError) {
      await emit("SCAN_FAILED", error.code === "SCOPE_REJECTED"
        ? `${error.reason ? failureCopy[error.reason] : "The request was rejected by the approved scan scope."} Temporary job cleanup was verified; no report was generated.`
        : "The baseline request could not complete. Temporary job cleanup was verified; no report was generated.");
    }
    const cleanupUnverified = error instanceof CleanupError;
    const isCapacityError = error instanceof Error && /no room|capacity|short of free memory/i.test(error.message);
    await emit(controller.signal.aborted ? "CANCELLED" : "FAILED", controller.signal.aborted
      ? "Cancellation processed. No successful outcome inferred."
      : cleanupUnverified
        ? "Scan failed because job cleanup could not be verified. The shared worker is quarantined; no successful report inferred."
        : isCapacityError
          ? "InstaBox micro-VM paused: The cloud host currently has insufficient free memory to resume the sandbox. Please try again in a few minutes. No score or finding was inferred."
          : "Scan did not produce a complete report. No score or finding was inferred.");
  } finally { await runtimeStore.releaseExecution(scan.id); }
}

/** One local worker drains the queue independently of browser connections. */
export function kickQueue(): Promise<void> {
  if (state.shipSafeQueue) return state.shipSafeQueue;
  state.shipSafeQueue = (async () => {
    for (;;) {
      if (await runtimeStore.hasCleanupFailure()) return;
      const scan = (await runtimeStore.listQueuedScans())[0];
      if (!scan) return;
      const controller = await runtimeStore.claimExecution(scan.id);
      if (!controller) return;
      await executeClaimedScan(scan, controller);
    }
  })().finally(() => { state.shipSafeQueue = undefined; });
  return state.shipSafeQueue;
}

/** Workflow delivery executes at most one scan within its invocation budget. */
export async function executeDurableScan(id: string): Promise<"busy" | "done"> {
  if (!/^scn_[a-f0-9]{32}$/.test(id) || !process.env.DATABASE_URL) throw new Error("Durable scan configuration is unavailable.");
  let scan = await runtimeStore.getScan(id);
  if (!scan || TERMINAL_STATUSES.has(scan.status)) return "done";
  const controller = await runtimeStore.claimExecution(id);
  if (!controller) {
    scan = await runtimeStore.getScan(id);
    return !scan || TERMINAL_STATUSES.has(scan.status) ? "done" : "busy";
  }
  await executeClaimedScan(scan, controller);
  return "done";
}
