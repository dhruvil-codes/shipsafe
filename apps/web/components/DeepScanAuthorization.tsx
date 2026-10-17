"use client";

import { useEffect, useState } from "react";
import { CopyButton } from "@/components/product-ui";
import { isVerified, request, type DeepScanClass, type Project, type SecurityAuthorization } from "@/components/product/data";

const CLASSES: { id: DeepScanClass; label: string }[] = [
  { id: "configuration", label: "GET /.git/HEAD to check for exposed Git metadata" },
  { id: "discovery", label: "GET up to 3 same-host page links without queries or fragments; exclude logout, signout, delete, remove and unsubscribe paths" },
  { id: "cors", label: "GET the approved page with Origin: https://shipsafe-origin.invalid to inspect its CORS response" },
  { id: "vulnerability", label: "Run vetted, non-destructive Nuclei & OWASP ZAP passive assessments with strict rate-limiting" },
];
type AuthorizationState = { hostname: string; dnsRecord: { type: "TXT"; name: string; value: string }; authorization: SecurityAuthorization | null };

/** DNS proof and narrowly scoped consent precede the separate scan-start action. */
export default function DeepScanAuthorization({ project, disabled, running, onStart, onRevoked }: {
  project: Project; disabled: boolean; running: boolean;
  onStart: (authorizationId: string) => Promise<void>;
  onRevoked: () => void;
}) {
  const [state, setState] = useState<AuthorizationState | null>(null);
  const [verifiedProject, setVerifiedProject] = useState(project);
  const [classes, setClasses] = useState<DeepScanClass[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [now, setNow] = useState(Date.now());
  const hostname = new URL(project.url).hostname;
  const path = `/api/projects/${encodeURIComponent(project.id)}`;
  useEffect(() => {
    let mounted = true;
    request<AuthorizationState>(`${path}/authorization`).then(next => { if (mounted) setState(next); })
      .catch(reason => { if (mounted) setError(reason instanceof Error ? reason.message : "Could not load authorization."); });
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => { mounted = false; clearInterval(timer); };
  }, [path]);
  const grant = state?.authorization;
  const grantActive = Boolean(grant && !grant.revokedAt && Date.parse(grant.expiresAt) > now);
  const verified = isVerified(verifiedProject);
  async function verify() {
    setBusy("Verifying DNS"); setError(""); setNotice("");
    try {
      const result = await request<{ project: Project }>(`${path}/verify`, { method: "POST" });
      setVerifiedProject(result.project); setNotice("DNS ownership verified. Select the actions you authorize below.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "DNS verification failed."); }
    finally { setBusy(""); }
  }
  async function authorizeAndStart() {
    if (!verified || !classes.length || running) return;
    setBusy("Authorizing"); setError(""); setNotice("");
    try {
      const result = await request<{ authorization: SecurityAuthorization }>(`${path}/authorization`, {
        method: "POST", body: JSON.stringify({ classes, consent: true }),
      });
      setState(previous => previous ? { ...previous, authorization: result.authorization } : previous);
      await onStart(result.authorization.id);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Authorization failed."); }
    finally { setBusy(""); }
  }
  async function revoke() {
    setBusy("Revoking"); setError("");
    try {
      await request(`${path}/authorization`, { method: "DELETE" });
      setState(previous => previous ? { ...previous, authorization: previous.authorization ? { ...previous.authorization, revokedAt: new Date().toISOString() } : null } : previous);
      setNotice("Authorization revoked. Associated deep scan jobs have been stopped."); onRevoked();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Revocation failed."); }
    finally { setBusy(""); }
  }
  return <section className="deep-authorization panel stack" aria-label="Deep scan authorization">
    <div><span className="eyebrow">Deep Security Scan</span><h3>Verify and authorize {hostname}</h3></div>
    <p className="small muted">Deep checks need DNS proof of ownership and explicit consent for each action class. Preparing this panel does not start a scan.</p>
    <div className="deep-dns"><h4>1. Publish a DNS TXT record</h4>
      {state ? <dl><dt>Record name</dt><dd><code>{state.dnsRecord.name}</code><CopyButton text={state.dnsRecord.name} label="Copy record name" /></dd><dt>TXT value</dt><dd><code>{state.dnsRecord.value}</code><CopyButton text={state.dnsRecord.value} label="Copy TXT value" /></dd></dl> : <p className="small" role="status">{error ? "DNS instructions unavailable. Prepare Deep Scan again to retry." : "Loading DNS record…"}</p>}
      <button className="button secondary" type="button" onClick={() => void verify()} disabled={Boolean(busy) || disabled || running || !state}>{busy === "Verifying DNS" ? "Verifying DNS…" : verified ? "Recheck DNS ownership" : "Verify DNS ownership"}</button>
      <p className="small" role="status">{verified ? `Ownership verified until ${new Date(verifiedProject.verificationExpiresAt!).toLocaleString()}.` : "DNS ownership has not been verified or has expired. DNS propagation may take time."}</p>
    </div>
    <fieldset className="deep-consent" disabled={Boolean(busy) || disabled || running || !verified}><legend>2. Select permitted actions</legend>
      {CLASSES.map(item => <label key={item.id}><input type="checkbox" checked={classes.includes(item.id)} onChange={event => setClasses(previous => event.target.checked ? [...previous, item.id] : previous.filter(value => value !== item.id))} /><span>{item.label}</span></label>)}
    </fieldset>
    <aside className="notice"><strong>Strict scope and limits</strong><p>GET requests only, against the exact hostname {hostname}. At most 20 requests, 40 seconds, and 64 KiB per response. Authorization lasts at most 15 minutes. No subdomains or third-party hosts.</p><p>No authenticated requests, credentials, exploit payloads, brute force, data mutation, port scanning, destructive actions, or access-control bypass.</p></aside>
    <button className="button" type="button" onClick={() => void authorizeAndStart()} disabled={Boolean(busy) || disabled || running || !verified || !classes.length || !state}>{busy === "Authorizing" ? "Authorizing…" : "Authorize selected actions & start Deep Scan"}</button>
    {grant && <div className="deep-grant"><p className="small" role="status">Authorization {grant.revokedAt ? "revoked" : grantActive ? "active" : "expired"} · {grant.classes.join(", ")} · Expires {new Date(grant.expiresAt).toLocaleString()}</p>{grantActive && <button className="button secondary" type="button" onClick={() => void revoke()} disabled={Boolean(busy) || disabled}>{busy === "Revoking" ? "Revoking…" : "Revoke authorization & stop Deep Scans"}</button>}</div>}
    {busy && <p className="small" role="status">{busy}…</p>}{notice && <p className="small" role="status">{notice}</p>}{error && <p className="scan-error" role="alert">{error}</p>}
  </section>;
}
