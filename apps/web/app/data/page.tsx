import type { Metadata } from "next";
import Link from "next/link";
import { AppShell, PageHeading } from "@/components/product-ui";
export const metadata: Metadata = { title: "Data & privacy" };
export default function DataPage() {
  return <AppShell><article className="prose">
    <PageHeading title="Your data, in this build." description="What the local ShipSafe scan flow stores and what it can assess." />
    <h2>Browser access</h2>
    <p>A random, HTTP-only browser cookie keeps access to this browser's targets and scan records private. It is a browser capability, not a verified email account. Keep access to your browser private.</p>
    <h2>Targets and reports</h2>
    <p>The local runtime saves targets, scan events and reports in its private data directory when file persistence is configured. Without it, records stay in server memory and can be lost on restart. Cross-device accounts and recovery are not available.</p>
    <h2>Authorization and scope</h2>
    <p>Selecting Scan records your attestation that you own or are authorized to assess the exact hostname. This is not independent ownership proof. The baseline stays on that hostname and blocks private or local network addresses, custom ports, credentials, query strings, and cross-host redirects. It sends no login sessions or exploit payloads.</p>
    <h2>Scan execution</h2>
    <p>When the local runtime is configured, the URL baseline runs 13 bounded HTTP/TLS hardening checks on the shared InstaBox VM queue. An unavailable runner returns an error and creates no simulated result. Cloudflare durable storage and dispatch are not connected, so the current local worker is not ready for public deployment.</p>
    <h2>Assessment limits</h2>
    <p>The URL baseline does not inspect source code, dependencies, authenticated routes, database policies, payments, or AI features. Those need additional artifacts, accounts, or provider test environments.</p>
    <h2>Sample assessment</h2>
    <p>The example report is a static historical exhibit, separate from your targets. It is not a live scan or evidence about a site you submit.</p>
    <h2>Integrations</h2>
    <p>GitHub authentication, repository connections, and team accounts are not configured. The interface does not request their credentials.</p>
    <p><Link href="/#scan-tree">Return to your scan tree →</Link></p>
  </article></AppShell>;
}
