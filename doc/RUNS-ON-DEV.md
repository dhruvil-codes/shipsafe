# Free ShipSafe address: runs-on.dev

Verified 2026-10-16. No name has been claimed and no DNS or hosting configuration has been changed.

[runs-on.dev](https://runs-on.dev/) is a free subdomain registry, not application hosting or VM compute. Its [FAQ](https://runs-on.dev/faq) permits commercial use, limits claims to one name per GitHub account, and requires an account at least 30 days old with a public repository. Availability is best effort; the registry retains control of its parent domain.

## Supported deployment choices

1. **Cloudflare Pages custom subdomain:** register the chosen hostname in the Pages project's custom domains, then set its registry CNAME to the project's pages.dev address. Follow the registry's [Pages guide](https://runs-on.dev/docs/guides/cloudflare-pages) and [Cloudflare's external-subdomain instructions](https://developers.cloudflare.com/pages/configuration/custom-domains/). Adding a CNAME alone does not establish Pages routing or TLS. This does not make the current server-backed Next.js app a static Pages application.
2. **URL redirect for an initial demo:** the registry's URL record can redirect to the eventual hosted application. The browser address changes to the destination. This is the simplest branding option if the deployment uses workers.dev. See [record semantics](https://runs-on.dev/docs/records).
3. **Workers custom domain:** do not assume a CNAME to workers.dev works. [Workers Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) require an active Cloudflare zone and have existing-CNAME restrictions. A registry subdomain does not grant ownership of runs-on.dev or its Cloudflare zone. A supported integration must be established before promising a direct Workers hostname.

Root CNAME and TXT records cannot coexist at the same registry hostname, but the registry supports child records such as `_shipsafe` for a TXT ownership challenge. Name availability, account eligibility and actual DNS/TLS behavior still need verification at setup time.

The remaining hosting work is unchanged: replace the local file store and in-process dispatcher with production-compatible storage/execution, enforce production quotas and abuse controls, and validate the Cloudflare build/runtime. A free hostname does not fund InstaBox compute or guarantee 24/7 uptime.
