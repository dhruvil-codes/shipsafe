# ShipSafe Production Deployment Guide: Cloudflare & Single-VM Architecture

This guide provides step-by-step instructions for deploying **ShipSafe** to Cloudflare using **Cloudflare Pages / Workers**, **Cloudflare D1** (serverless SQL database), **Cloudflare R2** (zero-egress object storage), and a single **InstaBox Micro-VM** running the pull-based worker manager.

---

## Architecture Overview

```
                      ┌───────────────────────────────────────────────┐
                      │              Cloudflare Edge                  │
                      │                                               │
Browser User ─────────► Workers / Pages (Frontend & Public APIs)      │
                      │   - Turnstile & Sliding Window Rate Limiting  │
                      │   - SSRF Protection & URL Normalization       │
                      │   - Public Report Caching (20m TTL)           │
                      │   - In-flight Duplicate Deduplication         │
                      │   - Bounded Queue Backpressure (Max 100)      │
                      └───────▲───────────────────────────┬───────────┘
                              │                           │
                              │ (D1 Query & Transactions) │ (R2 Put/Get)
                              ▼                           ▼
                      ┌────────────────┐          ┌───────────────────┐
                      │ Cloudflare D1  │          │   Cloudflare R2   │
                      │ (Job State,    │          │  (Full Reports &  │
                      │  Events, Queue)│          │   Evidence Blobs) │
                      └────────────────┘          └───────────────────┘
                              ▲
                              │ Authenticated Outbound HTTPS Pull
                              │ (POST /api/vm/jobs/claim with X-VM-Token)
                              │
                      ┌───────┴───────────────────────────────────────┐
                      │          Single InstaBox Micro-VM             │
                      │                                               │
                      │  ShipSafe Worker Manager (Python 3.13)        │
                      │   - Slot Concurrency: Max 2 Standard, 1 Deep  │
                      │   - Target Concurrency: Max 1 per Hostname    │
                      │   - Linux prlimit Resource Isolation          │
                      │   - Process Group Kill on Cancel / Timeout    │
                      │   - 10s Lease Heartbeats & Telemetry Stream   │
                      │   - Pre-warmed Nuclei & OWASP ZAP Containers  │
                      └───────────────────────────────────────────────┘
```

---

## Step 1: Cloudflare Account Prerequisites

1. Install Wrangler CLI (already included in repository):
   ```bash
   bun x wrangler --version
   ```
2. Log in to your Cloudflare account:
   ```bash
   bun x wrangler login
   ```

---

## Step 2: Provision Cloudflare D1 Database

1. Create the production D1 database:
   ```bash
   bun x wrangler d1 create shipsafe-db
   ```
2. Copy the generated `database_id` from the terminal output and paste it into [`wrangler.jsonc`](../wrangler.jsonc):
   ```jsonc
   "d1_databases": [
     {
       "binding": "DB",
       "database_name": "shipsafe-db",
       "database_id": "YOUR_ACTUAL_D1_DATABASE_ID_HERE",
       "migrations_dir": "deploy/migrations"
     }
   ]
   ```
3. Apply the initial schema migrations to remote D1:
   ```bash
   bun x wrangler d1 execute shipsafe-db --remote --file=deploy/migrations/0001_init.sql
   ```

---

## Step 3: Provision Cloudflare R2 Storage Bucket

1. Create the R2 bucket for storing scan reports and evidence:
   ```bash
   bun x wrangler r2 bucket create shipsafe-reports
   ```
2. (Optional) In the Cloudflare Dashboard under **R2** > **shipsafe-reports** > **Settings**, configure a Lifecycle rule to transition or delete reports older than 90 days.

---

## Step 4: Configure Cloudflare Secrets

Set the cryptographic secrets used for VM authentication and human verification:

```bash
# Shared secret for InstaBox VM worker authentication (generate a strong random token)
bun x wrangler secret put VM_WORKER_SECRET

# (Optional) Cloudflare Turnstile secret key for bot protection
bun x wrangler secret put TURNSTILE_SECRET_KEY
```

---

## Step 5: (Optional) Set Up Cloudflare Turnstile

1. Go to the **Cloudflare Dashboard** > **Turnstile** > **Add Site**.
2. Set Domain to your production domain (or select *Managed*).
3. Copy the **Site Key** and set it in your frontend environment variables:
   ```env
   NEXT_PUBLIC_TURNSTILE_SITE_KEY=your_turnstile_site_key
   ```
4. Copy the **Secret Key** and set it via `wrangler secret put TURNSTILE_SECRET_KEY`.
5. Set `"ENABLE_TURNSTILE": "true"` in [`wrangler.jsonc`](../wrangler.jsonc).

---

## Step 6: Deploy to Cloudflare

Deploy the ShipSafe Edge Gateway and Scheduled Reaper:

```bash
bun x wrangler deploy
```

Your Cloudflare Worker will be live at:
`https://shipsafe.<your-subdomain>.workers.dev` (or your custom domain).

---

## Step 7: Configure the Single InstaBox VM Worker

Now connect your single InstaBox VM to the newly deployed Cloudflare gateway.
Follow the detailed instructions in [`VM-WORKER-GUIDE.md`](./VM-WORKER-GUIDE.md):

1. SSH into the InstaBox VM.
2. Set environment variables:
   ```bash
   export CLOUDFLARE_URL="https://shipsafe.<your-subdomain>.workers.dev"
   export VM_SECRET="your_shared_vm_worker_secret_from_step_4"
   ```
3. Run the worker manager:
   ```bash
   python3 packages/sandbox/src/worker_manager.py
   ```
   *(Or install as a persistent systemd service using the provided unit file).*

---

## Step 8: Verify End-to-End Production Health

1. Check Gateway Health:
   ```bash
   curl -s https://shipsafe.<your-subdomain>.workers.dev/health
   # Returns: {"status":"healthy","service":"ShipSafe Edge Cloudflare Gateway",...}
   ```
2. Check Queue Metrics:
   ```bash
   curl -s https://shipsafe.<your-subdomain>.workers.dev/api/queue/metrics
   # Returns: {"queuedCount":0,"runningCount":0,"completedCount":0,...}
   ```
3. Submit a Test Scan:
   ```bash
   curl -X POST https://shipsafe.<your-subdomain>.workers.dev/api/scans \
     -H "Content-Type: application/json" \
     -d '{"url":"https://example.com","mode":"standard"}'
   # Returns: {"scanId":"scn_...","status":"QUEUED"}
   ```
4. Observe VM pickup in `worker_manager` logs:
   - Worker immediately claims job.
   - Executes baseline check with 256MB/45s CPU limit.
   - Emits SSE events.
   - Durably saves report to R2 and updates D1 status to `COMPLETED`.
