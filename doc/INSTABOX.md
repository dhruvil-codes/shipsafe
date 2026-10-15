# InstaBox Reference & Integration Guide

Official Documentation Source: [https://instabox.sh/docs](https://instabox.sh/docs)  
Provider: InsForge AI, Inc.  
SDK Package: `@insforge/instabox-sdk`

---

## 1. Overview & Architecture
InstaBox provides disposable, isolated Linux cloud VMs (sandboxes) with dedicated kernels, full root access, and Docker support. In ShipSafe, InstaBox is the primary compute infrastructure: **all security scans, tool runners (OWASP ZAP, testssl.sh, Semgrep, Gitleaks, Trivy), and test workloads execute inside ephemeral InstaBox sandboxes**.

### Core Concepts
- **Machine (Sandbox)**: KVM guest running Linux (Debian 13 kernel with Docker). Persistent user storage under `/data` (`/data/home`).
- **Templates**: Pre-configured baseline images (e.g. `universal`, `agent-browser`, `herdr`, `orca`). Listed via `instabox templates`.
- **Snapshots**: Private saved state of a machine. ShipSafe uses warm snapshots with pinned toolchains to minimize scan startup latency.
- **Operations**: State changes (create, start, stop, pause, resume, delete) are tracked as asynchronous operations until finished.
- **API Keys**: Keys prefixed with `ibk_...`, transmitted via `X-API-Key` HTTP header or configured via `INSTABOX_API_KEY`.
- **Vault**: Secret store injected into the machine upon boot.

---

## 2. Account & Resource Limits
Agents and orchestrators must account for these limits in the scheduler and quota manager:

| Resource | Free / Standard Limit | Notes |
| :--- | :--- | :--- |
| **Max Concurrent Machines** | 5 machines total | Includes running, paused, and stopped machines |
| **Machine Sizing** | 4 vCPU, 8 GiB RAM | Standard VM capacity |
| **Concurrent Execs** | 4 concurrent commands | Excess commands return `429 quota_exceeded` |
| **Command Timeout** | 10 minutes max per exec | Enforce deadlines within this threshold |
| **Snapshots** | 10 max | Prune unused scan snapshots |
| **Storage Quota** | 200 GB | Shared across snapshots and files (counted hourly) |
| **Active API Keys** | 20 active keys | Track and rotate properly |
| **Machine Labels** | 32 key-value pairs per machine | Used for `scan_id`, `workspace_id`, expiry |
| **Public Ports** | 16 per machine | ShipSafe leaves public ports closed by default |

---

## 3. TypeScript SDK (`@insforge/instabox-sdk`)

### Installation & Initialization
```bash
npm install @insforge/instabox-sdk
```

```typescript
import { Sandbox, InstaboxAuthError } from '@insforge/instabox-sdk';

// Uses process.env.INSTABOX_API_KEY by default
const sbx = await Sandbox.create('universal', {
  apiKey: process.env.INSTABOX_API_KEY,
  requestTimeoutMs: 60_000,
  operationTimeoutMs: 600_000,
});
```

### Key SDK Methods
- **`Sandbox.create(template?, opts?)`**: Creates a new VM and waits for it to become ready.
- **`Sandbox.connect(sandboxId, opts?)`**: Reconnects to an existing machine (resumes if suspended).
- **`Sandbox.list(opts?)`**: Lists all machines owned by the account.
- **`Sandbox.kill(sandboxId, opts?)`**: Permanently terminates a machine and releases its disks.
- **`sbx.commands.run(command, opts?)`**: Executes a command inside the VM with timeout and environment options.
- **`sbx.createSnapshot(opts)`**: Takes a snapshot of the current VM state.
- **`Sandbox.listSnapshots()` / `Sandbox.deleteSnapshot(id)`**: Snapshot lifecycle management.

### API Scopes
- `machines:read`, `machines:write`, `machines:delete`
- `images:read`, `images:write`, `images:delete`

---

## 4. CLI Reference

### Installation & Auth
```bash
# One-shot interactive shell:
npx instabox@latest sh

# Global install:
curl -fsSL https://api.instabox.sh/install.sh | sh

# Authentication:
instabox login              # Interactive browser login
instabox login --device     # Headless/CI device code login
instabox whoami
instabox logout
```

### Machine Management Commands
```bash
# Templates & listing
instabox templates
instabox ls [--meta key=value]

# Create sandbox
instabox create --name <name> --template <template> [--timeout <duration>] [--auto-suspend <seconds>] [--meta key=value]

# Lifecycle
instabox start <name>
instabox suspend <name>    # Saves memory state and disk
instabox resume <name>     # Restores session instantly
instabox stop <name>
instabox rm <name>

# Execution & Files
instabox exec <name> -- <command>
instabox ssh <name>
instabox files <name> ...
```

---

## 5. ShipSafe Integration Rules & Invariants
1. **Pull Model (S-09)**: The VM must **never** call back to the ShipSafe control plane or hold ShipSafe credentials. Orchestration drives the VM via `@insforge/instabox-sdk`.
2. **Quota Management**: Free tier allows max 5 machines and 4 concurrent execs. The queue scheduler must strictly gate concurrency.
3. **Always Clean Up (S-19)**: Every scan workflow must terminate the machine on success, failure, timeout, or cancellation. Reconciler cron cleans up any orphaned VM.
4. **Tag Every Machine**: Always pass metadata (`scan_id`, `workspace_id`, `expires_at`) when calling `create`.
5. **Egress Firewall**: Enforce target-only outbound network access inside the VM to prevent scanning third-party unauthorized networks.
