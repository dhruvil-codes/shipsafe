# ShipSafe Single-VM Worker Manager Operational Guide

This document details the configuration, management, resource tuning, and disaster recovery procedures for the **Single-VM Scan Worker Manager** running on your InstaBox cloud VM.

---

## 1. Hardware Profile & Resource Capacity

The production worker manager runs on a single InstaBox micro-VM with the following verified hardware specifications:

| Resource | Specification | Allocation / Boundary |
|---|---|---|
| **vCPU** | 4 Cores (x86_64) | 2 Cores for Standard Scans, 1.5 Cores for Deep Scan |
| **System RAM** | 8 GB Total (7.3 GB free) | 256 MiB per Standard Scan, 1024 MiB for Deep Scan |
| **Disk Storage** | 16 GB SSD (5.6 GB free) | Ephemeral `/tmp/shipsafe-run-*` with automatic cleanup |
| **Operating System** | Debian 13 (Trixie) Linux | Kernel 6.12+ with cgroups v2, util-linux `prlimit` |
| **Runtimes** | Python 3.13.5 & Docker 29.8 | Standard library only; zero pip dependencies |
| **Pre-pulled Images** | Nuclei 3.11.1, ZAP 2.17.0 | Stored locally in Docker cache; zero network pull delay |

---

## 2. Worker Concurrency Model

The single VM worker manager enforces strict slot limits to prevent resource exhaustion and ensure predictable latency:

```
┌─────────────────────────────────────────────────────────────┐
│                    Single InstaBox VM                       │
│                                                             │
│  ┌───────────────────────┐       ┌───────────────────────┐  │
│  │ Standard Scan Slot 1  │       │ Standard Scan Slot 2  │  │
│  │ (Max 256 MiB RAM,     │       │ (Max 256 MiB RAM,     │  │
│  │  45s CPU limit)       │       │  45s CPU limit)       │  │
│  └───────────────────────┘       └───────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │               Conditional Deep Scan Slot              │  │
│  │ (Max 1024 MiB RAM, 120s CPU limit, Docker isolation)  │  │
│  │ Gated by: RAM >= 1.5GB Free & Active Standard <= 1    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Invariant: MAX 1 CONCURRENT SCAN PER TARGET HOSTNAME       │
└─────────────────────────────────────────────────────────────┘
```

1. **Standard Scans (Max 2 Concurrent)**:
   - Non-intrusive baseline checks.
   - Pinned public IP resolution, SSL inspection, HTTP headers, cookie hygiene, DNS CAA/SPF/DMARC.
   - Bounded by `prlimit --as=268435456 --cpu=45 --nproc=32 --nofile=64`.
   - Timeout: 50s.

2. **Deep Scan (Max 1 Conditional Concurrent)**:
   - Authorized active scanning (vetted Nuclei templates, OWASP ZAP baseline).
   - Only claimed if:
     - Free RAM >= 1.5 GB.
     - 1-minute system load average < 3.5.
     - Active standard scans <= 1.
   - Bounded by `prlimit --as=1073741824 --cpu=120 --nproc=64 --nofile=128`.
   - Timeout: 150s.

3. **Per-Host Concurrency (Max 1 Active)**:
   - The worker manager tracks currently active hostnames (`activeHostnames`).
   - Multiple scan submissions for the same domain are queued and processed sequentially, preventing target rate-limiting or accidental DoS.

---

## 3. Installation & Systemd Service

### Option A: Manual Interactive Run
```bash
export CLOUDFLARE_URL="https://your-shipsafe-worker.workers.dev"
export VM_SECRET="your_shared_vm_worker_secret"
export VM_WORKER_ID="instabox-primary-01"

python3 packages/sandbox/src/worker_manager.py
```

### Option B: Persistent Systemd Daemon (Recommended)

1. Create the systemd service file at `/etc/systemd/system/shipsafe-worker.service`:

```ini
[Unit]
Description=ShipSafe Single-VM Scan Worker Manager
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/shipsafe
Environment="CLOUDFLARE_URL=https://your-shipsafe-worker.workers.dev"
Environment="VM_SECRET=your_shared_vm_worker_secret"
Environment="VM_WORKER_ID=instabox-primary-01"
Environment="MAX_STANDARD_SLOTS=2"
Environment="MAX_DEEP_SLOTS=1"
ExecStart=/usr/bin/python3 packages/sandbox/src/worker_manager.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

2. Enable and start the service:
```bash
systemctl daemon-reload
systemctl enable shipsafe-worker
systemctl start shipsafe-worker
```

---

## 4. Monitoring & Operational Logs

View real-time worker manager logs:
```bash
journalctl -u shipsafe-worker -f -o cat
```

Sample output:
```
2026-10-17 13:45:00 [INFO] [MainThread] Running startup boot recovery...
2026-10-17 13:45:01 [INFO] [MainThread] ShipSafe Single-VM Worker Manager online. Worker ID: instabox-primary-01. Slots: [Standard: 2, Deep: 1]
2026-10-17 13:45:10 [INFO] [MainThread] Claimed job scn_8f2b3e41 for https://example.com (mode: standard)
2026-10-17 13:45:10 [INFO] [worker-scn_8f2b3e41] Starting scan for https://example.com (mode: standard)
2026-10-17 13:45:22 [INFO] [worker-scn_8f2b3e41] Scan completed successfully. Checks: 40, Findings: 3, Score: 88
2026-10-17 13:45:23 [INFO] [worker-scn_8f2b3e41] Freed worker slot for job scn_8f2b3e41
```

---

## 5. Crash Recovery & Resilience

The worker manager includes robust, automated recovery mechanisms:

1. **Boot Sweep Recovery**:
   On every startup or restart, `boot_recovery()` automatically:
   - Scans `/tmp` for any lingering `shipsafe-run-*` directories and removes them.
   - Cleans up any orphaned Docker containers (`docker rm -f $(docker ps -a -q --filter name=shipsafe-)`).
   - Calls `POST /api/vm/reap-stale` on Cloudflare to reclaim or fail abandoned jobs.

2. **Visibility Timeout & Dead-Letter Handling**:
   - Each claimed job has a 45-second visibility lease on Cloudflare D1.
   - The worker renews this lease every 10 seconds while the scan is running.
   - If the VM crashes or loses connectivity, the lease expires. Cloudflare's scheduled reaper re-queues the job with exponential backoff (up to 2 retries) or marks it `EXPIRED`.

3. **Subprocess Group Containment**:
   - Every scan runs inside a dedicated process group (`start_new_session=True`).
   - If a scan times out or is cancelled by the user, `os.killpg(pgid, signal.SIGKILL)` terminates the entire process tree (including all subprocesses, Python scripts, and child utilities), preventing background zombie processes.
