#!/usr/bin/env python3
"""
ShipSafe Single-VM Worker Manager
Production-grade pull-based queue worker with slot concurrency, resource throttling,
process group containment, heartbeat renewal, and crash recovery.
"""

import argparse
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("worker_manager")

DEFAULT_CLOUDFLARE_URL = os.environ.get("CLOUDFLARE_URL", "http://127.0.0.1:3000")
DEFAULT_VM_SECRET = os.environ.get("VM_SECRET", "shipsafe-local-vm-secret")
WORKER_ID = os.environ.get("VM_WORKER_ID", f"instabox-{socket.gethostname()}")

MAX_STANDARD_SLOTS = int(os.environ.get("MAX_STANDARD_SLOTS", "2"))
MAX_DEEP_SLOTS = int(os.environ.get("MAX_DEEP_SLOTS", "1"))
MAX_PER_HOST = int(os.environ.get("MAX_PER_HOST", "1"))
HEARTBEAT_INTERVAL_SEC = 10.0
POLL_INTERVAL_MIN_SEC = 2.0
POLL_INTERVAL_MAX_SEC = 10.0

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_system_metrics() -> Dict[str, Any]:
    """Inspects Linux /proc/loadavg and /proc/meminfo to return CPU and RAM metrics."""
    metrics = {
        "load_1m": 0.0,
        "load_5m": 0.0,
        "mem_total_mb": 0,
        "mem_available_mb": 0,
        "can_run_deep": False,
    }
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            parts = f.read().split()
            metrics["load_1m"] = float(parts[0])
            metrics["load_5m"] = float(parts[1])
    except Exception as e:
        logger.debug("Failed to read /proc/loadavg: %s", e)

    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    metrics["mem_total_mb"] = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    metrics["mem_available_mb"] = int(line.split()[1]) // 1024
    except Exception as e:
        logger.debug("Failed to read /proc/meminfo: %s", e)

    # Deep scan gating: requires at least 1500 MB available and 1-minute load < 3.5
    metrics["can_run_deep"] = (
        metrics["mem_available_mb"] >= 1500 and metrics["load_1m"] < 3.5
    )
    return metrics


class CloudflareClient:
    """Authenticated outbound communication from the InstaBox VM to Cloudflare."""

    def __init__(self, base_url: str, secret: str, worker_id: str):
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self.worker_id = worker_id

    def _request(
        self, endpoint: str, data: Optional[Dict[str, Any]] = None, timeout: float = 15.0
    ) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}{endpoint}"
        body = json.dumps(data).encode("utf-8") if data is not None else None
        headers = {
            "Content-Type": "application/json",
            "X-VM-Token": self.secret,
            "X-Worker-ID": self.worker_id,
            "User-Agent": f"ShipSafe-WorkerManager/{self.worker_id}",
        }
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_body = resp.read().decode("utf-8")
                if not resp_body.strip():
                    return {}
                return json.loads(resp_body)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.warning("Cloudflare API error %s %s: %s", e.code, endpoint, err_body)
            if e.code == 404:
                return {"not_found": True}
            return None
        except Exception as e:
            logger.warning("Cloudflare network error on %s: %s", endpoint, e)
            return None

    def claim_job(
        self,
        available_standard: int,
        available_deep: int,
        active_hosts: List[str],
    ) -> Optional[Dict[str, Any]]:
        payload = {
            "workerId": self.worker_id,
            "availableStandardSlots": available_standard,
            "availableDeepSlots": available_deep,
            "activeHostnames": active_hosts,
        }
        res = self._request("/api/vm/jobs/claim", payload)
        if res and "job" in res:
            return res["job"]
        return None

    def send_heartbeat(
        self, job_id: str, stage: str, current_check: Optional[str] = None
    ) -> Dict[str, Any]:
        payload = {
            "workerId": self.worker_id,
            "stage": stage,
            "currentCheckId": current_check,
        }
        res = self._request(f"/api/vm/jobs/{job_id}/heartbeat", payload, timeout=10.0)
        return res or {}

    def send_events(self, job_id: str, events: List[Dict[str, Any]]) -> bool:
        if not events:
            return True
        res = self._request(f"/api/vm/jobs/{job_id}/events", {"events": events})
        return res is not None

    def complete_job(
        self,
        job_id: str,
        report: Dict[str, Any],
        score: Optional[int],
        coverage: Optional[int],
        findings: List[Dict[str, Any]],
    ) -> bool:
        payload = {
            "workerId": self.worker_id,
            "report": report,
            "score": score,
            "coverage": coverage,
            "findings": findings,
        }
        res = self._request(f"/api/vm/jobs/{job_id}/complete", payload, timeout=30.0)
        return res is not None and res.get("ok") is True

    def fail_job(
        self,
        job_id: str,
        error_code: str,
        error_message: str,
        retryable: bool = False,
    ) -> bool:
        payload = {
            "workerId": self.worker_id,
            "errorCode": error_code,
            "errorMessage": error_message,
            "retryable": retryable,
        }
        res = self._request(f"/api/vm/jobs/{job_id}/fail", payload, timeout=15.0)
        return res is not None

    def reap_stale(self) -> None:
        self._request("/api/vm/reap-stale", {"workerId": self.worker_id})


class ScanTask:
    """Encapsulates a running scan job on the VM."""

    def __init__(self, job: Dict[str, Any], client: CloudflareClient):
        self.job = job
        self.job_id = job["id"]
        self.url = job["url"]
        self.mode = job.get("mode", "standard")
        self.hostname = job.get("hostname", "")
        self.client = client
        self.dir = f"/tmp/shipsafe-run-{self.job_id}"
        self.container_name = f"shipsafe-{self.job_id}"
        self.process: Optional[subprocess.Popen] = None
        self.aborted = False
        self.cancelled = False
        self.events_offset = 0

    def cleanup(self) -> None:
        """Kills any remaining subprocesses and removes run artifacts."""
        if self.process and self.process.poll() is None:
            try:
                pgid = os.getpgid(self.process.pid)
                os.killpg(pgid, signal.SIGKILL)
                logger.info("[%s] Terminated process group %d", self.job_id, pgid)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

        # Cleanup docker container if spawned
        try:
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except Exception:
            pass

        # Remove tempdir
        if os.path.exists(self.dir):
            try:
                shutil.rmtree(self.dir, ignore_errors=True)
            except Exception as e:
                logger.warning("[%s] Failed to rmtree %s: %s", self.job_id, self.dir, e)

    def prepare_workspace(self) -> None:
        os.makedirs(self.dir, exist_ok=True, mode=0o700)
        # Copy engine scripts from packages/sandbox/src
        for filename in [
            "baseline.py",
            "security_engine.py",
            "security_registry.py",
            "security_registry.json",
            "security_dns.py",
        ]:
            src = os.path.join(SCRIPT_DIR, filename)
            dst = os.path.join(self.dir, filename)
            if os.path.exists(src):
                shutil.copyfile(src, dst)

        # Write input.json
        input_data = {
            "url": self.url,
            "mode": self.mode,
            "authorization": self.job.get("authorization"),
        }
        with open(os.path.join(self.dir, "input.json"), "w", encoding="utf-8") as f:
            json.dump(input_data, f)

    def heartbeat_loop(self) -> None:
        """Periodic heartbeat thread updating Cloudflare and detecting cancellation."""
        events_file = os.path.join(self.dir, "events.jsonl")
        while not self.aborted and self.process and self.process.poll() is None:
            time.sleep(HEARTBEAT_INTERVAL_SEC)
            if self.aborted:
                break

            # 1. Check for cancellation & renew lease
            res = self.client.send_heartbeat(self.job_id, stage="RUNNING")
            if res.get("cancelled") is True:
                logger.info("[%s] Job was cancelled by user; stopping process", self.job_id)
                self.cancelled = True
                self.cleanup()
                break

            # 2. Ingest & stream incremental events
            if os.path.exists(events_file):
                try:
                    with open(events_file, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(self.events_offset)
                        new_lines = f.readlines()
                        self.events_offset = f.tell()

                    events_to_send = []
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                            events_to_send.append(ev)
                        except json.JSONDecodeError:
                            continue

                    if events_to_send:
                        self.client.send_events(self.job_id, events_to_send)
                except Exception as e:
                    logger.debug("[%s] Error reading events.jsonl: %s", self.job_id, e)

    def execute(self) -> None:
        logger.info("[%s] Starting scan for %s (mode: %s)", self.job_id, self.url, self.mode)
        self.prepare_workspace()

        # Build execution command with Linux prlimit containment
        engine_script = os.path.join(self.dir, "security_engine.py")
        if not os.path.exists(engine_script):
            engine_script = os.path.join(self.dir, "baseline.py")

        if self.mode == "deep":
            # Deep Scan: 1024 MB RAM, 120s CPU, 128 processes, 150s timeout
            cmd = [
                "prlimit",
                "--as=1073741824",
                "--cpu=120",
                "--nproc=128",
                "--fsize=5242880",
                "--nofile=128",
                "--",
                "timeout",
                "150s",
                sys.executable,
                "-u",
                engine_script,
            ]
            timeout_sec = 160
        else:
            # Standard Scan: 512 MB RAM, 45s CPU, 128 processes, 50s timeout
            cmd = [
                "prlimit",
                "--as=536870912",
                "--cpu=45",
                "--nproc=128",
                "--fsize=1048576",
                "--nofile=128",
                "--",
                "timeout",
                "50s",
                sys.executable,
                "-u",
                engine_script,
            ]
            timeout_sec = 60

        events_path = os.path.join(self.dir, "events.jsonl")
        stderr_path = os.path.join(self.dir, "stderr.log")
        input_path = os.path.join(self.dir, "input.json")

        with open(input_path, "rb") as stdin_f, open(events_path, "wb") as stdout_f, open(
            stderr_path, "wb"
        ) as stderr_f:
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdin=stdin_f,
                    stdout=stdout_f,
                    stderr=stderr_f,
                    cwd=self.dir,
                    env={
                        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                        "HOME": "/tmp",
                        "LANG": "C.UTF-8",
                        "SHUTDOWN_CLEANUP": "1",
                    },
                    start_new_session=True,  # Isolate in dedicated process group
                )
            except Exception as e:
                logger.error("[%s] Failed to spawn process: %s", self.job_id, e)
                self.client.fail_job(
                    self.job_id,
                    error_code="SPAWN_FAILED",
                    error_message=str(e),
                    retryable=False,
                )
                self.cleanup()
                return

        # Start heartbeat in separate thread
        hb_thread = threading.Thread(
            target=self.heartbeat_loop,
            name=f"hb-{self.job_id}",
            daemon=True,
        )
        hb_thread.start()

        # Wait for completion or timeout
        try:
            exit_code = self.process.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            logger.warning("[%s] Process timed out after %ds", self.job_id, timeout_sec)
            self.aborted = True
            self.cleanup()
            self.client.fail_job(
                self.job_id,
                error_code="TIMEOUT",
                error_message="The scan exceeded its execution budget and was terminated.",
                retryable=False,
            )
            return

        self.aborted = True
        hb_thread.join(timeout=2.0)

        if self.cancelled:
            logger.info("[%s] Scan cancelled cleanly", self.job_id)
            self.cleanup()
            return

        # Read stderr
        stderr_content = ""
        if os.path.exists(stderr_path):
            with open(stderr_path, "r", encoding="utf-8", errors="replace") as f:
                stderr_content = f.read().strip()

        # Check for report in events.jsonl
        report_data = None
        if os.path.exists(events_path):
            with open(events_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                        if parsed.get("type") == "report":
                            report_data = parsed
                    except json.JSONDecodeError:
                        continue

        if not report_data:
            logger.error(
                "[%s] Scan exited with code %d but produced no report. Stderr: %s",
                self.job_id,
                exit_code,
                stderr_content[:500],
            )
            retryable = exit_code in (137, 143)  # OOM or SIGTERM may be transient
            self.client.fail_job(
                self.job_id,
                error_code="NO_REPORT",
                error_message=stderr_content[:500] or "No report was produced by the scanner.",
                retryable=retryable,
            )
            self.cleanup()
            return

        # Calculate score and coverage
        manifest = report_data.get("manifest", {})
        checks = report_data.get("checks", [])
        findings = report_data.get("findings", [])

        passed_or_obs = [c for c in checks if c.get("status") in ("passed", "observation")]
        applicable = [c for c in checks if c.get("status") in ("passed", "observation", "failed")]

        score = (
            int(round((len(passed_or_obs) / len(applicable)) * 100))
            if applicable
            else None
        )
        coverage = (
            int(round((len(passed_or_obs) / len(checks)) * 100))
            if checks
            else 0
        )

        logger.info(
            "[%s] Scan completed successfully. Checks: %d, Findings: %d, Score: %s",
            self.job_id,
            len(checks),
            len(findings),
            score,
        )

        success = self.client.complete_job(
            self.job_id,
            report=report_data,
            score=score,
            coverage=coverage,
            findings=findings,
        )
        if not success:
            logger.error("[%s] Failed to record completed report with Cloudflare!", self.job_id)

        self.cleanup()


class WorkerManager:
    """Manages scan slots, host concurrency, and the pull loop on the single VM."""

    def __init__(
        self,
        cf_url: str = DEFAULT_CLOUDFLARE_URL,
        secret: str = DEFAULT_VM_SECRET,
        worker_id: str = WORKER_ID,
        max_standard: int = MAX_STANDARD_SLOTS,
        max_deep: int = MAX_DEEP_SLOTS,
    ):
        self.client = CloudflareClient(cf_url, secret, worker_id)
        self.max_standard = max_standard
        self.max_deep = max_deep
        self.active_tasks: Dict[str, ScanTask] = {}
        self.lock = threading.Lock()
        self.running = True

    def boot_recovery(self) -> None:
        """Sweeps orphaned directories and kills stale processes on startup."""
        logger.info("Running startup boot recovery...")
        for entry in os.listdir("/tmp"):
            if entry.startswith("shipsafe-run-"):
                p = os.path.join("/tmp", entry)
                try:
                    shutil.rmtree(p, ignore_errors=True)
                    logger.info("Removed leftover run dir: %s", p)
                except Exception:
                    pass

        # Cleanup stray containers
        try:
            res = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=shipsafe-", "-q"],
                stdout=subprocess.PIPE,
                text=True,
                check=False,
            )
            cids = res.stdout.strip().split()
            if cids:
                subprocess.run(["docker", "rm", "-f"] + cids, check=False)
                logger.info("Removed %d stale Docker containers", len(cids))
        except Exception:
            pass

        # Notify Cloudflare to reap stale jobs
        try:
            self.client.reap_stale()
        except Exception as e:
            logger.warning("Reap stale call on startup failed: %s", e)

    def get_slot_availability(self) -> tuple[int, int, List[str]]:
        """Calculates available slots taking active tasks and system resource bounds into account."""
        with self.lock:
            active_standard = sum(1 for t in self.active_tasks.values() if t.mode != "deep")
            active_deep = sum(1 for t in self.active_tasks.values() if t.mode == "deep")
            active_hosts = [t.hostname for t in self.active_tasks.values() if t.hostname]

        metrics = get_system_metrics()

        # Adaptive slot auto-tuning based on real-time load.
        load_1m = float(metrics.get("load_1m", 0.0))
        mem_available_mb = int(metrics.get("mem_available_mb", 0))
        if load_1m >= 3.0 or mem_available_mb < 2048:
            effective_max_standard = min(self.max_standard, 2)
        elif load_1m < 2.0 and mem_available_mb >= 4096:
            effective_max_standard = max(self.max_standard, 4)
            effective_max_standard = min(effective_max_standard, 4)
        else:
            effective_max_standard = self.max_standard

        avail_standard = max(0, effective_max_standard - active_standard)

        # Deep scan is permitted only if active deep is 0, active standard <= 1, and system RAM permits.
        avail_deep = 0
        if active_deep < self.max_deep and active_standard <= 1 and mem_available_mb >= 1500:
            avail_deep = 1

        return avail_standard, avail_deep, active_hosts

    def run_task_wrapper(self, task: ScanTask) -> None:
        try:
            task.execute()
        finally:
            with self.lock:
                self.active_tasks.pop(task.job_id, None)
            logger.info("Freed worker slot for job %s", task.job_id)

    def shutdown(self, signum: int, frame: Any) -> None:
        logger.info("Received termination signal (%d). Shutting down worker manager...", signum)
        self.running = False
        with self.lock:
            for task in list(self.active_tasks.values()):
                task.cleanup()

    def start(self) -> None:
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

        self.boot_recovery()
        logger.info(
            "ShipSafe Single-VM Worker Manager online. Worker ID: %s. Slots: [Standard: %d, Deep: %d]",
            self.client.worker_id,
            self.max_standard,
            self.max_deep,
        )

        poll_interval = POLL_INTERVAL_MIN_SEC
        last_reap = time.time()

        while self.running:
            try:
                # Periodic stale check every 60s
                if time.time() - last_reap > 60:
                    self.client.reap_stale()
                    last_reap = time.time()

                avail_std, avail_dp, active_hosts = self.get_slot_availability()

                if avail_std == 0 and avail_dp == 0:
                    # All slots full or system throttled; wait briefly
                    time.sleep(1.0)
                    continue

                job = self.client.claim_job(avail_std, avail_dp, active_hosts)

                if job and "id" in job:
                    poll_interval = POLL_INTERVAL_MIN_SEC  # Fast polling when queue is active
                    task = ScanTask(job, self.client)
                    with self.lock:
                        self.active_tasks[task.job_id] = task

                    t = threading.Thread(
                        target=self.run_task_wrapper,
                        args=(task,),
                        name=f"worker-{task.job_id}",
                        daemon=True,
                    )
                    t.start()
                else:
                    # No job claimed; apply backoff
                    time.sleep(poll_interval)
                    poll_interval = min(POLL_INTERVAL_MAX_SEC, poll_interval * 1.5)

            except Exception as e:
                logger.error("Exception in worker manager main loop: %s", e, exc_info=True)
                time.sleep(3.0)

        logger.info("Worker manager stopped.")


def main():
    parser = argparse.ArgumentParser(description="ShipSafe Single-VM Worker Manager")
    parser.add_argument("--cf-url", default=DEFAULT_CLOUDFLARE_URL, help="Cloudflare Base URL")
    parser.add_argument("--secret", default=DEFAULT_VM_SECRET, help="Shared VM Worker Secret")
    parser.add_argument("--worker-id", default=WORKER_ID, help="Unique Worker ID")
    parser.add_argument("--standard-slots", type=int, default=MAX_STANDARD_SLOTS)
    parser.add_argument("--deep-slots", type=int, default=MAX_DEEP_SLOTS)
    args = parser.parse_args()

    manager = WorkerManager(
        cf_url=args.cf_url,
        secret=args.secret,
        worker_id=args.worker_id,
        max_standard=args.standard_slots,
        max_deep=args.deep_slots,
    )
    manager.start()


if __name__ == "__main__":
    main()
