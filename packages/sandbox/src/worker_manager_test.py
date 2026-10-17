#!/usr/bin/env python3
import json
import os
import signal
import sys
import unittest
from unittest.mock import MagicMock, patch

from worker_manager import (
    CloudflareClient,
    ScanTask,
    WorkerManager,
    get_system_metrics,
)


class WorkerManagerTest(unittest.TestCase):
    def test_system_metrics(self):
        metrics = get_system_metrics()
        self.assertIn("load_1m", metrics)
        self.assertIn("mem_available_mb", metrics)
        self.assertIn("can_run_deep", metrics)
        self.assertIsInstance(metrics["can_run_deep"], bool)

    def test_slot_availability_standard_slots(self):
        manager = WorkerManager(max_standard=2, max_deep=1)
        with patch("worker_manager.get_system_metrics", return_value={"load_1m": 0.5, "mem_available_mb": 4000, "can_run_deep": True}):
            std, deep, hosts = manager.get_slot_availability()
            self.assertEqual(std, 2)
            self.assertEqual(deep, 1)
            self.assertEqual(hosts, [])

    def test_slot_availability_host_and_resource_bounds(self):
        manager = WorkerManager(max_standard=2, max_deep=1)
        fake_task = MagicMock()
        fake_task.mode = "standard"
        fake_task.hostname = "example.com"
        manager.active_tasks["test-1"] = fake_task

        # With 1 standard running, deep scan can run if resources permit
        with patch("worker_manager.get_system_metrics", return_value={"load_1m": 0.5, "mem_available_mb": 2000, "can_run_deep": True}):
            std, deep, hosts = manager.get_slot_availability()
            self.assertEqual(std, 1)
            self.assertEqual(deep, 1)
            self.assertEqual(hosts, ["example.com"])

        # If system is under high load or low RAM, deep scan is throttled
        with patch("worker_manager.get_system_metrics", return_value={"load_1m": 5.0, "mem_available_mb": 500, "can_run_deep": False}):
            std, deep, hosts = manager.get_slot_availability()
            self.assertEqual(std, 1)
            self.assertEqual(deep, 0)

    def test_cloudflare_client_claim_job(self):
        client = CloudflareClient("http://fake-cf.invalid", "test-secret", "worker-1")
        with patch.object(client, "_request", return_value={"job": {"id": "scn_123", "url": "https://example.com", "mode": "standard"}}):
            job = client.claim_job(1, 0, ["busy.com"])
            self.assertIsNotNone(job)
            self.assertEqual(job["id"], "scn_123")

    def test_cloudflare_client_complete_job(self):
        client = CloudflareClient("http://fake-cf.invalid", "test-secret", "worker-1")
        with patch.object(client, "_request", return_value={"ok": True}):
            success = client.complete_job("scn_123", {"type": "report"}, 85, 90, [])
            self.assertTrue(success)

    def test_scan_task_cleanup(self):
        fake_job = {"id": "scn_fake_999", "url": "https://example.com", "mode": "standard"}
        client = MagicMock()
        task = ScanTask(fake_job, client)
        task.dir = "/tmp/shipsafe-test-cleanup-dir"
        os.makedirs(task.dir, exist_ok=True)
        self.assertTrue(os.path.exists(task.dir))

        task.cleanup()
        self.assertFalse(os.path.exists(task.dir))


if __name__ == "__main__":
    unittest.main()
