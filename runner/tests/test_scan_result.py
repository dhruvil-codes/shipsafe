"""Offline shape tests for scan_result.json (stdlib only, no network).

Run: python3 -m unittest discover -s runner/tests -v   (from repo root: -s runner/tests)
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

RUNNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(RUNNER_ROOT, "scanner.py")
FIXTURE = os.path.join(RUNNER_ROOT, "tests", "fixtures", "scan_result.json")

VALID_STATUSES = {"passed", "failed", "skipped"}


def validate_tool_result(tr, ctx=""):
    assert isinstance(tr, dict), f"{ctx}: ToolResult must be an object"
    for field in ("tool", "toolVersion", "status", "startedAt", "endedAt",
                  "durationMs", "checksAttempted", "evidence"):
        assert field in tr, f"{ctx}: missing field {field!r}"
    assert isinstance(tr["tool"], str) and tr["tool"], f"{ctx}: tool must be non-empty"
    assert tr["status"] in VALID_STATUSES, f"{ctx}: bad status {tr['status']!r}"
    assert isinstance(tr["durationMs"], int) and tr["durationMs"] >= 0, f"{ctx}: bad durationMs"
    assert isinstance(tr["checksAttempted"], int) and tr["checksAttempted"] >= 0, f"{ctx}: bad checksAttempted"
    assert isinstance(tr["evidence"], dict), f"{ctx}: evidence must be an object"
    # Evidence-first: failed tools must carry evidence or an error.
    if tr["status"] == "failed":
        assert tr["evidence"] or tr.get("error"), f"{ctx}: failed tool without evidence/error"
    # No credit for what did not run: skipped tools must not claim checks.
    if tr["status"] == "skipped":
        assert tr["checksAttempted"] == 0, f"{ctx}: skipped tool must have checksAttempted=0"


def validate_scan_result(doc):
    assert isinstance(doc, dict), "top level must be an object"
    assert isinstance(doc.get("target"), str) and doc["target"], "target must be non-empty"
    assert isinstance(doc.get("scannedAt"), str), "scannedAt must be a string"
    assert isinstance(doc.get("tools"), list) and doc["tools"], "tools must be a non-empty list"
    for tr in doc["tools"]:
        validate_tool_result(tr, ctx=tr.get("tool", "?"))


class TestFixtureShape(unittest.TestCase):
    def test_fixture_matches_toolresult_schema(self):
        with open(FIXTURE, encoding="utf-8") as fh:
            doc = json.load(fh)
        validate_scan_result(doc)
        tools = {t["tool"] for t in doc["tools"]}
        self.assertTrue({"tls-probe", "headers", "sensitive-files", "ports"} <= tools)


class TestScannerOffline(unittest.TestCase):
    def test_scanner_writes_valid_output_against_unreachable_target(self):
        # Unreachable/reserved target: every tool must record skipped/failed
        # with evidence — never crash, never invent a pass without checks.
        with tempfile.TemporaryDirectory() as outdir:
            target = "http://127.0.0.1:9"
            rc = subprocess.run(
                [sys.executable, SCANNER, target, outdir],
                capture_output=True, text=True, timeout=120,
            ).returncode
            self.assertEqual(rc, 0)
            with open(os.path.join(outdir, "scan_result.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
            validate_scan_result(doc)
            self.assertEqual(doc["target"], target)
            self.assertTrue(os.path.exists(os.path.join(outdir, "scan_result.sha256")))


if __name__ == "__main__":
    unittest.main()
