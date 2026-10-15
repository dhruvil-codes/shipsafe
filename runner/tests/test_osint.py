"""Offline tests for the OSINT engine (stdlib only, no network).

Covers: domain extraction/validation, ToolResult shape of osint_result.json,
missing-binary behavior (ran=false, zero invented output), invalid-target
handling, and orchestration plumbing with stub binaries standing in for the
real tools (the stubs only verify argv/stdout plumbing — all finding logic
is tested against real-shaped fixtures in packages/adapters/tests/osint).

Run: python -m unittest discover -s runner/tests -v
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

RUNNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(RUNNER_ROOT, "osint_engine.py")
FIXTURES = os.path.join(RUNNER_ROOT, "tests", "fixtures")

sys.path.insert(0, RUNNER_ROOT)
import osint_engine as engine  # noqa: E402


def validate_osint_result(doc):
    assert isinstance(doc, dict), "top level must be an object"
    assert doc.get("tool") == "osint-suite", "tool must be osint-suite"
    for field in ("toolVersion", "status", "startedAt", "endedAt",
                  "durationMs", "checksAttempted", "evidence"):
        assert field in doc, f"missing field {field!r}"
    assert doc["status"] in ("passed", "failed", "skipped")
    assert isinstance(doc["durationMs"], int) and doc["durationMs"] >= 0
    assert isinstance(doc["checksAttempted"], int) and doc["checksAttempted"] >= 0
    ev = doc["evidence"]
    assert isinstance(ev, dict), "evidence must be an object"
    for key in ("subfinder", "httpx", "subzy", "checkdmarc", "whois"):
        assert key in ev, f"evidence missing section {key!r}"
        assert isinstance(ev[key], dict)
        assert "ran" in ev[key], f"section {key} missing ran flag"


class TestExtractDomain(unittest.TestCase):
    def test_bare_domain(self):
        self.assertEqual(engine.extract_domain("example.com"), "example.com")

    def test_url_forms(self):
        self.assertEqual(engine.extract_domain("https://Example.COM:443/a?b=c"), "example.com")
        self.assertEqual(engine.extract_domain("http://staging.example.com"), "staging.example.com")

    def test_rejects_garbage(self):
        for bad in ("", "http://", "not a domain!", "http:///x", "a" * 300 + ".com"):
            with self.assertRaises(ValueError, msg=bad):
                engine.extract_domain(bad)


class TestEngineOffline(unittest.TestCase):
    def test_no_binaries_records_ran_false_and_writes_output(self):
        # Empty PATH: every stage must record ran=false with an error, the
        # consolidated status must be failed with checksAttempted=0, and the
        # runner must still write valid output (never crash, never invent).
        with tempfile.TemporaryDirectory() as outdir:
            env = dict(os.environ, PATH=tempfile.gettempdir())
            rc = subprocess.run(
                [sys.executable, ENGINE, "example.com", outdir],
                capture_output=True, text=True, timeout=120, env=env,
            ).returncode
            self.assertEqual(rc, 0)
            with open(os.path.join(outdir, "osint_result.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
            validate_osint_result(doc)
            self.assertEqual(doc["status"], "failed")
            self.assertEqual(doc["checksAttempted"], 0)
            for key in ("subfinder", "httpx", "subzy", "checkdmarc", "whois"):
                self.assertFalse(doc["evidence"][key]["ran"])
                self.assertIn("error", doc["evidence"][key])
            self.assertTrue(os.path.exists(os.path.join(outdir, "osint_result.sha256")))

    def test_invalid_target_emits_failed_result(self):
        with tempfile.TemporaryDirectory() as outdir:
            rc = subprocess.run(
                [sys.executable, ENGINE, "not a domain!", outdir],
                capture_output=True, text=True, timeout=120,
            ).returncode
            self.assertEqual(rc, 0)
            with open(os.path.join(outdir, "osint_result.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["status"], "failed")
            self.assertEqual(doc["checksAttempted"], 0)

    def test_plumbing_with_stub_binaries(self):
        # Stub executables on PATH verify argv/stdout plumbing end to end:
        # stub whois emits a real-shaped record, stub checkdmarc emits JSON.
        if os.name != "posix":
            self.skipTest("stub executables require POSIX exec")
        with tempfile.TemporaryDirectory() as bindir, tempfile.TemporaryDirectory() as outdir:
            with open(os.path.join(FIXTURES, "osint_whois.txt"), encoding="utf-8") as fh:
                whois_text = fh.read()
            with open(os.path.join(FIXTURES, "osint_checkdmarc_none.json"), encoding="utf-8") as fh:
                dmarc_json = fh.read()
            stub_whois = os.path.join(bindir, "whois")
            with open(stub_whois, "w", encoding="utf-8") as fh:
                fh.write("#!/usr/bin/env python3\nimport sys\n"
                         f"sys.stdout.write({whois_text!r})\n")
            stub_dmarc = os.path.join(bindir, "checkdmarc")
            with open(stub_dmarc, "w", encoding="utf-8") as fh:
                fh.write("#!/usr/bin/env python3\nimport sys\n"
                         f"sys.stdout.write({dmarc_json!r})\n")
            for stub in (stub_whois, stub_dmarc):
                os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=bindir + os.pathsep + tempfile.gettempdir())
            rc = subprocess.run(
                [sys.executable, ENGINE, "example-test.invalid", outdir],
                capture_output=True, text=True, timeout=180, env=env,
            ).returncode
            self.assertEqual(rc, 0)
            with open(os.path.join(outdir, "osint_result.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
            validate_osint_result(doc)
            # PATH exposes python but not the real tools: only the two stubs ran.
            self.assertTrue(doc["evidence"]["whois"]["ran"])
            self.assertTrue(doc["evidence"]["checkdmarc"]["ran"])
            self.assertEqual(doc["evidence"]["whois"]["registrar"], "Example Registrar, Inc.")
            self.assertEqual(doc["evidence"]["checkdmarc"]["parsed"]["dmarc"]["policy"], "none")
            self.assertEqual(doc["evidence"]["checkdmarc"]["argv"], ["checkdmarc", "-f", "json", "example-test.invalid"])
            self.assertFalse(doc["evidence"]["subfinder"]["ran"])
            self.assertEqual(doc["status"], "passed")
            self.assertEqual(doc["checksAttempted"], 2)


if __name__ == "__main__":
    unittest.main()
