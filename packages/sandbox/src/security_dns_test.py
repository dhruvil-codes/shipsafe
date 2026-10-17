import subprocess
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import security_dns


def output(host, kind, *records, status="NOERROR", flags="qr rd ra"):
    return (";; ->>HEADER<<- opcode: QUERY, status: " + status + ", id: 1\n;; flags: " + flags + "; QUERY: 1, ANSWER: 1\n" + "\n".join(f"{host}. 300 IN {kind} {record}" for record in records)).encode()


class DnsTests(unittest.TestCase):
    def collect(self, answers):
        def run(argv, **kwargs):
            host, kind = argv[-2:]
            return SimpleNamespace(returncode=0, stdout=answers.get((host, kind), output(host, kind)))
        with patch("security_dns.subprocess.run", side_effect=run) as mocked:
            result = security_dns.observe_dns("my-app.com", time.monotonic() + 10)
        return result, mocked

    def test_fixed_argv_and_private_evidence(self):
        answers = {("my-app.com", "CAA"): output("my-app.com", "CAA", '0 issue "ca.vendor.com"'),
                   ("my-app.com", "TXT"): output("my-app.com", "TXT", '"v=spf1 include:private.vendor.com -all"', '"secret=DO_NOT_LEAK"'),
                   ("_dmarc.my-app.com", "TXT"): output("_dmarc.my-app.com", "TXT", '"v=DMARC1; p=reject; rua=mailto:private@my-app.com"'),
                   ("my-app.com", "MX"): output("my-app.com", "MX", "10 private.mail.com.")}
        result, mocked = self.collect(answers)
        self.assertTrue(all(status == "PASS" for status, evidence in result.values()))
        for secret in ("private", "DO_NOT_LEAK", "ca.vendor.com", "mailto"):
            self.assertNotIn(secret, str(result))
        self.assertEqual(mocked.call_count, 4)
        for call in mocked.call_args_list:
            self.assertEqual(call.args[0][0], "/usr/bin/dig")
            self.assertNotIn("shell", call.kwargs)
            self.assertEqual(call.kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C"})
            self.assertLessEqual(call.kwargs["timeout"], 3)

    def test_each_dns_record_emits_a_structured_lifecycle_pair(self):
        events = []
        with patch("security_dns.subprocess.run", side_effect=lambda argv, **kwargs: SimpleNamespace(returncode=0, stdout=output(argv[-2], argv[-1]))):
            result = security_dns.observe_dns("my-app.com", time.monotonic() + 10, emit=events.append)
        self.assertEqual(set(result), {"dns-caa", "dns-spf", "dns-dmarc", "dns-mx"})
        self.assertEqual(sum(event["stage"] == "check" for event in events), 4)
        self.assertEqual(sum(event["stage"] == "check_done" for event in events), 4)
        for check in result:
            start = next(i for i, event in enumerate(events) if event["stage"] == "check" and event["checkId"] == check)
            done = next(i for i, event in enumerate(events) if event["stage"] == "check_done" and event["checkId"] == check)
            self.assertLess(start, done)
            self.assertIn(events[done]["status"], ("passed", "observation", "skipped"))
            self.assertTrue(events[start]["timestamp"].endswith("Z"))

    def test_absence_informational_and_inheritance_unassessed(self):
        result, _ = self.collect({})
        self.assertTrue(all(status == "WARNING" for status, evidence in result.values()))
        self.assertIn("inheritance was not assessed", result["dns-dmarc"][1])
        self.assertIn("informational", result["dns-caa"][1])

    def test_errors_truncation_and_size_never_pass(self):
        for content in (output("my-app.com", "TXT", status="SERVFAIL"), output("my-app.com", "TXT", flags="qr tc"), b"x" * 65537):
            with patch("security_dns.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=content)):
                result = security_dns.observe_dns("my-app.com", time.monotonic() + 10)
                self.assertTrue(all(status == "NOT_TESTED" for status, evidence in result.values()))
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("dig", 3)):
            with patch("security_dns.subprocess.run", side_effect=error):
                result = security_dns.observe_dns("my-app.com", time.monotonic() + 10)
                self.assertTrue(all(status == "NOT_TESTED" for status, evidence in result.values()))

    def test_spf_multiple_malformed_and_unrestricted_all(self):
        for records in [('"v=spf1 -all"', '"v=spf1 ~all"'), ('"v=spf1 made-up"',), ('"v=spf1 +all"',)]:
            result, _ = self.collect({("my-app.com", "TXT"): output("my-app.com", "TXT", *records)})
            self.assertEqual(result["dns-spf"][0], "WARNING")

    def test_dmarc_none_and_duplicate_tags(self):
        for value in ('"v=DMARC1; p=none"', '"v=DMARC1; p=reject; p=reject"', '"v=DMARC1; p=bad"'):
            result, _ = self.collect({("_dmarc.my-app.com", "TXT"): output("_dmarc.my-app.com", "TXT", value)})
            self.assertEqual(result["dns-dmarc"][0], "WARNING")

    def test_deadline_hostname_and_grant_reject_before_execution(self):
        with patch("security_dns.subprocess.run") as mocked:
            security_dns.observe_dns("my-app.com", time.monotonic() - 1)
            security_dns.observe_dns("-bad.host", time.monotonic() + 10)
            mocked.assert_not_called()
            def revoked():
                raise PermissionError("revoked")
            with self.assertRaises(PermissionError):
                security_dns.observe_dns("my-app.com", time.monotonic() + 10, revoked)
            mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
