"""Offline regression tests: no external host is contacted."""
import io
import json
import socket
import unittest
from unittest.mock import Mock, patch

import baseline


def record(ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, 6, "", (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443))


class ScopeTests(unittest.TestCase):
    def test_analyze_emits_one_start_and_completion_for_each_check(self):
        events=[]
        checks=baseline.analyze('https',200,[('Content-Security-Policy','default-src \'self\'')],b'page',{'notAfter':'fixture'},True,events.append)
        starts=[e for e in events if e['stage']=='check']
        done=[e for e in events if e['stage']=='check_done']
        self.assertEqual([e['checkId'] for e in starts],[c['id'] for c in checks])
        self.assertEqual([e['checkId'] for e in done],[c['id'] for c in checks])
        self.assertTrue(all(e['status'] in ('passed','observation','skipped') for e in done))
    def test_valid_normalization(self):
        self.assertEqual(baseline.validate_url("https://www.Example.com:443/path"), "https://www.example.com/path")

    def test_rejected_urls(self):
        for url in ("file:///etc/passwd", "http://localhost/", "http://127.0.0.1/", "http://[::1]/", "https://a.example.test/", "https://example.com:8443/", "https://user:secret@example.com/", "https://example.com/?token=secret", "https://example.com/#secret", "https://example.com/\r\nX:secret", "https://example.com\\@evil.com", "https://example.com/ space"):
            with self.subTest(url=url), self.assertRaises(baseline.ScopeError):
                baseline.validate_url(url)
        with self.assertRaises(baseline.ScopeError) as rejected:
            baseline.validate_url("https://example.com:8443/")
        self.assertEqual(rejected.exception.reason, "URL_POLICY")

    def test_all_dns_answers_checked(self):
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1", "0.0.0.0", "100.64.0.1", "64:ff9b::7f00:1", "64:ff9b:1::7f00:1", "2002:7f00:1::"):
            resolver = Mock(return_value=[record("8.8.8.8"), record(ip)])
            with self.subTest(ip=ip), self.assertRaises(baseline.ScopeError):
                baseline.public_addresses("example.com", 443, resolver)
        self.assertEqual(len(baseline.public_addresses("example.com", 443, Mock(return_value=[record("8.8.8.8"), record("2606:4700:4700::1111")]))), 2)
        with self.assertRaises(baseline.ScopeError):
            baseline.public_addresses("example.com", 443, Mock(return_value=[]))

    def test_redirects(self):
        self.assertEqual(baseline.redirect_url("http://example.com/a", "https://example.com/b", "example.com"), "https://example.com/b")
        self.assertEqual(baseline.redirect_url("https://example.com/a", "https://www.example.com/b", "example.com"), "https://www.example.com/b")
        self.assertEqual(baseline.redirect_url("https://www.example.com/a", "https://example.com/b", "www.example.com"), "https://example.com/b")
        for location in ("https://other.com/", "//other.com/", "http://example.com/", "https://example.com:8080/", "/?token=secret", "https://sub.example.com/", "https://api.example.com/"):
            with self.subTest(location=location), self.assertRaises(baseline.ScopeError):
                baseline.redirect_url("https://example.com/a", location, "example.com")
        with self.assertRaises(baseline.ScopeError) as rejected:
            baseline.redirect_url("https://example.com/a", "https://other.com/", "example.com")
        self.assertEqual(rejected.exception.reason, "REDIRECT_HOST")
        with self.assertRaises(baseline.ScopeError) as rejected:
            baseline.redirect_url("https://example.com/a", "http://example.com/", "example.com")
        self.assertEqual(rejected.exception.reason, "HTTPS_DOWNGRADE")
        with self.assertRaises(baseline.ScopeError) as rejected:
            baseline.redirect_url("https://example.com/a", "https://example.com/?token=secret", "example.com")
        self.assertEqual(rejected.exception.reason, "REDIRECT_INVALID")

    def test_missing_and_ambiguous_redirects_have_distinct_reasons(self):
        for headers, reason in (([], "REDIRECT_MISSING"), ([('Location', '/a'), ('Location', '/b')], "REDIRECT_AMBIGUOUS")):
            collector = baseline.Collector(lambda _: None)
            with patch.object(collector, "request", return_value={"status": 302, "headers": headers}):
                _, response, _, stop_reason = collector.follow("https://example.com/")
            self.assertEqual(response["status"], 302)
            self.assertEqual(stop_reason, reason)

    def test_pinned_socket_and_original_sni(self):
        raw = Mock()
        wrapped = Mock()
        wrapped.getpeercert.return_value = {"notAfter": "fixture"}
        context = Mock()
        context.wrap_socket.return_value = wrapped
        with patch.object(baseline.socket, "socket", return_value=raw), patch.object(baseline.ssl, "create_default_context", return_value=context):
            connection = baseline.PinnedHTTP("example.com", 443, [(socket.AF_INET, ("8.8.8.8", 443))], 5, True)
            connection.connect()
            raw.connect.assert_called_once_with(("8.8.8.8", 443))
            context.wrap_socket.assert_called_once_with(raw, server_hostname="example.com")

    def test_header_and_body_caps(self):
        response = Mock(status=200)
        response.getheaders.return_value = [("Content-Type", "text/html")]
        response.read.return_value = b"bounded"
        connection = Mock(certificate=None)
        connection.getresponse.return_value = response
        collector = baseline.Collector(lambda _: None)
        with patch.object(collector, "resolve", return_value=[(socket.AF_INET, ("8.8.8.8", 80))]), patch.object(baseline, "PinnedHTTP", return_value=connection):
            collector.request("http://example.com/")
            response.read.assert_called_once_with(65536)
            args, kwargs = connection.request.call_args
            self.assertEqual(args, ("GET", "/"))
            self.assertNotIn("Cookie", kwargs["headers"])
            self.assertNotIn("Authorization", kwargs["headers"])
            self.assertNotIn("Origin", kwargs["headers"])
            response.getheaders.return_value = [("X-Large", "a" * 32769)]
            with self.assertRaises(baseline.ScopeError):
                collector.request("http://example.com/")

    def test_request_budget(self):
        collector = baseline.Collector(lambda _: None)
        collector.count = 8
        with self.assertRaises(TimeoutError):
            collector.request("http://example.com/")

    def test_redirect_hops_bounded(self):
        collector = baseline.Collector(lambda _: None)
        with patch.object(collector, "request", return_value={"status": 302, "headers": [("Location", "/again")]}) as request:
            _, response, _, reason = collector.follow("https://example.com/")
            self.assertEqual(request.call_count, 4)
            self.assertEqual(response["status"], 302)
            self.assertEqual(reason, "REDIRECT_LIMIT")

    def test_www_alias_redirect_is_followed_and_does_not_contact_other_hosts(self):
        collector = baseline.Collector(lambda _: None)
        calls = []
        def request(url, origin=False):
            calls.append(url)
            if url.startswith("http://"):
                return {"status": 301, "headers": [("Location", url.replace("http://", "https://", 1))], "body": b"", "tls": None}
            if url == "https://example.com/":
                return {"status": 302, "headers": [("Location", "https://www.example.com/")], "body": b"Moved", "tls": {"notAfter": "fixture"}}
            if url == "https://www.example.com/":
                return {"status": 200, "headers": [("Content-Type", "text/html")], "body": b"ok", "tls": {"notAfter": "fixture"}}
            raise AssertionError("unexpected url " + url)
        with patch.object(baseline, "Collector", return_value=collector), patch.object(collector, "request", side_effect=request):
            report = baseline.collect("https://example.com/", "website", lambda _: None)
        self.assertFalse(report["manifest"]["scopeLimited"])
        self.assertEqual(report["manifest"]["profile"], "bounded-http-hardening")
        self.assertIn("https://www.example.com/", calls)
        self.assertTrue(any(url.startswith("http://www.example.com/") for url in calls))
        self.assertNotIn("other.com", json.dumps(report))
        self.assertNotIn("api.example.com", json.dumps(calls))

    def test_out_of_scope_redirect_produces_partial_response_report_without_following(self):
        collector = baseline.Collector(lambda _: None)
        collector.count = 1
        redirect = {"status": 302, "headers": [("Location", "https://other.com/private")], "body": b"Moved", "tls": {"verified": True}}
        with patch.object(baseline, "Collector", return_value=collector), patch.object(collector, "request", return_value=redirect) as request:
            report = baseline.collect("https://example.com/", "website", lambda _: None)
        self.assertEqual(request.call_count, 1)
        self.assertTrue(report["manifest"]["scopeLimited"])
        self.assertEqual(report["manifest"]["scopeStopReason"], "REDIRECT_HOST")
        self.assertEqual(report["manifest"]["profile"], "bounded-http-redirect-response")
        self.assertEqual(report["manifest"]["requests"], 1)
        self.assertNotIn("other.com", json.dumps(report))
        finding = next(item for item in report["findings"] if item["checkId"] == "redirect-scope")
        self.assertIn("did not contact any redirect destination", finding["description"])
        self.assertIn("Partial redirect-response assessment", report["manifest"]["limitations"][-1])

    def test_http_redirect_stopped_by_scope_does_not_claim_upgrade_failure(self):
        collector = baseline.Collector(lambda _: None)
        collector.count = 1
        redirect = {"status": 301, "headers": [("Location", "https://other.com/")], "body": b"Moved", "tls": None}
        with patch.object(baseline, "Collector", return_value=collector), patch.object(collector, "request", return_value=redirect):
            report = baseline.collect("http://example.com/", "website", lambda _: None)
        check = next(item for item in report["checks"] if item["id"] == "https-redirect")
        self.assertEqual(check["status"], "skipped")
        self.assertEqual(report["manifest"]["requests"], 1)


class AnalysisTests(unittest.TestCase):
    def test_no_secrets_in_report(self):
        headers = [("Set-Cookie", "session=TOPSECRET; Path=/"), ("Authorization", "Bearer TOPSECRET"), ("X-Api-Key", "TOPSECRET"), ("Content-Security-Policy", "report-uri https://example.com/?key=TOPSECRET"), ("Access-Control-Allow-Origin", "https://TOPSECRET.example.com")]
        checks = baseline.analyze("https", 200, headers, b"SQLSTATE[42000] database-password=TOPSECRET", {"verified": True})
        serialized = json.dumps(checks)
        self.assertNotIn("TOPSECRET", serialized)
        self.assertNotIn("database-password", serialized)
        self.assertEqual(next(c for c in checks if c["id"] == "error-disclosure")["status"], "observation")

    def test_hardened_headers(self):
        headers = [("Strict-Transport-Security", "max-age=31536000"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin"), ("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax")]
        checks = baseline.analyze("https", 200, headers, b"ordinary body", {"verified": True}, True)
        self.assertTrue(all(c["status"] == "passed" for c in checks))

    def test_invalid_values_are_observations(self):
        checks = baseline.analyze("https", 200, [("Strict-Transport-Security", "max-age=0"), ("X-Frame-Options", "ALLOWALL"), ("X-Content-Type-Options", "wrong"), ("Referrer-Policy", "unsafe-url")], b"", {"verified": True})
        for id_ in ("hsts", "framing", "nosniff", "referrer"):
            self.assertEqual(next(c for c in checks if c["id"] == id_)["status"], "observation")

    def test_wildcard_and_invalid_framing_do_not_pass(self):
        for directive in ("frame-ancestors *", "frame-ancestors https://*", "frame-ancestors invalid", "frame-ancestors 'none' https://example.com"):
            checks = baseline.analyze("http", 200, [("Content-Security-Policy", directive)], b"")
            self.assertEqual(next(c for c in checks if c["id"] == "framing")["status"], "observation")

    def test_lab_ignores_supplied_target(self):
        events = []
        with patch.object(baseline, "validate_url", side_effect=AssertionError("Lab must not validate or contact user URL")):
            report = baseline.run({"mode": "lab", "url": "https://DO-NOT-CONTACT.example.org/?secret=TOPSECRET"}, events.append)
        self.assertTrue(report["manifest"]["synthetic"])
        self.assertEqual(report["manifest"]["requests"], 1)
        self.assertTrue(any(f["checkId"] == "csp" for f in report["findings"]))
        self.assertTrue(all(f["classification"] == "hardening" for f in report["findings"]))
        self.assertNotIn("TOPSECRET", json.dumps(report))
        self.assertNotIn("synthetic-value", json.dumps(report))
        self.assertEqual([e["stage"] for e in events[:2]], ["check", "check"])
        self.assertLess(next(i for i, e in enumerate(events) if e["stage"] == "check" and e["checkId"] == "https"), next(i for i, e in enumerate(events) if e["stage"] == "request"))
        self.assertEqual([e["stage"] for e in events][-1], "analysis")
        self.assertEqual(sum(e["stage"] == "check" for e in events), sum(e["stage"] == "check_done" for e in events))


if __name__ == "__main__":
    unittest.main()
