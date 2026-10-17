"""Bounded, exact-host HTTP hardening observations. No exploit payloads or crawling."""
import contextlib
import datetime
import http.client
import ipaddress
import json
import queue
import re
import signal
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urljoin, urlsplit

VERSION = "1.0.0"
BODY_LIMIT = 65536
MAX_REQUESTS = 8
http.client._MAXHEADERS = 64
http.client._MAXLINE = 8192


class ScopeError(ValueError):
    def __init__(self, message, reason="SCOPE_POLICY"):
        super().__init__(message)
        self.reason = reason


def validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or re.search(r"[\s\x00-\x1f\x7f\\]", url):
        raise ScopeError("URL contains unsupported characters", "URL_POLICY")
    try:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.query or p.fragment:
            raise ScopeError("Use an HTTP(S) URL without credentials, query or fragment", "URL_POLICY")
        host = p.hostname.encode("idna").decode("ascii").lower()
        if p.port not in (None, 443 if p.scheme == "https" else 80):
            raise ScopeError("Only standard HTTP(S) ports are supported", "URL_POLICY")
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}", host):
            raise ScopeError("A public DNS hostname is required", "URL_POLICY")
        if host.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".example")):
            raise ScopeError("Reserved hostname", "URL_POLICY")
        return p._replace(netloc=host, path=p.path or "/").geturl()
    except (ValueError, UnicodeError) as exc:
        raise ScopeError("Invalid or unsupported URL", "URL_POLICY") from exc


def public_addresses(host, port, resolver=socket.getaddrinfo):
    records = resolver(host, port, type=socket.SOCK_STREAM)
    addresses = []
    for family, _, _, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ScopeError("Unsupported DNS address family", "DNS_POLICY")
        ip = ipaddress.ip_address(sockaddr[0])
        if isinstance(ip, ipaddress.IPv6Address) and (
            ip.sixtofour is not None or ip.teredo is not None
            or ip in ipaddress.ip_network("64:ff9b::/96")
            or ip in ipaddress.ip_network("64:ff9b:1::/48")
        ):
            raise ScopeError("DNS scope contains an address translation mechanism", "DNS_POLICY")
        effective = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        if not effective.is_global or effective.is_multicast or effective.is_unspecified:
            raise ScopeError("DNS scope contains a non-public address", "DNS_POLICY")
        addresses.append((family, sockaddr))
    if not addresses:
        raise ScopeError("DNS returned no approved addresses", "DNS_POLICY")
    return addresses


def site_aliases(hostname):
    """Exact submitted host plus its conventional www/apex alias. No other subdomains."""
    host = (hostname or "").lower()
    names = {host}
    if host.startswith("www.") and host.count(".") >= 2:
        names.add(host[4:])
    elif host.count(".") >= 1:
        names.add("www." + host)
    return names


def redirect_url(current, location, hostname):
    try:
        candidate = validate_url(urljoin(current, location))
    except ScopeError as exc:
        raise ScopeError("Redirect target is invalid or unsupported", "REDIRECT_INVALID") from exc
    p = urlsplit(candidate)
    if p.hostname not in site_aliases(hostname):
        raise ScopeError("Redirect leaves the approved hostname", "REDIRECT_HOST")
    if urlsplit(current).scheme == "https" and p.scheme != "https":
        raise ScopeError("Redirect downgrades HTTPS", "HTTPS_DOWNGRADE")
    return candidate


def sanitized_headers(headers):
    """Prepare in-memory policy inputs; callers emit observations, never these values."""
    allowed = {"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "access-control-allow-origin", "access-control-allow-credentials", "content-type"}
    result = {}
    cookies = []
    for name, value in headers:
        name = name.lower()
        if name == "set-cookie":
            attributes = {part.strip().split("=", 1)[0].lower() for part in value.split(";")[1:]}
            cookies.append({"secure": "secure" in attributes, "httpOnly": "httponly" in attributes, "sameSite": "samesite" in attributes})
        elif name in allowed:
            # Reject URL-bearing policy values from report evidence; analyze presence only.
            result[name] = value[:8192]
    return result, cookies


def analyze(scheme, status, headers, body, tls=None, http_redirect=None, emit=None, started=None):
    h, cookies = sanitized_headers(headers)
    checks = []
    started = started or set()
    def add(id_, title, passed, evidence, remediation, skipped=False):
        outcome = "skipped" if skipped else "passed" if passed else "observation"
        if emit:
            if id_ not in started:
                emit({"type": "stage", "stage": "check", "checkId": id_, "message": "Evaluating " + title + "...", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")})
            emit({"type": "stage", "stage": "check_done", "checkId": id_, "status": outcome, "message": "[" + outcome.upper() + "] " + title + " — " + evidence, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")})
        checks.append({"id": id_, "title": title, "status": outcome, "evidence": evidence, "remediation": remediation})
    secure = scheme == "https" and bool(tls)
    add("https", "Validated HTTPS connection", secure, "Certificate chain and hostname validated" if secure else "HTTPS was not established", "Serve the site with a trusted, valid HTTPS certificate.")
    add("https-redirect", "HTTP upgrades to HTTPS", http_redirect is True, "Same-host HTTP redirect to HTTPS observed" if http_redirect else "No verified same-host HTTP-to-HTTPS redirect", "Redirect HTTP requests to HTTPS.", http_redirect is None)
    add("hsts", "HTTP Strict Transport Security", bool(re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*", h.get("strict-transport-security", ""), re.I)), "Positive HSTS max-age present" if re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*", h.get("strict-transport-security", ""), re.I) else "No positive HSTS max-age observed", "After HTTPS readiness, configure Strict-Transport-Security.", not secure)
    csp = h.get("content-security-policy", "")
    add("csp", "Content Security Policy", bool(csp.strip()), "Enforced CSP header present; policy quality not assessed" if csp.strip() else "No enforced CSP header observed", "Deploy an application-specific CSP, starting in report-only mode.")
    frame_directive = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
    ancestors = frame_directive.group(1).split() if frame_directive else []
    valid_ancestors = bool(ancestors) and all(token in ("'none'", "'self'") or re.fullmatch(r"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?", token) for token in ancestors)
    if "'none'" in ancestors and len(ancestors) != 1:
        valid_ancestors = False
    framed = valid_ancestors or h.get("x-frame-options", "").strip().upper() in ("DENY", "SAMEORIGIN")
    add("framing", "Framing restrictions", framed, "Framing control present" if framed else "No supported framing restriction observed", "Set CSP frame-ancestors to the permitted embedding origins.")
    nosniff = h.get("x-content-type-options", "").strip().lower() == "nosniff"
    add("nosniff", "MIME sniffing restriction", nosniff, "nosniff present" if nosniff else "nosniff missing or invalid", "Set X-Content-Type-Options: nosniff.")
    policy = h.get("referrer-policy", "").strip().lower()
    good_policy = policy in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin")
    add("referrer", "Referrer policy", good_policy, "Restrictive referrer policy observed" if good_policy else "No recognized restrictive referrer policy", "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin.")
    for flag, title in (("secure", "Secure"), ("httpOnly", "HttpOnly"), ("sameSite", "SameSite")):
        missing = sum(not c[flag] for c in cookies)
        add("cookie-" + flag.lower(), "Cookie " + title + " attribute", not missing, str(missing) + " of " + str(len(cookies)) + " response cookies lack " + title + "; values omitted", "Review each cookie's purpose and set the appropriate " + title + " attribute.", not cookies)
    cors = h.get("access-control-allow-origin", "")
    add("cors", "CORS policy observation", not cors or cors != "*", "Wildcard CORS header observed; exploitability and credential access not established" if cors == "*" else "No wildcard CORS header observed; authorization not assessed", "Permit only intended origins for sensitive responses; validate server-side authorization.")
    markers = sum(bool(re.search(pattern, body.decode("utf-8", "replace"), re.I)) for pattern in (r"Traceback \(most recent call last\)", r"Fatal error:.*? on line \d+", r"Exception in thread", r"SQLSTATE\[[A-Z0-9]+\]"))
    add("error-disclosure", "Returned-page error disclosure", markers == 0, "Recognized diagnostic markers observed; response text omitted" if markers else "No recognized diagnostic markers in the bounded returned page", "Return generic production errors and retain diagnostics in private server logs.")
    add("http-response", "HTTP response received", status < 500, "HTTP status " + str(status), "Investigate server errors before interpreting this limited profile.")
    return checks


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, approved, timeout, secure=False):
        super().__init__(host, port, timeout=timeout)
        self.approved = approved
        self.secure = secure
        self.certificate = None

    def connect(self):
        family, sockaddr = self.approved[0]
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(sockaddr)
            if self.secure:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
                self.certificate = sock.getpeercert()
            self.sock = sock
        except BaseException:
            sock.close()
            raise


class Collector:
    def __init__(self, emit, lab_port=None):
        self.deadline = time.monotonic() + 40
        self.count = 0
        self.emit = emit
        self.lab_port = lab_port

    def resolve(self, host, port):
        if self.lab_port is not None:
            if host != "127.0.0.1" or port != self.lab_port:
                raise ScopeError("Lab scope mismatch", "LAB_POLICY")
            return [(socket.AF_INET, (host, port))]
        result = queue.Queue(maxsize=1)
        def worker():
            try:
                result.put((True, public_addresses(host, port)))
            except Exception as exc:
                result.put((False, exc))
        threading.Thread(target=worker, daemon=True).start()
        ok, value = result.get(timeout=min(5, max(.01, self.deadline - time.monotonic())))
        if not ok:
            raise value
        return value

    def request(self, url, origin=False):
        if self.count >= MAX_REQUESTS or time.monotonic() >= self.deadline:
            raise TimeoutError("Assessment request or time limit reached")
        p = urlsplit(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        approved = self.resolve(p.hostname, port)
        self.count += 1
        self.emit({"type": "stage", "stage": "request", "message": "Reading approved host response", "request": self.count})
        conn = PinnedHTTP(p.hostname, port, approved, min(5, max(.01, self.deadline - time.monotonic())), p.scheme == "https")
        try:
            headers = {"User-Agent": "ShipSafe-Baseline/" + VERSION, "Accept": "text/html,*/*;q=0.5", "Accept-Encoding": "identity", "Connection": "close"}
            if origin:
                headers["Origin"] = "https://shipsafe-origin.invalid"
            conn.request("GET", p.path or "/", headers=headers)
            response = conn.getresponse()
            raw_headers = response.getheaders()
            if sum(len(k) + len(v) for k, v in raw_headers) > 32768:
                raise ScopeError("Response headers exceeded bound", "RESPONSE_LIMIT")
            body = response.read(BODY_LIMIT)
            return {"status": response.status, "headers": raw_headers, "body": body, "tls": conn.certificate}
        finally:
            conn.close()

    def follow(self, url):
        hostname = urlsplit(url).hostname
        upgraded = False
        for count in range(4):
            response = self.request(url)
            if response["status"] not in (301, 302, 303, 307, 308):
                return url, response, upgraded, None
            if count == 3:
                if self.lab_port is not None:
                    raise ScopeError("Redirect limit reached in fixed lab", "LAB_POLICY")
                return url, response, upgraded, "REDIRECT_LIMIT"
            locations = [v for k, v in response["headers"] if k.lower() == "location"]
            if self.lab_port is not None:
                raise ScopeError("Redirects are not part of the fixed lab fixture", "LAB_POLICY")
            if not locations:
                return url, response, upgraded, "REDIRECT_MISSING"
            if len(locations) != 1:
                return url, response, upgraded, "REDIRECT_AMBIGUOUS"
            try:
                next_url = redirect_url(url, locations[0], hostname)
            except ScopeError as exc:
                if exc.reason not in ("REDIRECT_INVALID", "REDIRECT_HOST", "HTTPS_DOWNGRADE"):
                    raise
                return url, response, upgraded, exc.reason
            upgraded = upgraded or (urlsplit(url).scheme == "http" and urlsplit(next_url).scheme == "https")
            url = next_url
        raise ScopeError("Redirect limit reached in fixed lab", "LAB_POLICY")


@contextlib.contextmanager
def lab_fixture():
    """Fixed owned page only. No configurable route, proxy, files or customer code."""
    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<!doctype html><title>ShipSafe synthetic fixture</title><p>Owned lab hardening fixture.</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "fixture=synthetic-value; Path=/")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()


def collect(url, mode, emit, lab_port=None):
    collector = Collector(emit, lab_port)
    emit({"type": "stage", "stage": "check", "checkId": "https", "message": "Evaluating Validated HTTPS connection...", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")})
    emit({"type": "stage", "stage": "check", "checkId": "https-redirect", "message": "Evaluating HTTP upgrades to HTTPS...", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")})
    final_url, response, upgraded, scope_stop_reason = collector.follow(url)
    http_redirect = upgraded if urlsplit(url).scheme == "http" else None
    if scope_stop_reason and urlsplit(url).scheme == "http" and not upgraded:
        http_redirect = None
    if mode == "website" and not scope_stop_reason and urlsplit(final_url).scheme == "https" and collector.count < 5:
        try:
            _, _, http_redirect, http_stop_reason = collector.follow(final_url.replace("https://", "http://", 1))
            if http_stop_reason:
                http_redirect = None
        except Exception:
            http_redirect = None
    checks = analyze(urlsplit(final_url).scheme, response["status"], response["headers"], response["body"], response["tls"], http_redirect, emit, {"https", "https-redirect"})
    if scope_stop_reason:
        checks.append({
            "id": "redirect-scope", "title": "Redirect stays within approved scope", "status": "observation",
            "evidence": "The submitted hostname returned an HTTP redirect that ShipSafe did not follow; the destination was omitted.",
            "remediation": "If authorized to assess the destination, submit its final canonical HTTPS hostname directly.",
        })
    emit({"type": "stage", "stage": "analysis", "message": "Analyzed bounded response headers and diagnostic markers"})
    findings = [{"checkId": c["id"], "title": c["title"], "severity": "info", "classification": "hardening", "description": "Observed response hardening gap; this does not establish an exploitable vulnerability.", "evidence": c["evidence"], "remediation": c["remediation"]} for c in checks if c["status"] == "observation"]
    if scope_stop_reason:
        findings = [finding for finding in findings if finding["checkId"] != "redirect-scope"]
        findings.append({
            "checkId": "redirect-scope", "title": "Redirected response could not be fully assessed", "severity": "info", "classification": "hardening",
            "description": "The submitted hostname returned a redirect that the baseline could not safely follow under exact-host, HTTPS and redirect-validation policy. This is a scope limitation, not evidence of a vulnerability. ShipSafe did not contact any redirect destination.",
            "evidence": "An HTTP redirect response was observed on the submitted hostname. Its destination was not stored or requested.",
            "remediation": "Submit the final canonical HTTPS hostname directly if you are authorized to assess it, or correct the redirect chain if its destination is invalid or ambiguous.",
        })
    tls_metadata = {"validated": bool(response["tls"])}
    if response["tls"]:
        # Certificate validity dates are fixed-format metadata; omit subject/SAN data.
        for key in ("notBefore", "notAfter"):
            value = response["tls"].get(key, "")
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9 :]{1,40}", value):
                tls_metadata[key] = value
    limitations = ["No crawling or exploitation", "No authenticated, source, dependency, database or business-logic testing", "CORS observes ordinary response headers only; no Origin probe or credential/auth validation", "TLS validation or transport failure fails the job without producing a report", "Header presence does not prove policy effectiveness", "No security score or exhaustive coverage claim"]
    if scope_stop_reason:
        limitations.append("Partial redirect-response assessment: the destination was not requested. Checks and observations describe only the submitted hostname's redirect response.")
    return {"type": "report", "checks": checks, "findings": findings, "manifest": {"engine": "shipsafe-http-baseline", "version": VERSION, "profile": "bounded-http-redirect-response" if scope_stop_reason else "bounded-http-hardening", "scopeLimited": bool(scope_stop_reason), "scopeStopReason": scope_stop_reason, "mode": mode, "synthetic": mode == "lab", "scope": "owned synthetic loopback fixture" if mode == "lab" else urlsplit(url).hostname, "requests": collector.count, "bodyByteLimit": BODY_LIMIT, "tls": tls_metadata, "limitations": limitations}}


def run(config, emit):
    mode = config.get("mode")
    if mode == "lab":
        with lab_fixture() as port:
            return collect("http://127.0.0.1:" + str(port) + "/", mode, emit, port)
    if mode != "website":
        raise ScopeError("Unsupported assessment mode", "CONFIG_POLICY")
    return collect(validate_url(config.get("url")), mode, emit)


def main():
    def emit(value):
        print(json.dumps(value, ensure_ascii=True), flush=True)
    if hasattr(signal, "SIGALRM"):
        def deadline(*_):
            raise TimeoutError("Assessment deadline reached")
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(45)
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ScopeError("Input limit exceeded", "CONFIG_POLICY")
        config = json.loads(raw)
        if not isinstance(config, dict):
            raise ScopeError("Invalid configuration", "CONFIG_POLICY")
        emit({"type": "stage", "stage": "start", "message": "Starting bounded baseline observations"})
        emit(run(config, emit))
    except Exception as exc:
        # Error strings can contain URLs, certificate names or response data. Never echo them.
        failure = {"type": "error", "code": "SCOPE_REJECTED" if isinstance(exc, ScopeError) else "BASELINE_FAILED", "message": "Assessment could not complete within the approved scope and resource limits"}
        if isinstance(exc, ScopeError):
            failure["reason"] = exc.reason
        emit(failure)
        return 1
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
