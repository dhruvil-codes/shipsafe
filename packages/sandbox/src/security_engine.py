"""Bounded Standard and verified Deep observations; no exploit or credential probes."""
import datetime
from email.utils import parsedate_to_datetime
import json
import re
import signal
import ssl
import subprocess
import sys
import time
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit

import baseline
from security_registry import REGISTRY, VERSION, IMPLEMENTED, DEFERRED_IDS
from security_dns import observe_dns

MAX_REQUESTS = 20
ALLOWED_CLASSES = {"configuration", "discovery", "cors", "vulnerability"}
SAFE_METADATA = "/.well-known/security.txt"
METADATA_PATHS = {"security-txt": SAFE_METADATA, "robots-txt": "/robots.txt", "sitemap-xml": "/sitemap.xml"}
REDIRECTS = (301, 302, 303, 307, 308)
ACTION_PATH = re.compile(r"(?:logout|signout|delete|remove|unsubscribe|cancel|destroy|reset|revoke|checkout|purchase|transfer|confirm|activate|disable|enable|execute|admin|api/)", re.I)
REMEDIATIONS = {
    "coop": "If compatible with required popups, set Cross-Origin-Opener-Policy: same-origin; verify login and payment popup flows.",
    "coep": "If cross-origin isolation is required, use require-corp or credentialless and test all embedded resources.",
    "corp": "Set a suitable Cross-Origin-Resource-Policy for resources; test intended cross-origin consumers.",
    "permissions": "Restrict unused browser features with an application-specific Permissions-Policy; test required features.",
    "cache": "Classify response sensitivity; use private or no-store for sensitive responses and verify intermediary caching.",
    "server-disclosure": "Remove unnecessary software version headers in the actual server or proxy configuration and recheck responses.",
    "cookie-samesite-valid": "Use SameSite=Lax or Strict where compatible; SameSite=None requires Secure. Recheck each Set-Cookie response.",
    "cookie-domain": "Prefer host-only cookies by omitting Domain unless sharing across subdomains is required.",
    "cookie-path": "Review cookie Path for intended use; Path is not an authorization boundary. Test session behavior on intended routes.",
    "cookie-lifetime": "Use purpose-appropriate cookie expiry and server-side session invalidation; review persistent cookies individually.",
    "cookie-prefix": "Serve prefixed cookies over HTTPS with Secure; __Host- also requires Path=/ and no Domain attribute.",
    "mixed-content": "Replace insecure resource references with HTTPS and inspect the browser mixed-content console on the affected page.",
    "script-inventory": "Review each script owner and necessity; consider CSP and integrity metadata where compatible. Retest in a browser.",
    "library-inventory": "Verify detected library versions against your dependency inventory and a maintained advisory feed before reporting CVEs.",
    "tls-expiry": "Renew the certificate before expiry, automate renewal, and verify the served chain and hostname after deployment.",
    "dns-public": "Keep target DNS within the authorized public network scope; private and mixed public/private answers are rejected.",
    "security-txt": "Publish Contact and Expires fields at /.well-known/security.txt; validate the full security.txt format separately.",
    "robots-txt": "Review robots.txt for intended indexing behavior; do not rely on it to protect sensitive routes.",
    "sitemap-xml": "Publish only intended public URLs in sitemap.xml; protect private routes with server-side authorization.",
    "source-map": "Review whether production source maps should be public; remove public maps if they reveal source that should remain private.",
    "deep-git-head": "Remove .git data from the deployed web root and deny dot-directory access in the actual server. Retest the reviewed path.",
    "deep-discovery": "Review the deployment's route inventory separately; this bounded linked-page sample cannot establish complete endpoint coverage.",
    "deep-cors": "Allow only intended origins for sensitive responses and test credentialed browser access with a reviewed authenticated context.",
    "dns-caa": "Review CAA issuer authorization with your DNS operator and certificate issuer; requery after propagation.",
    "dns-spf": "Review a single valid SPF record for your sending services; validate includes and lookup limits separately.",
    "dns-dmarc": "Review DMARC policy and reporting with your email operator; validate alignment before enforcing a rejection policy.",
    "dns-mx": "Confirm the target hostname's mail-routing intent with your DNS operator; absence is not proof of a web vulnerability.",
    "deep-nuclei": "Review reported misconfigurations in server and application deployment files, applying recommended vendor patches.",
    "deep-zap": "Inspect reported passive alerts such as missing security headers or missing anti-CSRF protections in your application framework.",
}


IMPACTS = {
    "tls": "TLS validates the server identity and encrypts transport; invalid or expiring deployment certificates can disrupt trusted access.",
    "headers": "Browser response policies constrain resource loading, embedding and information sharing; required policies depend on application behavior.",
    "cookies": "Cookie attributes constrain transport, script access, cross-site delivery and scope. The purpose of each cookie needs application context.",
    "cors": "CORS determines which origins may read browser responses. Header observations alone do not prove access to authenticated data.",
    "configuration": "Diagnostic output or exposed deployment metadata may disclose internal implementation details.",
    "discovery": "Linked-page observations establish which approved pages were requested; they do not prove endpoint completeness or authorization enforcement.",
    "frontend": "Public page resources can cross transport or third-party trust boundaries. Their presence does not prove a vulnerable dependency or an exposed secret.",
    "dns": "DNS declarations affect certificate issuance and email policy. Direct records do not establish inherited policy, sender alignment or complete DNS security.",
    "metadata": "Public contact and indexing metadata supports discovery and responsible reporting; presence or absence is not a vulnerability result.",
    "vulnerability": "Passive vulnerability scanning checks for common misconfigurations and exposed sensitive resources without active exploitation.",
}
CHECK_IMPACTS = {
    "csp": "CSP constrains browser resource execution and can reduce injection impact; missing policy is not evidence of an injection vulnerability.",
    "framing": "Embedding restrictions can reduce clickjacking risk when sensitive application interactions exist.",
    "nosniff": "An explicit nosniff policy reduces browser MIME interpretation ambiguity for returned resources.",
    "referrer": "Referrer policy limits which URL details browsers share with other resources and origins.",
    "hsts": "HSTS can reduce HTTP downgrade exposure after a browser learns the host policy.",
    "deep-git-head": "A public Git HEAD signature indicates repository metadata exposure; only that signature was assessed, not repository contents.",
    "deep-cors": "Reflection of the controlled Origin warrants policy review; no credentials or cross-user data were used to establish exploitability.",
    "http-response": "Server errors can limit the usefulness of a response assessment. A successful HTTP response does not establish application security.",
    "deep-nuclei": "Nuclei applies vetted vulnerability templates to detect known security misconfigurations and exposed administrative assets.",
    "deep-zap": "OWASP ZAP passive baseline analyzer inspects responses for security anti-patterns without active fuzzing or payload injection.",
}


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def grant_valid(grant, hostname):
    """Validate backend-issued scope. Ownership verification remains a backend duty."""
    if not isinstance(grant, dict) or grant.get("hostname") != hostname or grant.get("revoked", False) is not False:
        raise baseline.ScopeError("Deep authorization unavailable", "AUTHORIZATION_REQUIRED")
    classes = grant.get("classes")
    if not isinstance(classes, list) or not classes or any(c not in ALLOWED_CLASSES for c in classes):
        raise baseline.ScopeError("Unsupported test classes", "AUTHORIZATION_CLASSES")
    try:
        expiry = datetime.datetime.fromisoformat(grant["expiresAt"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.datetime.now(datetime.timezone.utc):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise baseline.ScopeError("Deep authorization expired or invalid", "AUTHORIZATION_EXPIRED") from None
    return set(classes)


class Collector(baseline.Collector):
    """Reuse pinned transport, with exact-host scope and a shared 20-request budget."""
    def __init__(self, emit, url, mode, grant=None):
        super().__init__(emit)
        self.hostname = urlsplit(url).hostname
        self.mode = mode
        self.grant = grant
        self.paths = {urlsplit(url).path or "/", *METADATA_PATHS.values()}
        self.resolution_count = 0
        self.public_dns_reported = False

    def approve(self, url):
        candidate = baseline.validate_url(url)
        if urlsplit(candidate).hostname != self.hostname:
            raise baseline.ScopeError("Exact host required", "REDIRECT_HOST")
        self.paths.add(urlsplit(candidate).path)
        return candidate

    def resolve(self, host, port):
        report = not self.public_dns_reported
        self.public_dns_reported = True
        if report:
            emit_check_start(self.emit, "dns-public", "Anti-SSRF public IP resolution and address pinning")
        try:
            result = super().resolve(host, port)
        except Exception:
            if report:
                emit_check_done(self.emit, "dns-public", "Anti-SSRF public IP resolution and address pinning", "NOT_TESTED", "Public address validation did not complete; request stopped before connection")
            raise
        self.resolution_count += 1
        if report:
            emit_check_done(self.emit, "dns-public", "Anti-SSRF public IP resolution and address pinning", "PASS", "All connection DNS answers validated as public and selected address pinned")
        return result

    def request(self, url, origin=False):
        normalized = baseline.validate_url(url)
        parsed = urlsplit(normalized)
        if parsed.hostname != self.hostname or parsed.path not in self.paths:
            raise baseline.ScopeError("Unapproved request", "REQUEST_SCOPE")
        if self.mode == "deep":
            classes = grant_valid(self.grant, self.hostname)
            if origin and "cors" not in classes:
                raise baseline.ScopeError("CORS class not authorized", "AUTHORIZATION_CLASSES")
        elif origin:
            raise baseline.ScopeError("Origin probes require Deep authorization", "AUTHORIZATION_REQUIRED")
        if self.count >= MAX_REQUESTS or time.monotonic() >= self.deadline:
            raise TimeoutError("Shared resource budget exhausted")
        # Transport implementation mirrors baseline, retaining DNS pinning and bounds.
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = self.resolve(parsed.hostname, port)
        if self.mode == "deep":
            grant_valid(self.grant, self.hostname)
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Shared time budget exhausted")
        self.count += 1
        self.emit({"type": "stage", "stage": "request", "message": "Reading approved host response", "request": self.count})
        connection = baseline.PinnedHTTP(parsed.hostname, port, addresses, min(5, max(.01, self.deadline - time.monotonic())), parsed.scheme == "https")
        try:
            headers = {"User-Agent": "ShipSafe-Security/" + VERSION, "Accept": "text/html,*/*;q=0.5", "Accept-Encoding": "identity", "Connection": "close"}
            if origin:
                headers["Origin"] = "https://shipsafe-origin.invalid"
            connection.request("GET", parsed.path, headers=headers)
            response = connection.getresponse()
            raw_headers = response.getheaders()
            if sum(len(k) + len(v) for k, v in raw_headers) > 32768:
                raise baseline.ScopeError("Header limit", "RESPONSE_LIMIT")
            # Bound slow-drip reads by the shared deadline, not a fresh timeout per byte.
            body = bytearray()
            while len(body) < baseline.BODY_LIMIT:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Shared time budget exhausted")
                if connection.sock is not None:
                    connection.sock.settimeout(min(5, remaining))
                chunk = response.read1(min(8192, baseline.BODY_LIMIT - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            return {"status": response.status, "headers": raw_headers, "body": bytes(body), "tls": connection.certificate}
        finally:
            connection.close()

    def follow(self, url):
        upgraded = False
        for hop in range(4):
            response = self.request(url)
            if response["status"] not in REDIRECTS:
                return url, response, upgraded, None
            locations = [v for k, v in response["headers"] if k.lower() == "location"]
            if hop == 3:
                return url, response, upgraded, "REDIRECT_LIMIT"
            if len(locations) != 1:
                return url, response, upgraded, "REDIRECT_MISSING" if not locations else "REDIRECT_AMBIGUOUS"
            try:
                candidate = baseline.validate_url(urljoin(url, locations[0]))
                if urlsplit(candidate).hostname != self.hostname:
                    raise baseline.ScopeError("Exact hostname required", "REDIRECT_HOST")
                if urlsplit(url).scheme == "https" and urlsplit(candidate).scheme != "https":
                    raise baseline.ScopeError("HTTPS downgrade", "HTTPS_DOWNGRADE")
                if ACTION_PATH.search(unquote(urlsplit(candidate).path)):
                    raise baseline.ScopeError("Action-like redirect path", "REDIRECT_PATH")
                self.approve(candidate)
            except baseline.ScopeError as exc:
                reason = exc.reason if exc.reason in ("REDIRECT_HOST", "HTTPS_DOWNGRADE", "REDIRECT_PATH") else "REDIRECT_INVALID"
                return url, response, upgraded, reason
            upgraded = upgraded or (urlsplit(url).scheme == "http" and urlsplit(candidate).scheme == "https")
            url = candidate


class HTMLInventory(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.resources = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag in ("script", "img", "iframe", "audio", "video", "source", "link"):
            resource_link = tag == "link" and bool(set(attrs.get("rel", "").lower().split()) & {"stylesheet", "preload", "modulepreload", "icon", "manifest"})
            resource = attrs.get("src") or (attrs.get("href") if resource_link else None)
            if resource:
                self.resources.append(resource)
                if tag == "script":
                    self.scripts.append(resource)


def emit_check_start(emit, check_id, title):
    emit({"type": "stage", "stage": "check", "checkId": check_id, "message": "Evaluating " + title + "...", "timestamp": timestamp()})


def emit_check_done(emit, check_id, title, status, summary):
    terminal_status = {"PASS": "passed", "WARNING": "observation", "FAIL": "observation", "NOT_TESTED": "skipped", "NOT_APPLICABLE": "skipped"}.get(status, "skipped")
    emit({"type": "stage", "stage": "check_done", "checkId": check_id, "status": terminal_status, "message": "[" + terminal_status.upper() + "] " + title + " — " + summary, "timestamp": timestamp()})


def extra_observations(url, response, emit=None, body_available=True):
    """Analyze bounded response inputs; never emit cookies, bodies or resource URLs."""
    headers = {k.lower(): v for k, v in response["headers"]}
    observations = {}
    def add(id_, passed, evidence, na=False):
        unavailable_body_checks = {"error-disclosure", "mixed-content", "script-inventory", "library-inventory"}
        if id_ in unavailable_body_checks and not body_available:
            status, evidence = "NOT_TESTED", "Unsupported content encoding; returned body was not interpreted"
        else:
            status = "NOT_APPLICABLE" if na else "PASS" if passed else "WARNING"
        title = next((item["title"] for item in REGISTRY if item["id"] == id_), id_)
        if emit:
            emit_check_start(emit, id_, title)
            emit_check_done(emit, id_, title, status, evidence)
        observations[id_] = (status, evidence)
    for id_, header, values in (
        ("coop", "cross-origin-opener-policy", {"same-origin", "same-origin-allow-popups"}),
        ("coep", "cross-origin-embedder-policy", {"require-corp", "credentialless"}),
        ("corp", "cross-origin-resource-policy", {"same-origin", "same-site"}),
    ):
        add(id_, headers.get(header, "").lower().strip() in values, "Recognized restrictive value observed" if headers.get(header, "").lower().strip() in values else "Restrictive value absent; suitability depends on application embedding requirements")
    add("permissions", bool(headers.get("permissions-policy", "").strip()), "Policy header present; directives not assessed" if headers.get("permissions-policy", "").strip() else "Policy header absent; required restrictions depend on application features")
    add("cache", bool(headers.get("cache-control")), "Cache-Control header present; sensitivity and cache behavior not established" if headers.get("cache-control") else "No Cache-Control header; response sensitivity not established")
    version = bool(re.search(r"\d+\.\d+", headers.get("server", "") + " " + headers.get("x-powered-by", "")))
    add("server-disclosure", not version, "Software version-like token observed; value omitted" if version else "No software version-like token in reviewed headers")
    cookies = [v for k, v in response["headers"] if k.lower() == "set-cookie"]
    counts = dict.fromkeys(("cookie-samesite-valid", "cookie-domain", "cookie-path", "cookie-lifetime", "cookie-prefix"), 0)
    for raw in cookies:
        pieces = raw.split(";")
        name = pieces[0].partition("=")[0].strip()
        attrs = {p.partition("=")[0].strip().lower(): p.partition("=")[2].strip() for p in pieces[1:]}
        same = attrs.get("samesite", "").lower()
        counts["cookie-samesite-valid"] += same not in ("strict", "lax", "none") or (same == "none" and "secure" not in attrs)
        counts["cookie-domain"] += "domain" in attrs
        counts["cookie-path"] += not attrs.get("path", "").startswith("/")
        # Long persistence is an observation only, without assumptions about cookie purpose.
        age = attrs.get("max-age")
        if age is not None:
            counts["cookie-lifetime"] += not re.fullmatch(r"-?\d{1,10}", age) or int(age) > 34560000
        elif "expires" in attrs:
            try:
                expiry = parsedate_to_datetime(attrs["expires"])
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=datetime.timezone.utc)
                counts["cookie-lifetime"] += (expiry - datetime.datetime.now(datetime.timezone.utc)).total_seconds() > 34560000
            except (ValueError, TypeError, OverflowError):
                counts["cookie-lifetime"] += 1
        counts["cookie-prefix"] += (name.startswith("__Secure-") and ("secure" not in attrs or urlsplit(url).scheme != "https")) or (name.startswith("__Host-") and ("secure" not in attrs or "domain" in attrs or attrs.get("path") != "/" or urlsplit(url).scheme != "https"))
    for id_, count in counts.items():
        add(id_, not count, str(count) + " of " + str(len(cookies)) + " cookies require attribute review; names and values omitted", not cookies)
    inventory = HTMLInventory()
    html = "text/html" in headers.get("content-type", "").lower()
    if html:
        inventory.feed(response["body"].decode("utf-8", "replace"))
    mixed = sum(urljoin(url, resource).startswith("http://") for resource in inventory.resources) if urlsplit(url).scheme == "https" else 0
    add("mixed-content", not mixed, str(mixed) + " insecure HTML resource references; browser behavior and exploitability not established", not html or urlsplit(url).scheme != "https")
    external = sum(urlsplit(urljoin(url, src)).hostname != urlsplit(url).hostname for src in inventory.scripts)
    add("script-inventory", True, str(len(inventory.scripts)) + " script references, " + str(external) + " external; no script destinations requested", not html)
    # Record only reviewed version markers. Do not infer a CVE from a name/version.
    text = response["body"].decode("utf-8", "replace") if html else ""
    libraries = sum(bool(re.search(pattern, text, re.I)) for pattern in (r"jquery[.-](?:\d+\.){1,2}\d+", r"bootstrap[.-](?:\d+\.){1,2}\d+", r"react[.-](?:\d+\.){1,2}\d+"))
    add("library-inventory", True, str(libraries) + " reviewed library version marker families observed; no CVE feed correlation", not html)
    cert = response.get("tls")
    if not cert:
        evidence = "No validated certificate metadata available"
        if emit:
            emit_check_start(emit, "tls-expiry", "Validated certificate expiry")
            emit_check_done(emit, "tls-expiry", "Validated certificate expiry", "NOT_TESTED", evidence)
        observations["tls-expiry"] = ("NOT_TESTED", evidence)
    else:
        try:
            days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
            add("tls-expiry", days > 30, "Validated certificate expires in " + str(days) + " days")
        except (KeyError, ValueError, TypeError):
            evidence = "Certificate expiry metadata unavailable"
            if emit:
                emit_check_start(emit, "tls-expiry", "Validated certificate expiry")
                emit_check_done(emit, "tls-expiry", "Validated certificate expiry", "NOT_TESTED", evidence)
            observations["tls-expiry"] = ("NOT_TESTED", evidence)
    return observations, inventory


def run(config, emit):
    if not isinstance(config, dict) or config.get("mode") not in ("standard", "deep"):
        raise baseline.ScopeError("Unsupported mode", "CONFIG_POLICY")
    mode = config["mode"]
    url = baseline.validate_url(config.get("url"))
    host = urlsplit(url).hostname
    grant = config.get("authorization")
    classes = grant_valid(grant, host) if mode == "deep" else set()
    collector = Collector(emit, url, mode, grant)
    emit_check_start(emit, "https", "Validated HTTPS connection")
    emit_check_start(emit, "https-redirect", "HTTP upgrades to HTTPS")
    final_url, response, upgraded, stop = collector.follow(url)
    upgrade = upgraded if urlsplit(url).scheme == "http" and not stop else None
    if not stop and urlsplit(final_url).scheme == "https":
        try:
            _, _, upgrade, upgrade_stop = collector.follow(final_url.replace("https://", "http://", 1))
            if upgrade_stop:
                upgrade = None
        except (OSError, TimeoutError, baseline.ScopeError):
            upgrade = None
    legacy = baseline.analyze(urlsplit(final_url).scheme, response["status"], response["headers"], response["body"], response["tls"], upgrade, emit, {"https", "https-redirect"})
    observed = {c["id"]: ("NOT_APPLICABLE" if c["status"] == "skipped" and c["id"].startswith("cookie-") else "NOT_TESTED" if c["status"] == "skipped" else "PASS" if c["status"] == "passed" else "WARNING", c["evidence"]) for c in legacy}
    body_available = not any(k.lower() == "content-encoding" and v.lower().strip() not in ("", "identity") for k, v in response["headers"])
    extra, inventory = extra_observations(final_url, response if body_available else {**response, "body": b""}, emit, body_available)
    observed.update(extra)
    if not body_available:
        for id_ in ("error-disclosure", "mixed-content", "script-inventory", "library-inventory"):
            observed[id_] = ("NOT_TESTED", "Unsupported content encoding; returned body was not interpreted")
    observed["dns-public"] = ("PASS", "All connection DNS answers validated as public and selected address pinned")
    if not stop:
        observed.update(observe_dns(host, collector.deadline, lambda: grant_valid(grant, host) if mode == "deep" else None, emit))
        for id_, path in METADATA_PATHS.items():
            title = next(item["title"] for item in REGISTRY if item["id"] == id_)
            emit_check_start(emit, id_, title)
            try:
                metadata_url = urlsplit(final_url)._replace(path=path).geturl()
                metadata = collector.request(metadata_url)
                available = not any(k.lower() == "content-encoding" and v.lower().strip() not in ("", "identity") for k, v in metadata["headers"])
                valid = available and metadata["status"] == 200 and bool(re.search({"security-txt": rb"(?im)^Contact:\s*\S+", "robots-txt": rb"(?im)^User-agent:\s*\S+", "sitemap-xml": rb"<(?:\w+:)?(?:urlset|sitemapindex)(?:\s|>)"}[id_], metadata["body"]))
                observed[id_] = ("PASS" if valid else "WARNING" if available and metadata["status"] in (200, 404, 410) else "NOT_TESTED", "Expected public metadata marker observed; values and linked URLs omitted" if valid else "Expected public metadata marker not established; no URLs followed")
            except (OSError, TimeoutError, baseline.ScopeError):
                observed[id_] = ("NOT_TESTED", "Metadata request could not complete within approved bounds")
            emit_check_done(emit, id_, title, observed[id_][0], observed[id_][1])
        html = "text/html" in dict((k.lower(), v) for k, v in response["headers"]).get("content-type", "").lower()
        emit_check_start(emit, "source-map", "Explicit same-host source map reference")
        source = re.search(r"[#@]\s*sourceMappingURL\s*=\s*([^\s<>\"']+)", response["body"].decode("utf-8", "replace")) if html and body_available else None
        observed["source-map"] = ("NOT_APPLICABLE" if body_available else "NOT_TESTED", "No explicit returned-page source map reference; linked scripts were not fetched" if body_available else "Unsupported content encoding; source map reference unavailable")
        if source:
            try:
                target = baseline.validate_url(urljoin(final_url, source.group(1)))
                parsed = urlsplit(target)
                if parsed.hostname != host or not parsed.path.endswith(".map") or ACTION_PATH.search(unquote(parsed.path)) or (urlsplit(final_url).scheme == "https" and parsed.scheme != "https"):
                    raise baseline.ScopeError("Source map outside scope", "REQUEST_SCOPE")
                collector.approve(target)
                mapped = collector.request(target)
                signature = mapped["status"] == 200 and bool(re.search(rb'"version"\s*:\s*3', mapped["body"])) and b'"sources"' in mapped["body"]
                observed["source-map"] = ("WARNING" if signature else "NOT_TESTED", "Public source map signature observed; sources and contents omitted" if signature else "Source map content not established")
            except (OSError, TimeoutError, baseline.ScopeError):
                observed["source-map"] = ("NOT_TESTED", "Source map reference outside approved scope or unavailable")
        emit_check_done(emit, "source-map", "Explicit same-host source map reference", observed["source-map"][0], observed["source-map"][1])
    if mode == "deep" and not stop:
        for test_class in sorted(classes):
            if test_class == "vulnerability":
                n_id = "deep-nuclei"
                n_title = next(item["title"] for item in REGISTRY if item["id"] == n_id)
                emit_check_start(emit, n_id, n_title)
                try:
                    cmd = [
                        "docker", "run", "--rm", "--network", "host",
                        "projectdiscovery/nuclei:v3.11.1",
                        "-u", final_url,
                        "-tags", "misconfiguration,exposure,ssl",
                        "-exclude-tags", "dos,fuzz,sqli,xss,rce,bruteforce,auth-bypass,intrusive",
                        "-c", "2", "-rate-limit", "10", "-timeout", "3", "-silent", "-jsonl"
                    ]
                    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
                    if p.returncode == 0:
                        lines = [l for l in p.stdout.decode("utf-8", "replace").split("\n") if l.strip()]
                        if len(lines) == 0:
                            observed[n_id] = ("PASS", "0 active misconfigurations or exposures identified across vetted Nuclei templates")
                        else:
                            observed[n_id] = ("WARNING", f"{len(lines)} misconfiguration findings reported by vetted Nuclei templates")
                    else:
                        observed[n_id] = ("NOT_TESTED", "Nuclei container returned non-zero exit code or template evaluation was inconclusive")
                except Exception:
                    observed[n_id] = ("NOT_TESTED", "Nuclei execution was unavailable or command timed out")
                emit_check_done(emit, n_id, n_title, observed[n_id][0], observed[n_id][1])

                z_id = "deep-zap"
                z_title = next(item["title"] for item in REGISTRY if item["id"] == z_id)
                emit_check_start(emit, z_id, z_title)
                try:
                    cmd = [
                        "docker", "run", "--rm", "--network", "host",
                        "ghcr.io/zaproxy/zaproxy:2.17.0",
                        "zap-baseline.py", "-t", final_url,
                        "-m", "1", "-T", "2", "-s", "-I"
                    ]
                    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
                    if p.returncode in (0, 1, 2):
                        observed[z_id] = ("PASS" if p.returncode == 0 else "WARNING", "OWASP ZAP passive baseline scan completed; see findings for details" if p.returncode != 0 else "OWASP ZAP passive baseline completed with zero warnings")
                    else:
                        observed[z_id] = ("NOT_TESTED", "ZAP container baseline was unavailable or did not complete")
                except Exception:
                    observed[z_id] = ("NOT_TESTED", "ZAP container execution was unavailable or timed out")
                emit_check_done(emit, z_id, z_title, observed[z_id][0], observed[z_id][1])
                continue

            id_ = {"configuration": "deep-git-head", "cors": "deep-cors", "discovery": "deep-discovery"}.get(test_class)
            if not id_:
                continue
            title = next(item["title"] for item in REGISTRY if item["id"] == id_)
            emit_check_start(emit, id_, title)
            try:
                if test_class == "configuration":
                    target = collector.approve(urlsplit(final_url)._replace(path="/.git/HEAD").geturl())
                    result = collector.request(target)
                    exposed = result["status"] == 200 and bool(re.fullmatch(rb"(?:ref: refs/[a-zA-Z0-9_./-]+|[a-fA-F0-9]{40,64})\s*", result["body"]))
                    observed["deep-git-head"] = ("WARNING" if exposed else "PASS" if result["status"] in (404, 410) else "NOT_TESTED", "Git HEAD signature observed; body omitted" if exposed else "Reviewed Git HEAD path absent" if result["status"] in (404, 410) else "Response inconclusive; no absence or exposure established")
                elif test_class == "cors":
                    result = collector.request(final_url, origin=True)
                    h = {k.lower(): v.strip() for k, v in result["headers"]}
                    reflected = h.get("access-control-allow-origin") == "https://shipsafe-origin.invalid"
                    observed["deep-cors"] = ("NOT_TESTED" if not 200 <= result["status"] < 300 else "WARNING" if reflected else "PASS", "Origin probe returned an inconclusive HTTP status" if not 200 <= result["status"] < 300 else "Test Origin reflected; credentialed access and exploitability not established" if reflected else "Test Origin not reflected; browser authorization not assessed")
                elif test_class == "discovery":
                    if not body_available:
                        observed["deep-discovery"] = ("NOT_TESTED", "Unsupported content encoding; linked-page discovery was unavailable")
                    else:
                        candidates = []
                        for href in inventory.links:
                            candidate = urljoin(final_url, href)
                            p = urlsplit(candidate)
                            if p.hostname != host or p.query or p.fragment or ACTION_PATH.search(unquote(p.path)):
                                continue
                            try:
                                candidate = baseline.validate_url(candidate)
                            except baseline.ScopeError:
                                continue
                            if candidate not in candidates and candidate != final_url:
                                candidates.append(candidate)
                            if len(candidates) == 3:
                                break
                        read = 0
                        for candidate in candidates:
                            if urlsplit(final_url).scheme == "https" and urlsplit(candidate).scheme != "https":
                                continue
                            collector.approve(candidate)
                            collector.request(candidate)
                            read += 1
                        observed["deep-discovery"] = ("PASS" if read else "NOT_APPLICABLE", str(read) + " same-host linked pages read without following redirects; bodies and URLs omitted")
            except (OSError, TimeoutError, baseline.ScopeError):
                observed[id_] = ("NOT_TESTED", "Approved request could not complete within authorization or resource bounds")
            emit_check_done(emit, id_, title, observed[id_][0], observed[id_][1])
    results = []
    legacy_remediation = {c["id"]: c["remediation"] for c in legacy}
    for definition in REGISTRY:
        id_ = definition["id"]
        status, evidence = observed.get(id_, ("NOT_TESTED", "Requires a verified test-class grant" if definition["implemented"] else "No reviewed execution context or integration is available"))
        if stop and id_ not in {c["id"] for c in legacy} | set(extra) | {"dns-public"}:
            status, evidence = "NOT_TESTED", "Exact-host redirect policy stopped additional requests"
        verification = "Re-run the versioned " + id_ + " observation after applying the relevant deployment configuration; evidence describes only the bounded response."
        results.append({"id": id_, "category": definition["category"], "title": definition["title"], "severity": "info", "confidence": "none" if status in ("NOT_TESTED", "NOT_APPLICABLE") else "high", "status": status, "evidence": evidence, "timestamp": timestamp(), "affectedUrl": url, "why": CHECK_IMPACTS.get(id_, IMPACTS.get(definition["category"], "This capability requires additional reviewed context before its security behavior can be assessed.")), "verification": verification if status not in ("NOT_TESTED", "NOT_APPLICABLE") else "No executable evidence", "remediation": legacy_remediation.get(id_, REMEDIATIONS.get(id_, "Provide a reviewed authorized context and integrate a bounded test before claiming this control was assessed.")), "version": VERSION})
    checks = [{"id": r["id"], "title": r["title"], "status": {"PASS": "passed", "WARNING": "observation", "FAIL": "observation", "NOT_TESTED": "skipped", "NOT_APPLICABLE": "skipped"}[r["status"]], "evidence": r["evidence"], "remediation": r["remediation"]} for r in results]
    findings = [{"checkId": r["id"], "title": r["title"], "severity": "info", "classification": "hardening", "description": r["why"], "evidence": r["evidence"], "remediation": r["remediation"]} for r in results if r["status"] in ("WARNING", "FAIL")]
    eligible_ids = {d["id"] for d in REGISTRY if d["implemented"] and d["scoreEligible"] and (not d["id"].startswith("deep-") or mode == "deep")}
    eligible = [r for r in results if r["id"] in eligible_ids and r["status"] != "NOT_APPLICABLE"]
    passed = sum(r["status"] == "PASS" for r in eligible)
    tested = sum(r["status"] not in ("NOT_TESTED", "NOT_APPLICABLE") for r in eligible)
    posture = {"value": None if stop else round(100 * passed / len(eligible)) if eligible else None, "coverage": None if stop else round(100 * tested / len(eligible)) if eligible else 0, "passed": passed, "tested": tested, "eligible": len(eligible), "label": "Bounded hardening posture; not vulnerability safety", "untestedCredit": 0}
    limitations = ["No exploit, authenticated, API, source, dependency or business-logic testing", "Header presence and cookie attributes do not establish application safety", "Bodies, cookie values, resource URLs and redirect destinations are omitted", "Deep grants are issued and revocations enforced by the trusted backend", "Only explicitly listed capabilities are implemented; no 150-test claim", "DNS includes connection address validation and bounded direct CAA/SPF/DMARC/MX observations; DNSSEC, inheritance and external intelligence are untested"]
    return {"type": "report", "checks": checks, "findings": findings, "manifest": {"engine": "shipsafe-security", "version": VERSION, "profile": mode + "-security-v1", "mode": mode, "scope": host, "scopeLimited": bool(stop), "scopeStopReason": stop, "requests": collector.count, "bodyByteLimit": baseline.BODY_LIMIT, "requestLimit": MAX_REQUESTS, "timeLimitSeconds": 40, "synthetic": False, "unifiedResults": results, "posture": posture, "registry": REGISTRY, "implemented": IMPLEMENTED, "deferred": DEFERRED_IDS, "limitations": limitations}}


def main():
    def emit(value):
        print(json.dumps(value, ensure_ascii=True), flush=True)
    if hasattr(signal, "SIGALRM"):
        def deadline(*_):
            raise TimeoutError("Assessment deadline")
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(40)
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise baseline.ScopeError("Configuration bound", "CONFIG_POLICY")
        config = json.loads(raw)
        emit({"type": "stage", "stage": "start", "message": "Starting bounded security observations"})
        emit(run(config, emit))
        return 0
    except Exception as exc:
        error = {"type": "error", "code": "SCOPE_REJECTED" if isinstance(exc, baseline.ScopeError) else "SECURITY_FAILED", "message": "Assessment could not complete within approved scope and limits"}
        if isinstance(exc, baseline.ScopeError):
            error["reason"] = exc.reason
        emit(error)
        return 1
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())

