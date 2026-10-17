"""Bounded direct DNS observations; no raw TXT or mail addresses enter evidence."""
import concurrent.futures
import datetime
import ipaddress
import re
import shlex
import subprocess
import time

DIG = "/usr/bin/dig"
MAX_OUTPUT = 65536
CHECKS = ("dns-caa", "dns-spf", "dns-dmarc", "dns-mx")
TITLES = {"dns-caa": "DNS CAA record inspection", "dns-spf": "DNS SPF email authentication policy", "dns-dmarc": "DNS DMARC alignment policy", "dns-mx": "DNS mail exchange routing"}


def _query(host, kind, deadline, grant_check):
    grant_check()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        result = subprocess.run([DIG, "-r", "+timeout=2", "+tries=1", "+noall", "+comments", "+answer", "+ignore", host, kind],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=min(3, remaining), check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C"}, cwd="/")
    except (OSError, subprocess.TimeoutExpired):
        return None
    grant_check()
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT or time.monotonic() >= deadline:
        return None
    try:
        output = result.stdout.decode("ascii")
    except UnicodeDecodeError:
        return None
    statuses = re.findall(r"^;; ->>HEADER<<- .*status: ([A-Z]+),", output, re.M)
    if len(statuses) != 1 or statuses[0] not in ("NOERROR", "NXDOMAIN") or re.search(r"^;; flags: [^;]*\btc\b", output, re.M):
        return None
    records = []
    for line in output.splitlines():
        if not line or line.startswith(";"):
            continue
        fields = line.split(None, 4)
        if len(fields) != 5:
            return None
        owner, ttl, dns_class, record_type, payload = fields
        if owner.rstrip(".").lower() == host.lower() and dns_class == "IN" and record_type == kind:
            records.append(payload)
    return records


def _txt(records):
    try:
        if any(not value.startswith('"') for value in records):
            return None
        return ["".join(shlex.split(value)) for value in records]
    except ValueError:
        return None


def _spf_valid(value):
    tokens = value.split()
    if len(tokens) < 2 or tokens[0].lower() != "v=spf1":
        return False
    for token in tokens[1:]:
        term = token[1:] if token[0] in "+-~?" else token
        if term == "all":
            continue
        if term.startswith(("ip4:", "ip6:")):
            try:
                network = ipaddress.ip_network(term[4:], strict=False)
                if network.version != (4 if term.startswith("ip4:") else 6):
                    return False
            except ValueError:
                return False
        elif not re.fullmatch(r"(?:include:|exists:|redirect=|exp=)[a-zA-Z0-9._%{}+/-]+|(?:a|mx|ptr)(?::[a-zA-Z0-9._%{}+-]+)?(?:/\d{1,3})?(?://\d{1,3})?", term):
            return False
    return True


def _observe(check, records):
    if records is None:
        return "NOT_TESTED", "DNS observation unavailable or incomplete; no policy conclusion was made."
    if check == "dns-caa":
        if not records:
            return "WARNING", "No direct CAA record observed. Parent policy inheritance was not assessed; this is informational."
        valid = all(re.fullmatch(r'\d{1,3}\s+[a-zA-Z0-9-]+\s+"[^"\r\n]*"', value) and int(value.split()[0]) <= 255 for value in records)
        return ("PASS" if valid else "WARNING"), "Direct CAA records observed. Issuer authorization and parent inheritance were not evaluated."
    if check == "dns-mx":
        if not records:
            return "WARNING", "No direct MX record observed. Mail capability and implicit fallback were not assessed; this is informational."
        valid = all(re.fullmatch(r"\d{1,5}\s+[a-zA-Z0-9.-]+", value) and int(value.split()[0]) <= 65535 for value in records)
        return ("PASS" if valid else "WARNING"), "Direct MX records observed. Mail delivery and receiving-host security were not tested."
    texts = _txt(records)
    if texts is None:
        return "NOT_TESTED", "TXT response could not be parsed safely; no policy conclusion was made."
    if check == "dns-spf":
        selected = [value for value in texts if re.match(r"^v=spf1(?:\s|$)", value, re.I)]
        if not selected:
            return "WARNING", "No direct SPF declaration observed. Mail-sender configuration was not assessed; this is informational."
        if len(selected) != 1:
            return "WARNING", "Multiple direct SPF declarations observed; policy evaluation was not attempted."
        if not _spf_valid(selected[0]):
            return "WARNING", "Direct SPF declaration has unrecognized or malformed selected syntax; includes and DNS expansion were not evaluated."
        if any(term in ("all", "+all") for term in selected[0].split()[1:]):
            return "WARNING", "Direct SPF declaration contains an unrestricted all mechanism. Sender authorization was not evaluated."
        return "PASS", "One direct SPF declaration with recognized selected syntax observed. Includes, DNS lookup limits and sender authorization were not evaluated."
    selected = [value for value in texts if re.match(r"^v=DMARC1(?:\s*;|$)", value, re.I)]
    if not selected:
        return "WARNING", "No direct DMARC declaration observed. Organizational-domain inheritance was not assessed; this is informational."
    if len(selected) != 1:
        return "WARNING", "Multiple direct DMARC declarations observed; effective policy was not evaluated."
    tags = {}
    for part in selected[0].split(";"):
        if not part.strip():
            continue
        pair = part.strip().split("=", 1)
        if len(pair) != 2 or pair[0].lower() in tags or not pair[1].strip():
            return "WARNING", "Direct DMARC declaration has malformed or duplicate tags; effective policy was not evaluated."
        tags[pair[0].lower()] = pair[1].strip()
    if tags.get("p") not in ("none", "quarantine", "reject"):
        return "WARNING", "Direct DMARC declaration lacks a recognized policy tag; effective policy was not evaluated."
    if tags["p"] == "none":
        return "WARNING", "Direct DMARC declaration uses monitoring policy. Alignment, reporting and inherited policy were not evaluated."
    return "PASS", "Direct DMARC declaration contains a quarantine or reject policy tag. Alignment, reporting and inherited policy were not evaluated."


def observe_dns(hostname, deadline, grant_check=lambda: None, emit=None):
    """At most two fixed dig processes share the collector's monotonic deadline."""
    if not isinstance(hostname, str) or not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", hostname) or any(len(part) > 63 for part in hostname.split(".")):
        return {key: ("NOT_TESTED", "Unsupported DNS hostname; no DNS command executed.") for key in CHECKS}
    jobs = (("dns-caa", hostname, "CAA"), ("dns-spf", hostname, "TXT"), ("dns-dmarc", "_dmarc." + hostname, "TXT"), ("dns-mx", hostname, "MX"))
    def run_one(check, host, kind):
        if emit:
            emit({"type": "stage", "stage": "check", "checkId": check, "message": "Evaluating " + TITLES[check] + "...", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")})
        result = _observe(check, _query(host, kind, deadline, grant_check))
        if emit:
            status = {"PASS": "passed", "WARNING": "observation", "NOT_TESTED": "skipped"}.get(result[0], "skipped")
            emit({"type": "stage", "stage": "check_done", "checkId": check, "status": status, "message": "[" + status.upper() + "] " + TITLES[check] + " — " + result[1], "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")})
        return result
    result = {}
    for key, host, kind in jobs:
        result[key] = run_one(key, host, kind)
    grant_check()
    return result
