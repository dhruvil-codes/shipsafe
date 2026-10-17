"""Versioned implemented capabilities and explicit unimplemented catalog entries."""
VERSION = "1.0.0"
BASELINE_IDS = [
    ("https", "tls", "Validated HTTPS connection"),
    ("https-redirect", "tls", "HTTP upgrades to HTTPS"),
    ("hsts", "headers", "HTTP Strict Transport Security"),
    ("csp", "headers", "Content Security Policy"),
    ("framing", "headers", "Framing restrictions"),
    ("nosniff", "headers", "MIME sniffing restriction"),
    ("referrer", "headers", "Referrer policy"),
    ("cookie-secure", "cookies", "Cookie Secure attribute"),
    ("cookie-httponly", "cookies", "Cookie HttpOnly attribute"),
    ("cookie-samesite", "cookies", "Cookie SameSite attribute"),
    ("cors", "cors", "CORS response observation"),
    ("error-disclosure", "configuration", "Returned-page diagnostic markers"),
    ("http-response", "configuration", "HTTP response received"),
]
EXTRA = [
    ("coop", "headers", "Cross-Origin-Opener-Policy"),
    ("coep", "headers", "Cross-Origin-Embedder-Policy"),
    ("corp", "headers", "Cross-Origin-Resource-Policy"),
    ("permissions", "headers", "Permissions Policy presence"),
    ("cache", "headers", "Cache policy observation"),
    ("server-disclosure", "headers", "Server version disclosure"),
    ("cookie-samesite-valid", "cookies", "Cookie SameSite value"),
    ("cookie-domain", "cookies", "Cookie domain scope"),
    ("cookie-path", "cookies", "Cookie path scope"),
    ("cookie-lifetime", "cookies", "Cookie lifetime observation"),
    ("cookie-prefix", "cookies", "Cookie prefix requirements"),
    ("mixed-content", "frontend", "Returned HTML insecure resource references"),
    ("script-inventory", "frontend", "Returned HTML script inventory"),
    ("tls-expiry", "tls", "Validated certificate expiry"),
    ("dns-public", "dns", "Public DNS address validation"),
    ("security-txt", "metadata", "Published security contact metadata"),
    ("robots-txt", "metadata", "Published robots metadata"),
    ("sitemap-xml", "metadata", "Published sitemap metadata"),
    ("library-inventory", "frontend", "Returned HTML library version markers"),
    ("source-map", "frontend", "Explicit returned-page source map reference"),
    ("dns-caa", "dns", "DNS CAA record observation"),
    ("dns-spf", "dns", "DNS SPF record observation"),
    ("dns-dmarc", "dns", "DNS DMARC record observation"),
    ("dns-mx", "dns", "DNS MX record observation"),
    ("deep-git-head", "configuration", "Exposed Git HEAD signature"),
    ("deep-discovery", "discovery", "Bounded same-host linked-page observation"),
    ("deep-cors", "cors", "Uncredentialed Origin response observation"),
    ("deep-nuclei", "vulnerability", "Nuclei reviewed-template assessment"),
    ("deep-zap", "vulnerability", "OWASP ZAP baseline passive assessment"),
]
DEFERRED = [
    ("dnssec", "dns", "DNSSEC chain validation"),
    ("certificate-transparency", "tls", "Certificate transparency history"),
    ("ocsp", "tls", "OCSP revocation status"),
    ("weak-tls", "tls", "Legacy TLS protocol negotiation"),
    ("tls-ciphers", "tls", "TLS cipher enumeration"),
    ("cve", "frontend", "Maintained CVE feed correlation"),
    ("client-config", "frontend", "Context-aware client configuration review"),
    ("injection", "injection", "Injection testing"),
    ("api", "api", "API authorization and schema testing"),
    ("authentication", "authentication", "Authentication and session testing"),
    ("jwt", "authentication", "JWT validation testing"),
    ("csrf", "csrf", "CSRF validation testing"),
    ("graphql", "api", "GraphQL security testing"),
]

def definition(item, implemented=True):
    id_, category, title = item
    deep = id_.startswith("deep-") or not implemented
    fixed_paths = {"deep-git-head": "/.git/HEAD", "security-txt": "/.well-known/security.txt", "robots-txt": "/robots.txt", "sitemap-xml": "/sitemap.xml"}
    paths = [fixed_paths[id_]] if id_ in fixed_paths else ["vetted passive template paths"] if id_ in ("deep-nuclei", "deep-zap") else ["submitted path", "validated same-host redirects"]
    if id_ == "deep-discovery":
        paths = ["up to 3 same-host HTML links without query or fragment"]
    if id_ == "source-map":
        paths = ["explicit same-host sourceMappingURL .map path in returned HTML; no query or fragment"]
    dns = id_ in ("dns-caa", "dns-spf", "dns-dmarc", "dns-mx", "dns-public")
    if dns:
        paths = ["exact submitted hostname DNS records", "_dmarc TXT only" if id_ == "dns-dmarc" else "no parent or sibling lookup"]
    return {"id": id_, "category": category, "title": title, "version": VERSION,
            "implemented": implemented, "authorization": "verified exact-host grant" if deep else "standard low-impact URL submission",
            "scope": "exact submitted hostname only", "methods": ["DNS"] if dns else ["GET", "HEAD"] if id_ in ("deep-nuclei", "deep-zap") else ["GET"] if implemented else [], "paths": paths if implemented else [],
            "budgets": {"sharedRequests": 20, "sharedSeconds": 40, "bodyBytesPerResponse": 65536, "dnsQueries": 4, "concurrentDnsQueries": 2},
            "evidence": "bounded response metadata or redacted boolean/count observations" if implemented else "none; no reviewed execution context",
            "evidenceSchema": {"type": "string", "minLength": 1, "maxLength": 12000, "redaction": "No cookie values, bodies, secrets, resource URLs or redirect destinations"},
            "severityRules": "INFO hardening observations only; no exploit severity inferred",
            "confidenceRules": "High only for a completed bounded observation; none for unavailable or inapplicable checks",
            "severity": "info", "confidence": "high" if implemented else "none",
            "scoreEligible": id_ not in ("script-inventory", "library-inventory", "security-txt", "robots-txt", "sitemap-xml", "cache", "deep-discovery", "dns-mx")}

REGISTRY = [definition(item) for item in BASELINE_IDS + EXTRA] + [definition(item, False) for item in DEFERRED]
IMPLEMENTED = [entry["id"] for entry in REGISTRY if entry["implemented"]]
DEFERRED_IDS = [entry["id"] for entry in REGISTRY if not entry["implemented"]]
