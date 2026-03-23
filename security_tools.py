"""
Security scanning tools for Site Audit Agent.
Self-contained module — no imports from agent.py.

Checks:
  1. SSL/TLS certificate & protocol analysis
  2. Cookie security attributes
  3. Sensitive path / file exposure
  4. CORS misconfiguration
  5. Mixed content (HTTP resources on HTTPS)
  6. Email security (SPF, DMARC)
  7. Information disclosure (headers, error pages)
  8. Deep security header analysis with scoring/grading
"""
from __future__ import annotations

import re
import socket
import ssl
import subprocess
import uuid
from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════
Finding = Tuple[str, str]  # (severity, message)


def _hex8() -> str:
    return uuid.uuid4().hex[:8]


# ═══════════════════════════════════════════════════════════
#  1. SSL / TLS
# ═══════════════════════════════════════════════════════════
def check_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """Analyse SSL/TLS certificate and connection security."""
    findings: List[Finding] = []
    data: Dict[str, Any] = {"domain": domain, "port": port}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                data["protocol"] = ssock.version()
                cipher = ssock.cipher()
                data["cipher"] = cipher[0] if cipher else ""
                data["cipher_bits"] = cipher[2] if cipher and len(cipher) > 2 else 0

                # Subject / issuer
                subj = dict(x[0] for x in cert.get("subject", ()))
                iss = dict(x[0] for x in cert.get("issuer", ()))
                data["subject_cn"] = subj.get("commonName", "")
                data["issuer_org"] = iss.get("organizationName", "")

                # SANs
                data["san"] = [
                    v for t, v in cert.get("subjectAltName", ()) if t == "DNS"
                ]

                # Expiration
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.utcnow()).days
                    data["expires"] = not_after
                    data["days_until_expiry"] = days
                    if days < 0:
                        findings.append(("critical", "SSL certificate has EXPIRED"))
                    elif days < 14:
                        findings.append(("high", f"Certificate expires in {days} days"))
                    elif days < 30:
                        findings.append(("medium", f"Certificate expires in {days} days"))

                # Weak protocol
                if data["protocol"] in ("TLSv1", "TLSv1.1"):
                    findings.append(
                        ("high", f"Deprecated protocol: {data['protocol']}")
                    )

    except ssl.SSLCertVerificationError as e:
        findings.append(("critical", f"SSL verification failed: {e}"))
        data["error"] = str(e)
    except Exception as e:
        findings.append(("high", f"SSL connection failed: {e}"))
        data["error"] = str(e)

    return {"ok": "error" not in data, "findings": findings, "data": data}


# ═══════════════════════════════════════════════════════════
#  2. COOKIE SECURITY
# ═══════════════════════════════════════════════════════════
def check_cookies(url: str, session: requests.Session) -> Dict[str, Any]:
    """Inspect Set-Cookie headers for security attributes."""
    findings: List[Finding] = []
    cookies_data: List[Dict[str, Any]] = []

    try:
        resp = session.get(url, timeout=15, allow_redirects=True)

        # Gather raw Set-Cookie headers for flag detection
        raw_cookies: List[str] = []
        for k, v in resp.raw.headers.items():
            if k.lower() == "set-cookie":
                raw_cookies.append(v)

        for cookie in resp.cookies:
            # Match the raw header for this cookie
            raw = next(
                (rc for rc in raw_cookies if cookie.name in rc), ""
            )
            httponly = "httponly" in raw.lower()
            sm = re.search(r"samesite\s*=\s*(\w+)", raw, re.I)
            samesite = sm.group(1) if sm else "not set"

            info = {
                "name": cookie.name,
                "domain": cookie.domain or "",
                "path": cookie.path or "/",
                "secure": cookie.secure,
                "httponly": httponly,
                "samesite": samesite,
            }
            cookies_data.append(info)

            if not cookie.secure:
                findings.append(
                    ("medium", f"Cookie '{cookie.name}' missing Secure flag")
                )
            if not httponly:
                findings.append(
                    ("medium", f"Cookie '{cookie.name}' missing HttpOnly flag")
                )
            if samesite == "not set":
                findings.append(
                    ("low", f"Cookie '{cookie.name}' missing SameSite")
                )

    except Exception as e:
        findings.append(("medium", f"Cookie check failed: {e}"))

    return {
        "ok": True,
        "findings": findings,
        "data": {"url": url, "cookies": cookies_data},
    }


# ═══════════════════════════════════════════════════════════
#  3. SENSITIVE PATH / FILE EXPOSURE
# ═══════════════════════════════════════════════════════════
_SENSITIVE_PATHS = [
    ("/.env", "Environment config", "high"),
    ("/.git/config", "Git config", "high"),
    ("/.git/HEAD", "Git HEAD", "high"),
    ("/.htpasswd", "Apache passwords", "critical"),
    ("/phpinfo.php", "PHP info", "high"),
    ("/wp-login.php", "WordPress login", "medium"),
    ("/wp-admin/", "WordPress admin", "medium"),
    ("/administrator/", "Joomla admin", "medium"),
    ("/server-status", "Apache status", "medium"),
    ("/server-info", "Apache info", "medium"),
    ("/elmah.axd", ".NET error log", "high"),
    ("/trace.axd", ".NET trace", "high"),
    ("/web.config", "IIS config", "high"),
    ("/.DS_Store", "macOS metadata", "low"),
    ("/.gitignore", "Git ignore rules", "low"),
    ("/crossdomain.xml", "Flash policy", "low"),
    ("/backup/", "Backup directory", "medium"),
    ("/debug/", "Debug endpoint", "medium"),
    ("/api/", "API root", "info"),
    ("/graphql", "GraphQL endpoint", "info"),
    ("/.well-known/security.txt", "Security policy", "positive"),
    ("/robots.txt.bak", "Robots backup", "low"),
    ("/sitemap.xml.bak", "Sitemap backup", "low"),
]


def check_sensitive_paths(
    domain: str, session: requests.Session
) -> Dict[str, Any]:
    """Probe for common sensitive files and directories."""
    findings: List[Finding] = []
    exposed: List[Dict[str, Any]] = []
    base = f"https://{domain}"

    for path, desc, severity in _SENSITIVE_PATHS:
        try:
            resp = session.get(
                base + path, timeout=8, allow_redirects=False
            )
            if resp.status_code == 200:
                entry = {
                    "path": path,
                    "status": 200,
                    "size": len(resp.content),
                    "description": desc,
                }
                if severity == "positive":
                    entry["risk"] = "positive"
                else:
                    entry["risk"] = severity
                    findings.append(
                        (severity, f"Exposed: {path} ({desc})")
                    )
                exposed.append(entry)
        except Exception:
            pass

    return {
        "ok": True,
        "findings": findings,
        "data": {"checked": len(_SENSITIVE_PATHS), "exposed": exposed},
    }


# ═══════════════════════════════════════════════════════════
#  4. CORS MISCONFIGURATION
# ═══════════════════════════════════════════════════════════
def check_cors(
    url: str, domain: str, session: requests.Session
) -> Dict[str, Any]:
    """Test CORS by sending forged Origin headers."""
    findings: List[Finding] = []
    results: List[Dict[str, str]] = []

    origins = [
        f"https://{domain}",
        "https://evil.example.com",
        f"https://sub.{domain}",
        "null",
    ]

    for origin in origins:
        try:
            resp = session.get(
                url, timeout=10, headers={"Origin": origin},
                allow_redirects=True,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            results.append({"origin": origin, "acao": acao, "acac": acac})

            if acao == "*":
                findings.append(("medium", "CORS wildcard: *"))
            if acao == origin and "evil" in origin:
                findings.append(
                    ("high", f"CORS reflects arbitrary origin: {origin}")
                )
            if acac.lower() == "true" and acao == "*":
                findings.append(
                    ("high", "CORS credentials with wildcard origin")
                )
            if acao == "null":
                findings.append(("medium", "CORS allows null origin"))
        except Exception:
            pass

    return {
        "ok": True,
        "findings": findings,
        "data": {"url": url, "cors_tests": results},
    }


# ═══════════════════════════════════════════════════════════
#  5. MIXED CONTENT
# ═══════════════════════════════════════════════════════════
def check_mixed_content(
    pages: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Find HTTP resources referenced on HTTPS pages."""
    findings: List[Finding] = []
    issues: List[Dict[str, str]] = []

    for url, page in pages.items():
        if not url.startswith("https://"):
            continue
        for link in page.get("external_links", []):
            if link.startswith("http://"):
                issues.append({"page": url, "resource": link, "type": "link"})

    if issues:
        findings.append(
            ("low", f"{len(issues)} HTTP link(s) on HTTPS pages")
        )

    return {
        "ok": True,
        "findings": findings,
        "data": {"mixed_content_issues": issues[:50]},
    }


# ═══════════════════════════════════════════════════════════
#  6. EMAIL SECURITY  (SPF / DMARC via nslookup)
# ═══════════════════════════════════════════════════════════
def _nslookup_txt(query: str) -> str:
    try:
        r = subprocess.run(
            ["nslookup", "-type=TXT", query],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout
    except Exception:
        return ""


def check_email_security(domain: str) -> Dict[str, Any]:
    """Check SPF and DMARC DNS records."""
    findings: List[Finding] = []
    records: Dict[str, Any] = {}

    # SPF
    out = _nslookup_txt(domain)
    m = re.search(r'"(v=spf1[^"]*)"', out)
    if m:
        records["spf"] = m.group(1)
        if "+all" in m.group(1):
            findings.append(("high", "SPF uses +all (allows any sender)"))
        elif "~all" in m.group(1):
            findings.append(("low", "SPF uses ~all (soft-fail, consider -all)"))
    else:
        findings.append(("medium", "No SPF record found"))
        records["spf"] = None

    # DMARC
    out = _nslookup_txt(f"_dmarc.{domain}")
    m = re.search(r'"(v=DMARC1[^"]*)"', out)
    if m:
        records["dmarc"] = m.group(1)
        if "p=none" in m.group(1):
            findings.append(("low", "DMARC policy is 'none' (monitor only)"))
    else:
        findings.append(("medium", "No DMARC record found"))
        records["dmarc"] = None

    return {
        "ok": True,
        "findings": findings,
        "data": {"domain": domain, "records": records},
    }


# ═══════════════════════════════════════════════════════════
#  7. INFORMATION DISCLOSURE
# ═══════════════════════════════════════════════════════════
def check_info_disclosure(
    url: str, domain: str, session: requests.Session
) -> Dict[str, Any]:
    """Detect information leakage in headers and error pages."""
    findings: List[Finding] = []
    disclosures: List[Dict[str, str]] = []

    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Server version
        server = headers.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(("low", f"Server discloses version: {server}"))
            disclosures.append({"type": "server_version", "value": server})

        # X-Powered-By
        xpb = headers.get("x-powered-by", "")
        if xpb:
            findings.append(("low", f"X-Powered-By: {xpb}"))
            disclosures.append({"type": "x-powered-by", "value": xpb})

        # X-AspNet-Version
        aspnet = headers.get("x-aspnet-version", "")
        if aspnet:
            findings.append(("medium", f"X-AspNet-Version: {aspnet}"))
            disclosures.append({"type": "aspnet_version", "value": aspnet})

        # Error page inspection
        err_url = f"https://{domain}/nonexistent-{_hex8()}"
        try:
            err = session.get(err_url, timeout=10, allow_redirects=True)
            body = err.text[:8000].lower()
            patterns = [
                (r"stack\s*trace", "Stack trace in error page"),
                (r"exception|traceback", "Exception details in error page"),
                (r"sql\s*syntax|mysql|postgresql|sqlite",
                 "Database error in error page"),
                (r"php\s*(?:warning|error|notice)", "PHP error in error page"),
                (r"<address>.*?server at", "Server info in error page"),
            ]
            for pat, msg in patterns:
                if re.search(pat, body, re.I):
                    findings.append(("medium", msg))
                    disclosures.append({"type": "error_page", "detail": msg})
        except Exception:
            pass

    except Exception as e:
        return {
            "ok": False,
            "findings": [("medium", f"Info disclosure check failed: {e}")],
            "data": {},
        }

    return {
        "ok": True,
        "findings": findings,
        "data": {"url": url, "disclosures": disclosures},
    }


# ═══════════════════════════════════════════════════════════
#  8. DEEP SECURITY HEADER ANALYSIS  (scored + graded)
# ═══════════════════════════════════════════════════════════
def check_security_headers_deep(
    url: str, session: requests.Session
) -> Dict[str, Any]:
    """Comprehensive header analysis with A–F grading."""
    findings: List[Finding] = []

    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        h = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        return {
            "ok": False,
            "findings": [("high", f"Request failed: {e}")],
            "data": {},
        }

    checks: Dict[str, Any] = {}
    score = 0
    max_score = 0

    # ── HSTS ──
    max_score += 10
    hsts = h.get("strict-transport-security", "")
    if hsts:
        score += 5
        checks["hsts"] = {"present": True, "value": hsts}
        if "includesubdomains" in hsts.lower():
            score += 3
        if "preload" in hsts.lower():
            score += 2
        ma = re.search(r"max-age=(\d+)", hsts)
        if ma and int(ma.group(1)) < 31536000:
            findings.append(
                ("low", f"HSTS max-age {ma.group(1)}s (recommend ≥31536000)")
            )
    else:
        findings.append(("high", "Missing HSTS"))
        checks["hsts"] = {"present": False}

    # ── CSP ──
    max_score += 10
    csp = h.get("content-security-policy", "")
    if csp:
        score += 5
        checks["csp"] = {"present": True, "value": csp[:200]}
        if "'unsafe-inline'" in csp:
            findings.append(("medium", "CSP allows 'unsafe-inline'"))
        elif "'unsafe-eval'" in csp:
            findings.append(("medium", "CSP allows 'unsafe-eval'"))
        else:
            score += 5
    else:
        findings.append(("high", "Missing CSP"))
        checks["csp"] = {"present": False}

    # ── X-Content-Type-Options ──
    max_score += 5
    xcto = h.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        score += 5
        checks["xcto"] = {"present": True}
    else:
        findings.append(("medium", "Missing X-Content-Type-Options: nosniff"))
        checks["xcto"] = {"present": False}

    # ── X-Frame-Options ──
    max_score += 5
    xfo = h.get("x-frame-options", "")
    if xfo:
        score += 5
        checks["xfo"] = {"present": True, "value": xfo}
    elif "frame-ancestors" in csp:
        score += 5
        checks["xfo"] = {"present": False, "note": "Covered by CSP frame-ancestors"}
    else:
        findings.append(("medium", "Missing X-Frame-Options"))
        checks["xfo"] = {"present": False}

    # ── Referrer-Policy ──
    max_score += 5
    rp = h.get("referrer-policy", "")
    if rp:
        score += 5
        checks["referrer"] = {"present": True, "value": rp}
    else:
        findings.append(("low", "Missing Referrer-Policy"))
        checks["referrer"] = {"present": False}

    # ── Permissions-Policy ──
    max_score += 5
    pp = h.get("permissions-policy", "")
    if pp:
        score += 5
        checks["permissions"] = {"present": True, "value": pp[:200]}
    else:
        findings.append(("low", "Missing Permissions-Policy"))
        checks["permissions"] = {"present": False}

    # Grade
    pct = score / max_score if max_score else 0
    grade = (
        "A" if pct >= 0.9 else
        "B" if pct >= 0.7 else
        "C" if pct >= 0.5 else
        "D" if pct >= 0.3 else "F"
    )

    return {
        "ok": True,
        "findings": findings,
        "data": {
            "url": url,
            "score": score,
            "max_score": max_score,
            "grade": grade,
            "checks": checks,
        },
    }
