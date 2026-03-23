"""
Pentest Agent v3.0
━━━━━━━━━━━━━━━━━━
Autonomous penetration testing agent with LLM-driven terminal access.
Self-bootstrapping · Ollama-powered · Rich terminal UI
Windows PowerShell compatible · Full security scanning

Usage:
    python agent.py                 # interactive mode
    python agent.py example.com    # target specific domain
    python agent.py --resume       # resume from checkpoint
    python agent.py --fresh        # ignore checkpoint, start fresh
"""
from __future__ import annotations

# ═══════════════════════════════════════════════════════════
#  STDLIB IMPORTS  (always available)
# ═══════════════════════════════════════════════════════════
import importlib
import importlib.util
import json
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ═══════════════════════════════════════════════════════════
#  PHASE 0 — SELF-BOOTSTRAP  (before 3rd-party imports)
# ═══════════════════════════════════════════════════════════
_REQUIRED = {
    "ollama": "ollama",
    "requests": "requests",
    "bs4": "beautifulsoup4",
    "lxml": "lxml",
    "playwright": "playwright",
    "rich": "rich",
    "sqlmap": "sqlmap",
}


def _pip_install(*pkgs: str) -> None:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet",
         "--disable-pip-version-check"] + list(pkgs),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _bootstrap_packages() -> List[str]:
    missing = [
        pip for mod, pip in _REQUIRED.items()
        if importlib.util.find_spec(mod) is None
    ]
    if missing:
        print(f"[bootstrap] Installing: {', '.join(missing)}")
        _pip_install(*missing)
    return missing


def _bootstrap_playwright() -> str:
    try:
        r = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True, text=True, timeout=300,
        )
        return "ok" if r.returncode == 0 else f"warn: {r.stderr[:100]}"
    except Exception as e:
        return f"fail: {e}"


def _bootstrap_lighthouse() -> Tuple[bool, str]:
    if not shutil.which("npx"):
        return False, "Node.js not found — Lighthouse disabled"
    try:
        r = subprocess.run(
            ["npx", "--yes", "lighthouse", "--version"],
            capture_output=True, text=True, timeout=90, shell=True,
        )
        if r.returncode == 0:
            return True, f"v{r.stdout.strip()}"
    except Exception:
        pass
    return False, "Lighthouse unavailable"


def _bootstrap_ollama(model: str) -> Tuple[bool, str]:
    try:
        r = subprocess.run(
            ["ollama", "--version"], capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return False, "ollama --version failed"
        ver = r.stdout.strip()
    except FileNotFoundError:
        return False, "Ollama not in PATH"
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:11434", timeout=5).close()
    except Exception:
        return False, "API unreachable at 127.0.0.1:11434"
    r2 = subprocess.run(
        ["ollama", "list"], capture_output=True, text=True, timeout=15,
    )
    if model.split(":")[0] not in r2.stdout:
        print(f"[bootstrap] Pulling {model} …")
        subprocess.run(["ollama", "pull", model], timeout=1800)
    return True, ver


def _detect_tools() -> Dict[str, bool]:
    """Detect security tools in PATH."""
    tools = ["nmap", "sqlmap", "nuclei", "subfinder", "httpx",
             "ffuf", "nikto", "gobuster", "dirsearch", "wpscan",
             "testssl.sh", "whatweb", "wfuzz", "amass"]
    found = {}
    for t in tools:
        found[t] = shutil.which(t) is not None
    # sqlmap via python module
    if not found["sqlmap"] and importlib.util.find_spec("sqlmap") is not None:
        found["sqlmap"] = True
    # Check WSL availability
    found["wsl"] = shutil.which("wsl") is not None
    return found


def _detect_wsl_distros() -> List[str]:
    """Detect installed WSL distributions."""
    if not shutil.which("wsl"):
        return []
    try:
        r = subprocess.run(
            ["wsl", "--list", "--quiet"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return []
        distros = []
        for line in r.stdout.strip().splitlines():
            name = line.strip().strip('\x00')
            if name and name.lower() not in ('windows subsystem for linux',):
                distros.append(name)
        return distros
    except Exception:
        return []


# ── Execute bootstrap ────────────────────────────────────
print("[bootstrap] Checking dependencies …")
_bootstrap_packages()
_PW_STATUS = _bootstrap_playwright()
_LH_OK, _LH_MSG = _bootstrap_lighthouse()
_OL_OK, _OL_MSG = _bootstrap_ollama("qwen3:14b")
if not _OL_OK:
    print(f"[FATAL] Ollama: {_OL_MSG}")
    sys.exit(1)
_DETECTED_TOOLS = _detect_tools()
_WSL_DISTROS = _detect_wsl_distros()
if _WSL_DISTROS:
    print(f"[bootstrap] WSL distros found: {', '.join(_WSL_DISTROS)}")

# ═══════════════════════════════════════════════════════════
#  PHASE 1 — THIRD-PARTY IMPORTS  (guaranteed present)
# ═══════════════════════════════════════════════════════════
import ollama
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.prompt import Prompt, Confirm
from rich import box
from rich.markup import escape as rich_escape

from security_tools import (
    check_ssl, check_cookies, check_sensitive_paths,
    check_cors, check_mixed_content, check_email_security,
    check_info_disclosure, check_security_headers_deep,
)

# ═══════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════
MODEL = "qwen3:14b"
DEFAULT_DOMAIN = "getaxiom.ca"

OUTPUT_DIR = Path("audit_output")
CHECKPOINT_PATH = OUTPUT_DIR / "checkpoint.json"
JSON_REPORT = OUTPUT_DIR / "audit_report.json"
MD_REPORT = OUTPUT_DIR / "audit_summary.md"
SCREENSHOTS_DIR = OUTPUT_DIR / "screenshots"
LIGHTHOUSE_DIR = OUTPUT_DIR / "lighthouse"
SCAN_LOGS_DIR = OUTPUT_DIR / "scan_logs"

MAX_STEPS = 50
REQUEST_TIMEOUT = 20
MAX_EVENT_CHARS = 3000
BOOTSTRAP_BATCH = 6
COMMAND_TIMEOUT = 300

SCAN_PROFILES = {
    "quick":    {"max_steps": 20, "batch": 4, "broken_sample": 30},
    "standard": {"max_steps": 50, "batch": 6, "broken_sample": 80},
    "deep":     {"max_steps": 100, "batch": 8, "broken_sample": 150},
}

LIGHTHOUSE_AVAILABLE = _LH_OK
PLAYWRIGHT_AVAILABLE = (_PW_STATUS == "ok")

for _d in [OUTPUT_DIR, SCREENSHOTS_DIR, LIGHTHOUSE_DIR, SCAN_LOGS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════
#  SHARED CLIENTS
# ═══════════════════════════════════════════════════════════
# Explicit IPv4 — avoids Windows IPv6 "localhost" resolution bug
llm = ollama.Client(host="http://127.0.0.1:11434")

http = requests.Session()
http.headers.update({"User-Agent": "SiteAuditAgent/2.0 (+self-audit)"})

console = Console()

# ═══════════════════════════════════════════════════════════
#  PLAYWRIGHT SINGLETON
# ═══════════════════════════════════════════════════════════
_pw_ctx = None
_pw_browser = None


def _get_browser():
    global _pw_ctx, _pw_browser
    if _pw_browser is None:
        from playwright.sync_api import sync_playwright
        _pw_ctx = sync_playwright().start()
        _pw_browser = _pw_ctx.chromium.launch(headless=True)
    return _pw_browser


def _close_browser():
    global _pw_ctx, _pw_browser
    if _pw_browser:
        try:
            _pw_browser.close()
        except Exception:
            pass
        _pw_browser = None
    if _pw_ctx:
        try:
            _pw_ctx.stop()
        except Exception:
            pass
        _pw_ctx = None


# ═══════════════════════════════════════════════════════════
#  RICH UI HELPERS
# ═══════════════════════════════════════════════════════════
_ASCII_BANNER = r"""
[bold bright_red]  ██████╗ ███████╗███╗   ██╗████████╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗
  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
  ██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝[/]
[bold bright_cyan]              ═══  Autonomous Pentest Agent v3.0  ═══[/]
[dim]                    Powered by Qwen3 · Ollama · Playwright[/]
"""


def ui_banner(domain: str, profile: str = "standard") -> None:
    console.print(_ASCII_BANNER)
    pw_icon = "[green]✔[/]" if PLAYWRIGHT_AVAILABLE else "[red]✘[/]"
    lh_icon = "[green]✔[/]" if LIGHTHOUSE_AVAILABLE else "[red]✘[/]"
    avail = [t for t, ok in _DETECTED_TOOLS.items() if ok]
    avail_str = ", ".join(avail) if avail else "[dim]none detected[/]"
    lines = [
        f"[dim]Target:[/]   [bold bright_white]{domain}[/]",
        f"[dim]Model:[/]    [bold]{MODEL}[/]",
        f"[dim]Profile:[/]  [bold]{profile}[/]",
        "",
        f"  [green]✔[/] Ollama   {pw_icon} Playwright   {lh_icon} Lighthouse",
        f"  [dim]External tools:[/] {avail_str}",
    ]
    if not LIGHTHOUSE_AVAILABLE:
        lines.append(f"  [dim]{_LH_MSG}[/]")
    console.print(Panel("\n".join(lines), border_style="bright_red",
                        padding=(1, 2)))


def ui_phase(name: str) -> None:
    console.print(Rule(f"[bold bright_magenta]{name}[/]", style="dim"))


def ui_step(n: int) -> None:
    console.print(f"\n[bold bright_yellow]━━ Step {n} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")


def ui_tool(name: str, detail: str, ok: bool, duration: float,
            summary: str = "") -> None:
    icon = "[green]✔[/]" if ok else "[red]✘[/]"
    d = f"[dim]{duration:.1f}s[/]"
    line = f"  [bold cyan]▸[/] {name}  {detail}"
    console.print(line)
    summ = f"    {icon} {summary} │ {d}" if summary else f"    {icon} {d}"
    console.print(summ)


def ui_llm(action: str, detail: str, duration: float) -> None:
    console.print(f"  [bold bright_white]🤖 LLM[/] [dim]({duration:.1f}s)[/]")
    console.print(f"    → [bold]{action}[/]  {detail}")


def ui_dashboard(state: "AgentState") -> None:
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="left", ratio=1)
    grid.add_row(
        f"[bold cyan]Pages[/]  {len(state.pages)}",
        f"[bold yellow]Queue[/]  {len(state.queued_urls)}",
    )
    grid.add_row(
        f"[bold red]Findings[/]  {len(state.findings)}",
        f"[bold green]Steps[/]  {state.step}/{MAX_STEPS}",
    )
    console.print(Panel(grid, title="[bold]Dashboard[/]",
                        border_style="bright_blue", padding=(0, 2)))


def ui_done(elapsed: float) -> None:
    console.print(Panel(
        f"[bold green]✅  Audit complete[/]\n"
        f"Reports saved to [bold]{OUTPUT_DIR}/[/]\n"
        f"Runtime: [bold]{elapsed:.1f}s[/]",
        border_style="green", padding=(1, 2),
    ))


# ═══════════════════════════════════════════════════════════
#  DATA MODELS
# ═══════════════════════════════════════════════════════════
@dataclass
class ToolResult:
    ok: bool
    output: str
    error: str = ""
    duration_s: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentState:
    session_id: str
    domain: str
    start_url: str
    goal: str
    step: int = 0
    queued_urls: List[str] = field(default_factory=list)
    seen_urls: Set[str] = field(default_factory=set)
    pages: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    recent_events: List[Dict[str, Any]] = field(default_factory=list)
    memory_summary: str = ""
    recent_tool_signatures: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "domain": self.domain,
            "start_url": self.start_url,
            "goal": self.goal,
            "step": self.step,
            "queued_urls": self.queued_urls,
            "seen_urls": sorted(self.seen_urls),
            "pages": self.pages,
            "findings": self.findings,
            "notes": self.notes,
            "recent_events": self.recent_events[-20:],
            "memory_summary": self.memory_summary,
            "recent_tool_signatures": self.recent_tool_signatures,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentState":
        return cls(
            session_id=data["session_id"],
            domain=data["domain"],
            start_url=data["start_url"],
            goal=data["goal"],
            step=data.get("step", 0),
            queued_urls=data.get("queued_urls", []),
            seen_urls=set(data.get("seen_urls", [])),
            pages=data.get("pages", {}),
            findings=data.get("findings", []),
            notes=data.get("notes", []),
            recent_events=data.get("recent_events", []),
            memory_summary=data.get("memory_summary", ""),
            recent_tool_signatures=data.get("recent_tool_signatures", []),
        )

    def checkpoint(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "AgentState":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ═══════════════════════════════════════════════════════════
#  TOOL REGISTRY
# ═══════════════════════════════════════════════════════════
class ToolRegistry:
    def __init__(self) -> None:
        self.tools: Dict[str, Callable[..., ToolResult]] = {}

    def register(self, name: str, fn: Callable[..., ToolResult]) -> None:
        self.tools[name] = fn

    def call(self, name: str, **kwargs: Any) -> ToolResult:
        if name not in self.tools:
            return ToolResult(ok=False, output="", error=f"Unknown tool: {name}")
        start = time.time()
        try:
            result = self.tools[name](**kwargs)
            result.duration_s = time.time() - start
            return result
        except Exception:
            return ToolResult(
                ok=False, output="", error=traceback.format_exc(),
                duration_s=time.time() - start,
            )


# ═══════════════════════════════════════════════════════════
#  GLOBALS
# ═══════════════════════════════════════════════════════════
STATE: Optional[AgentState] = None


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════
def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    out = f"{scheme}://{netloc}{path}{query}"
    if out.endswith("/") and path != "/":
        out = out[:-1]
    return out


def same_domain(url: str, domain: str) -> bool:
    host = urlparse(url).netloc.lower()
    return host == domain.lower() or host.endswith("." + domain.lower())


def compact_text(text: str, max_len: int = 300) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:max_len]


def record_finding(kind: str, severity: str, url: str, detail: str) -> None:
    assert STATE is not None
    STATE.findings.append(
        {"kind": kind, "severity": severity, "url": url, "detail": detail}
    )


def limited_event(data: Any) -> str:
    if isinstance(data, str):
        return data[:MAX_EVENT_CHARS]
    return json.dumps(data, indent=2)[:MAX_EVENT_CHARS]


def add_sig(signature: str) -> None:
    assert STATE is not None
    STATE.recent_tool_signatures.append(signature)
    STATE.recent_tool_signatures = STATE.recent_tool_signatures[-8:]


def _url_to_slug(url: str) -> str:
    p = urlparse(url)
    raw = p.path.strip("/") or "index"
    return re.sub(r"[^\w\-]", "_", raw)[:80]


# ═══════════════════════════════════════════════════════════
#  CORE AUDIT TOOLS
# ═══════════════════════════════════════════════════════════
def tool_fetch_page(url: str) -> ToolResult:
    assert STATE is not None
    url = normalize_url(url)
    if not same_domain(url, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {url}")

    resp = http.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    final_url = normalize_url(resp.url)
    ct = resp.headers.get("content-type", "")

    page: Dict[str, Any] = {
        "url": final_url, "requested_url": url,
        "status_code": resp.status_code, "content_type": ct,
        "title": "", "meta_description": "", "canonical": "", "h1": "",
        "internal_links": [], "external_links": [],
        "asset_counts": {"scripts": 0, "stylesheets": 0, "images": 0},
        "form_count": 0, "forms": [], "issues": [],
    }

    if "text/html" in ct.lower():
        soup = BeautifulSoup(resp.text, "lxml")
        page["title"] = compact_text(soup.title.get_text()) if soup.title else ""
        md = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
        if md and md.get("content"):
            page["meta_description"] = compact_text(md["content"], 400)
        canon = soup.find("link", rel=lambda x: x and "canonical" in str(x).lower())
        if canon and canon.get("href"):
            page["canonical"] = normalize_url(urljoin(final_url, canon["href"]))
        h1 = soup.find("h1")
        if h1:
            page["h1"] = compact_text(h1.get_text(), 200)

        internal: Set[str] = set()
        external: Set[str] = set()
        for a in soup.find_all("a", href=True):
            abs_url = normalize_url(urljoin(final_url, a["href"]))
            if same_domain(abs_url, STATE.domain):
                internal.add(abs_url)
            elif abs_url.startswith("http"):
                external.add(abs_url)
        page["internal_links"] = sorted(internal)[:300]
        page["external_links"] = sorted(external)[:150]
        page["asset_counts"]["scripts"] = len(soup.find_all("script", src=True))
        page["asset_counts"]["stylesheets"] = len(
            soup.find_all("link", rel=lambda x: x and "stylesheet" in str(x).lower())
        )
        page["asset_counts"]["images"] = len(soup.find_all("img"))
        forms = soup.find_all("form")
        page["form_count"] = len(forms)
        for fm in forms[:20]:
            page["forms"].append({
                "action": fm.get("action", ""),
                "method": fm.get("method", "GET").upper(),
            })

        if not page["title"]:
            page["issues"].append("Missing <title>")
            record_finding("seo", "medium", final_url, "Missing page title")
        if not page["meta_description"]:
            page["issues"].append("Missing meta description")
            record_finding("seo", "low", final_url, "Missing meta description")
        if not page["h1"]:
            page["issues"].append("Missing H1")
            record_finding("content", "low", final_url, "Missing H1")
        if page["canonical"] and not same_domain(page["canonical"], STATE.domain):
            page["issues"].append("Canonical off-domain")
            record_finding("seo", "medium", final_url,
                           f"Canonical off-domain: {page['canonical']}")
        if resp.status_code >= 400:
            record_finding("http", "high", final_url,
                           f"Status {resp.status_code}")

        for link in page["internal_links"]:
            if link not in STATE.seen_urls and link not in STATE.queued_urls:
                STATE.queued_urls.append(link)
    else:
        if resp.status_code >= 400:
            record_finding("http", "high", final_url,
                           f"Status {resp.status_code}")

    STATE.pages[final_url] = page
    STATE.seen_urls.add(final_url)

    summary = {
        "url": final_url, "status_code": page["status_code"],
        "title": page["title"],
        "internal_links_found": len(page["internal_links"]),
        "external_links_found": len(page["external_links"]),
        "issues": page["issues"],
    }
    return ToolResult(ok=True, output=json.dumps(summary, indent=2),
                      meta={"url": final_url})


def tool_check_headers(url: str) -> ToolResult:
    assert STATE is not None
    url = normalize_url(url)
    if not same_domain(url, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {url}")
    resp = http.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    recommended = {
        "strict-transport-security": "Missing HSTS",
        "content-security-policy": "Missing CSP",
        "x-content-type-options": "Missing X-Content-Type-Options",
        "referrer-policy": "Missing Referrer-Policy",
        "permissions-policy": "Missing Permissions-Policy",
    }
    missing = []
    for key, msg in recommended.items():
        if key not in hdrs:
            missing.append(msg)
            record_finding("headers", "medium", resp.url, msg)
    result = {
        "url": normalize_url(resp.url),
        "status_code": resp.status_code,
        "server": hdrs.get("server", ""),
        "missing_recommended_headers": missing,
    }
    return ToolResult(ok=True, output=json.dumps(result, indent=2))


def tool_fetch_robots() -> ToolResult:
    assert STATE is not None
    url = f"https://{STATE.domain}/robots.txt"
    resp = http.get(url, timeout=REQUEST_TIMEOUT)
    sitemaps = []
    for line in resp.text.splitlines():
        if line.lower().startswith("sitemap:"):
            val = line.split(":", 1)[1].strip()
            if val:
                sitemaps.append(val)
    if resp.status_code >= 400:
        record_finding("crawl", "medium", url,
                       f"robots.txt returned {resp.status_code}")
    return ToolResult(ok=True, output=json.dumps({
        "url": url, "status_code": resp.status_code,
        "body_preview": resp.text[:2000], "declared_sitemaps": sitemaps,
    }, indent=2))


def tool_fetch_sitemap() -> ToolResult:
    assert STATE is not None
    url = f"https://{STATE.domain}/sitemap.xml"
    resp = http.get(url, timeout=REQUEST_TIMEOUT)
    if resp.status_code >= 400:
        record_finding("crawl", "medium", url,
                       f"sitemap.xml returned {resp.status_code}")
    found = re.findall(r"<loc>(.*?)</loc>", resp.text, flags=re.I)
    in_scope = [normalize_url(u.strip()) for u in found
                if same_domain(normalize_url(u.strip()), STATE.domain)]
    added = 0
    for u in in_scope[:250]:
        if u not in STATE.seen_urls and u not in STATE.queued_urls:
            STATE.queued_urls.append(u)
            added += 1
    return ToolResult(ok=True, output=json.dumps({
        "url": url, "status_code": resp.status_code,
        "urls_found": len(in_scope), "urls_added_to_queue": added,
    }, indent=2))


def tool_bulk_audit_next(batch_size: int = 5) -> ToolResult:
    assert STATE is not None
    batch: List[str] = []
    while STATE.queued_urls and len(batch) < batch_size:
        c = STATE.queued_urls.pop(0)
        if c not in STATE.seen_urls:
            batch.append(c)
    if not batch:
        return ToolResult(ok=True, output='{"message":"Queue empty"}')
    outputs = []
    with ThreadPoolExecutor(max_workers=min(batch_size, 5)) as ex:
        futs = {ex.submit(tool_fetch_page, u): u for u in batch}
        for fut in as_completed(futs):
            url = futs[fut]
            try:
                r = fut.result()
                outputs.append(json.loads(r.output) if r.ok
                               else {"url": url, "error": r.error[:200]})
            except Exception as e:
                outputs.append({"url": url, "error": str(e)[:200]})
    return ToolResult(ok=True, output=json.dumps(outputs, indent=2))


def tool_check_broken_links(sample_limit: int = 80) -> ToolResult:
    assert STATE is not None
    checked, broken = 0, []
    for page_url, pg in list(STATE.pages.items())[:120]:
        for link in pg.get("internal_links", []) + pg.get("external_links", []):
            if checked >= sample_limit:
                break
            checked += 1
            try:
                r = http.head(link, timeout=10, allow_redirects=True)
                status = r.status_code
                if status == 405:
                    r = http.get(link, timeout=10, allow_redirects=True)
                    status = r.status_code
                if status >= 400:
                    broken.append({"source": page_url, "url": link,
                                   "status_code": status})
                    record_finding("links", "medium", page_url,
                                   f"Broken: {link} → {status}")
            except Exception:
                broken.append({"source": page_url, "url": link,
                               "status_code": "error"})
                record_finding("links", "medium", page_url,
                               f"Broken: {link} → request failed")
    return ToolResult(ok=True, output=json.dumps(
        {"checked": checked, "broken": broken[:120]}, indent=2))


def tool_check_redirects() -> ToolResult:
    assert STATE is not None
    candidates = sorted(list(STATE.pages.keys()))[:40]
    redirects = []
    for url in candidates:
        try:
            r = http.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if len(r.history) > 0:
                chain = [h.url for h in r.history] + [r.url]
                redirects.append({"url": url, "chain": chain})
                if len(chain) > 2:
                    record_finding("redirect", "low", url,
                                   f"Chain length {len(chain)}")
        except Exception as e:
            redirects.append({"url": url, "error": str(e)[:200]})
    return ToolResult(ok=True, output=json.dumps(
        {"redirects": redirects}, indent=2))


def tool_check_duplicate_meta() -> ToolResult:
    assert STATE is not None
    titles: Dict[str, List[str]] = {}
    descs: Dict[str, List[str]] = {}
    for url, pg in STATE.pages.items():
        t = pg.get("title", "")
        d = pg.get("meta_description", "")
        if t:
            titles.setdefault(t, []).append(url)
        if d:
            descs.setdefault(d, []).append(url)
    dup_titles = {t: urls for t, urls in titles.items() if len(urls) > 1}
    dup_descs = {d: urls for d, urls in descs.items() if len(urls) > 1}
    for title, urls in dup_titles.items():
        record_finding("seo", "medium", urls[0],
                       f"Duplicate title '{title[:60]}' on {len(urls)} pages")
    for desc, urls in dup_descs.items():
        record_finding("seo", "low", urls[0],
                       f"Duplicate description on {len(urls)} pages")
    return ToolResult(ok=True, output=json.dumps({
        "duplicate_titles": len(dup_titles),
        "duplicate_descriptions": len(dup_descs),
        "details": {"titles": dup_titles, "descriptions": dup_descs},
    }, indent=2))


def tool_site_snapshot() -> ToolResult:
    assert STATE is not None
    sev: Dict[str, int] = {}
    kind: Dict[str, int] = {}
    for f in STATE.findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        kind[f["kind"]] = kind.get(f["kind"], 0) + 1
    return ToolResult(ok=True, output=json.dumps({
        "domain": STATE.domain,
        "pages_seen": len(STATE.pages),
        "queued_urls": len(STATE.queued_urls),
        "findings_total": len(STATE.findings),
        "severity_counts": sev, "kind_counts": kind,
        "sample_pages": list(STATE.pages.keys())[:25],
    }, indent=2))


# ═══════════════════════════════════════════════════════════
#  PLAYWRIGHT TOOLS
# ═══════════════════════════════════════════════════════════
def tool_playwright_screenshot(url: str) -> ToolResult:
    if not PLAYWRIGHT_AVAILABLE:
        return ToolResult(ok=False, output="",
                          error="Playwright not available")
    assert STATE is not None
    url = normalize_url(url)
    try:
        browser = _get_browser()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto(url, timeout=30000, wait_until="networkidle")
        slug = _url_to_slug(url)
        path = SCREENSHOTS_DIR / f"{slug}.png"
        page.screenshot(path=str(path), full_page=True)
        page.close()
        return ToolResult(ok=True, output=json.dumps(
            {"url": url, "screenshot": str(path)}, indent=2))
    except Exception as e:
        return ToolResult(ok=False, output="",
                          error=f"Screenshot failed: {e}")


def tool_playwright_extract(url: str) -> ToolResult:
    if not PLAYWRIGHT_AVAILABLE:
        return ToolResult(ok=False, output="",
                          error="Playwright not available")
    assert STATE is not None
    url = normalize_url(url)
    try:
        browser = _get_browser()
        page = browser.new_page()
        page.goto(url, timeout=30000, wait_until="networkidle")
        title = page.title()
        text = page.inner_text("body")[:3000]
        console_errors = []
        page.on("pageerror", lambda e: console_errors.append(str(e)[:200]))
        page.close()
        return ToolResult(ok=True, output=json.dumps({
            "url": url, "rendered_title": title,
            "body_text_preview": text,
            "console_errors": console_errors[:10],
        }, indent=2))
    except Exception as e:
        return ToolResult(ok=False, output="",
                          error=f"DOM extract failed: {e}")


# ═══════════════════════════════════════════════════════════
#  LIGHTHOUSE TOOL
# ═══════════════════════════════════════════════════════════
def tool_lighthouse_audit(url: str) -> ToolResult:
    if not LIGHTHOUSE_AVAILABLE:
        return ToolResult(ok=False, output="",
                          error="Lighthouse not available (Node.js required)")
    assert STATE is not None
    url = normalize_url(url)
    slug = _url_to_slug(url)
    out_path = LIGHTHOUSE_DIR / f"{slug}.json"
    try:
        r = subprocess.run(
            ["npx", "--yes", "lighthouse", url,
             "--output=json", f"--output-path={out_path}",
             "--chrome-flags=--headless --no-sandbox", "--quiet"],
            capture_output=True, text=True, timeout=120, shell=True,
        )
        if r.returncode == 0 and out_path.exists():
            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cats = data.get("categories", {})
            scores = {}
            for key, cat in cats.items():
                scores[key] = cat.get("score")
                if cat.get("score") is not None and cat["score"] < 0.5:
                    record_finding("lighthouse", "high", url,
                                   f"{key} score: {cat['score']:.0%}")
            return ToolResult(ok=True, output=json.dumps({
                "url": url, "scores": scores,
                "report_path": str(out_path),
            }, indent=2))
        return ToolResult(ok=False, output="",
                          error=f"Lighthouse exit {r.returncode}: "
                                f"{r.stderr[:200]}")
    except subprocess.TimeoutExpired:
        return ToolResult(ok=False, output="",
                          error="Lighthouse timed out (120s)")
    except Exception as e:
        return ToolResult(ok=False, output="",
                          error=f"Lighthouse error: {e}")


# ═══════════════════════════════════════════════════════════
#  TERMINAL ACCESS  (LLM can run any command)
# ═══════════════════════════════════════════════════════════
_SAFE_PATTERNS = {
    "nmap", "nikto", "sqlmap", "nuclei", "subfinder", "httpx", "ffuf",
    "gobuster", "dirb", "dirsearch", "whatweb", "wpscan", "sslscan",
    "enum4linux", "amass", "curl", "wget", "whois", "dig", "nslookup",
    "host", "traceroute", "ping", "openssl", "testssl", "wfuzz",
    "feroxbuster", "rustscan", "masscan", "theHarvester", "recon-ng",
    "dnsenum", "dnsrecon", "fierce", "wafw00f", "arjun", "paramspider",
    "python", "pip", "npm", "apt", "cat", "ls", "dir", "type", "echo",
    "grep", "find", "head", "tail", "wc", "sort", "uniq", "awk", "sed",
    "wsl", "which", "where", "whoami", "hostname", "ipconfig", "ifconfig",
}
_RISKY_PATTERNS = [
    "rm -rf", "del /f", "format ", "fdisk", "mkfs",
    ":(){ :|:& };:",  # fork bomb
    "shutdown", "reboot", "> /dev/",
    "metasploit", "msfconsole", "msfvenom",
    "exploit/", "payload/",
    "nc -e", "reverse_tcp", "bind_tcp",
    "passwd", "useradd", "adduser",
    "iptables -F", "ufw disable",
]


def _is_risky(command: str) -> bool:
    cmd_lower = command.lower()
    return any(p in cmd_lower for p in _RISKY_PATTERNS)


def tool_run_command(command: str, timeout: int = 120) -> ToolResult:
    """Execute a shell command. The LLM decides what to run."""
    assert STATE is not None

    # Risky command gate — ask user
    if _is_risky(command):
        console.print(f"\n  [bold red]⚠ RISKY COMMAND DETECTED:[/]")
        console.print(f"  [yellow]{command}[/]")
        ok = Confirm.ask("  [bold]Allow this command?[/]", default=False)
        if not ok:
            return ToolResult(ok=False, output="",
                              error="User denied risky command")

    timeout = min(timeout, COMMAND_TIMEOUT)
    log_path = SCAN_LOGS_DIR / f"cmd_{int(time.time())}.txt"
    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=str(OUTPUT_DIR),
        )
        stdout = r.stdout[-4000:] if len(r.stdout) > 4000 else r.stdout
        stderr = r.stderr[-2000:] if len(r.stderr) > 2000 else r.stderr
        # Log full output
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"$ {command}\n\n--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}\n")
        return ToolResult(ok=r.returncode == 0, output=json.dumps({
            "command": command, "returncode": r.returncode,
            "stdout": stdout, "stderr": stderr, "log": str(log_path),
        }, indent=2))
    except subprocess.TimeoutExpired:
        return ToolResult(ok=False, output="", error=f"Timed out ({timeout}s)")
    except Exception as e:
        return ToolResult(ok=False, output="", error=str(e))


def tool_ask_user(question: str) -> ToolResult:
    """Ask the operator a question and return their response."""
    console.print(f"\n  [bold bright_cyan]🤖 Agent wants to ask you:[/]")
    console.print(f"  [bold]{question}[/]")
    answer = Prompt.ask("  [bold]Your response[/]")
    return ToolResult(ok=True, output=json.dumps({"question": question, "answer": answer}))


def tool_install_tool(tool_name: str) -> ToolResult:
    """Attempt to install a security tool via winget, pip, or npm."""
    pip_tools = {"sqlmap": "sqlmap", "dirsearch": "dirsearch", "wapiti": "wapiti3"}
    winget_tools = {"nmap": "Insecure.Nmap", "ffuf": "ffuf", "nuclei": "ProjectDiscovery.Nuclei",
                    "subfinder": "ProjectDiscovery.Subfinder", "httpx": "ProjectDiscovery.httpx"}

    if tool_name in pip_tools:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pip_tools[tool_name]],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return ToolResult(ok=True, output=json.dumps({"installed": tool_name, "via": "pip"}))
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"pip install failed: {e}")

    if tool_name in winget_tools and shutil.which("winget"):
        try:
            r = subprocess.run(
                ["winget", "install", "--id", winget_tools[tool_name],
                 "--accept-package-agreements", "--accept-source-agreements", "-e"],
                capture_output=True, text=True, timeout=300,
            )
            return ToolResult(ok=r.returncode == 0, output=json.dumps({
                "installed": tool_name, "via": "winget", "output": r.stdout[-500:]
            }), error=r.stderr[-300:] if r.returncode != 0 else "")
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"winget install failed: {e}")

    return ToolResult(ok=False, output="",
                      error=f"Don't know how to install '{tool_name}'. Install manually.")


# ═══════════════════════════════════════════════════════════
#  SECURITY TOOL WRAPPERS  (from security_tools.py)
# ═══════════════════════════════════════════════════════════
def _wrap_security(result: Dict[str, Any], kind: str, url: str) -> ToolResult:
    """Convert security_tools result dict into ToolResult + record findings."""
    for sev, msg in result.get("findings", []):
        record_finding(kind, sev, url, msg)
    return ToolResult(ok=result.get("ok", True),
                      output=json.dumps(result.get("data", {}), indent=2))


def tool_security_ssl() -> ToolResult:
    assert STATE is not None
    return _wrap_security(check_ssl(STATE.domain), "ssl", f"https://{STATE.domain}")


def tool_security_cookies(url: str = "") -> ToolResult:
    assert STATE is not None
    url = url or STATE.start_url
    return _wrap_security(check_cookies(url, http), "cookies", url)


def tool_security_sensitive_paths() -> ToolResult:
    assert STATE is not None
    return _wrap_security(check_sensitive_paths(STATE.domain, http),
                          "exposure", f"https://{STATE.domain}")


def tool_security_cors(url: str = "") -> ToolResult:
    assert STATE is not None
    url = url or STATE.start_url
    return _wrap_security(check_cors(url, STATE.domain, http), "cors", url)


def tool_security_mixed_content() -> ToolResult:
    assert STATE is not None
    return _wrap_security(check_mixed_content(STATE.pages),
                          "mixed_content", f"https://{STATE.domain}")


def tool_security_email() -> ToolResult:
    assert STATE is not None
    return _wrap_security(check_email_security(STATE.domain),
                          "email_security", STATE.domain)


def tool_security_info_disclosure(url: str = "") -> ToolResult:
    assert STATE is not None
    url = url or STATE.start_url
    return _wrap_security(check_info_disclosure(url, STATE.domain, http),
                          "info_disclosure", url)


def tool_security_headers_deep(url: str = "") -> ToolResult:
    assert STATE is not None
    url = url or STATE.start_url
    return _wrap_security(check_security_headers_deep(url, http),
                          "security_headers", url)


# ═══════════════════════════════════════════════════════════
#  REPORT GENERATION TOOLS
# ═══════════════════════════════════════════════════════════
def tool_write_json_report(path: str = "") -> ToolResult:
    assert STATE is not None
    p = path or str(JSON_REPORT)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(STATE.to_dict(), f, indent=2)
    return ToolResult(ok=True, output=json.dumps({"written": p}))


def tool_write_markdown_summary(path: str = "") -> ToolResult:
    assert STATE is not None
    p = path or str(MD_REPORT)
    payload = json.dumps({
        "domain": STATE.domain,
        "pages_seen": len(STATE.pages),
        "findings": STATE.findings[:200],
        "sample_pages": list(STATE.pages.values())[:20],
        "notes": STATE.notes[-20:],
        "memory_summary": STATE.memory_summary,
    }, indent=2)

    resp = llm.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": (
                "Write a sharp markdown website audit summary for the owner. "
                "Include: executive summary, top issues, notable positives, "
                "prioritized fixes, and next steps. Be concrete."
            )},
            {"role": "user", "content": payload},
        ],
    )
    md = _get_content(resp)
    md = _strip_think(md)
    with open(p, "w", encoding="utf-8") as f:
        f.write(md)
    return ToolResult(ok=True, output=json.dumps({"written": p}))


# ═══════════════════════════════════════════════════════════
#  LLM ORCHESTRATION
# ═══════════════════════════════════════════════════════════
TOOL_DESCRIPTIONS = {
    # Recon & crawling
    "fetch_page": "Fetch & parse HTML page. args: {url}",
    "check_headers": "Check security headers. args: {url}",
    "fetch_robots": "Fetch robots.txt. no args",
    "fetch_sitemap": "Fetch sitemap.xml. no args",
    "bulk_audit_next": "Fetch next batch of queued URLs. args: {batch_size}",
    "check_broken_links": "Check for broken links. args: {sample_limit}",
    "check_redirects": "Check redirect chains. no args",
    "check_duplicate_meta": "Find duplicate titles/descriptions. no args",
    # Security scanning
    "security_ssl": "SSL/TLS cert & protocol analysis. no args",
    "security_cookies": "Cookie security audit (Secure/HttpOnly/SameSite). args: {url}",
    "security_sensitive_paths": "Probe for exposed files (.env, .git, etc). no args",
    "security_cors": "Test CORS misconfiguration. args: {url}",
    "security_mixed_content": "Find HTTP resources on HTTPS pages. no args",
    "security_email": "Check SPF/DMARC DNS records. no args",
    "security_info_disclosure": "Detect info leakage in headers/errors. args: {url}",
    "security_headers_deep": "Deep security header analysis with A-F grade. args: {url}",
    # Terminal & tools
    "run_command": "Execute ANY shell command freely. args: {command, timeout}",
    "install_tool": "Install a security tool (nmap,nuclei,sqlmap,etc). args: {tool_name}",
    "ask_user": "Ask the operator a question (for risky/unclear decisions). args: {question}",
    # Browser
    "playwright_screenshot": "Full-page screenshot. args: {url}",
    "playwright_extract": "JS-rendered DOM extract. args: {url}",
    "lighthouse_audit": "Lighthouse perf/a11y/SEO audit. args: {url}",
    # Status & reporting
    "site_snapshot": "Overview of audit progress. no args",
    "write_json_report": "Write JSON report. no args",
    "write_markdown_summary": "Write markdown summary. no args",
}


def _get_content(resp: Any) -> str:
    try:
        return resp["message"]["content"]
    except (TypeError, KeyError):
        return resp.message.content


def _strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _extract_json(text: str) -> Dict[str, Any]:
    text = _strip_think(text)
    # Try code block
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Try raw JSON
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    raise json.JSONDecodeError("No valid JSON", text, 0)


def build_system_prompt() -> str:
    tool_lines = "\n".join(
        f"  - {name}: {desc}" for name, desc in TOOL_DESCRIPTIONS.items()
    )
    avail = [t for t, ok in _DETECTED_TOOLS.items() if ok]
    ext_tools = ", ".join(avail) if avail else "none"
    wsl_info = ""
    if _WSL_DISTROS:
        wsl_info = f"""\n\nWSL DISTRIBUTIONS AVAILABLE: {', '.join(_WSL_DISTROS)}
You can run ANY Linux tool via WSL. This is your MOST POWERFUL capability.
Kali Linux and Athena OS have hundreds of pre-installed security tools.
Use: wsl -d <distro> <command>
Examples:
- wsl -d kali-linux nmap -sV -sC -A {{domain}}
- wsl -d kali-linux nikto -h https://{{domain}}
- wsl -d kali-linux whatweb https://{{domain}}
- wsl -d kali-linux wpscan --url https://{{domain}}
- wsl -d kali-linux dirb https://{{domain}}
- wsl -d kali-linux sqlmap -u "https://{{domain}}/page?id=1" --batch
- wsl -d kali-linux nuclei -u https://{{domain}}
- wsl -d kali-linux gobuster dir -u https://{{domain}} -w /usr/share/wordlists/dirb/common.txt
- wsl -d kali-linux sslscan {{domain}}
- wsl -d kali-linux enum4linux {{domain}}
PREFER WSL tools over native Windows tools — they are more capable."""
    return f"""You are an elite autonomous penetration testing agent.
You are AUTHORIZED to test ONLY this target domain: {{domain}}

Objective: Perform a comprehensive security assessment.
1. Reconnaissance — crawl, map, fingerprint tech stack
2. Security scanning — headers, SSL, cookies, CORS, sensitive files, info disclosure
3. Vulnerability testing — use run_command to run nmap, sqlmap, nuclei, or any tool
4. Deep inspection — Playwright for JS-rendered content, Lighthouse for perf/a11y
5. Reporting — write comprehensive JSON + markdown reports

You have FULL TERMINAL ACCESS via run_command. You can run ANY command.
External tools detected: {ext_tools}{wsl_info}

You have COMPLETE FREEDOM to run any standard security/recon tool without asking.
Standard tools include: nmap, nikto, sqlmap, nuclei, dirb, gobuster, whatweb,
wpscan, sslscan, curl, dig, whois, openssl, feroxbuster, and ALL kali/debian tools.

ONLY use ask_user for:
- Destructive operations (deleting files, modifying system config)
- Running exploits or reverse shells (metasploit, msfvenom)
- Actions that are ambiguous or outside normal recon/scanning
Do NOT ask permission for standard scanning, enumeration, or recon commands.

Rules:
- Return STRICT JSON only (no markdown, no extra text)
- ONLY target the authorized domain
- Be thorough, aggressive, and systematic
- Use run_command freely for any tool or command
- Vary your commands — change flags, targets, or approaches if retrying
- Finish when you have good coverage and both reports are written

Available tools:
{tool_lines}

Actions (return ONE as JSON):
1. {{{{"action":"tool","tool":"<name>","args":{{}},"why":"reason"}}}}
2. {{{{"action":"summarize","summary":"brief durable note"}}}}
3. {{{{"action":"finish","reason":"why assessment is complete"}}}}"""


def build_user_prompt(state: AgentState) -> str:
    preview = []
    for _, pg in list(state.pages.items())[:15]:
        preview.append({
            "url": pg.get("url", ""), "status_code": pg.get("status_code", 0),
            "title": pg.get("title", ""), "issues": pg.get("issues", []),
        })
    return json.dumps({
        "goal": state.goal, "domain": state.domain, "step": state.step,
        "memory_summary": state.memory_summary,
        "pages_seen": len(state.pages),
        "queued_urls": len(state.queued_urls),
        "findings_total": len(state.findings),
        "recent_tool_signatures": state.recent_tool_signatures[-6:],
        "preview_pages": preview,
        "recent_events": state.recent_events[-6:],
    }, indent=2)


def chat_json(messages: List[Dict[str, str]]) -> Dict[str, Any]:
    resp = llm.chat(model=MODEL, messages=messages)
    content = _get_content(resp)
    try:
        return _extract_json(content)
    except json.JSONDecodeError:
        # Ask LLM to repair
        repair_resp = llm.chat(
            model=MODEL,
            messages=[
                {"role": "system",
                 "content": "Repair this into valid JSON only. Return JSON only."},
                {"role": "user", "content": content},
            ],
        )
        repair_text = _get_content(repair_resp)
        try:
            return _extract_json(repair_text)
        except json.JSONDecodeError:
            return {"action": "summarize",
                    "summary": "LLM output was not parseable JSON"}


def summarize_memory() -> None:
    assert STATE is not None
    payload = json.dumps({
        "domain": STATE.domain, "pages_seen": len(STATE.pages),
        "findings": STATE.findings[-60:],
        "recent_events": STATE.recent_events[-16:],
        "notes": STATE.notes[-20:],
    }, indent=2)
    resp = llm.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content":
             "Summarize durable facts from this audit session. "
             "Keep it compact and useful for continuation."},
            {"role": "user", "content": payload},
        ],
    )
    text = _strip_think(_get_content(resp))
    STATE.memory_summary = text[:2500]


# ═══════════════════════════════════════════════════════════
#  AGENT RUNNER
# ═══════════════════════════════════════════════════════════
def bootstrap_state(domain: str) -> AgentState:
    domain = domain.strip().strip("/")  # Remove trailing slash
    start_url = normalize_url(f"https://{domain}")
    return AgentState(
        session_id=str(uuid.uuid4()),
        domain=domain,
        start_url=start_url,
        goal=f"Full penetration test and security assessment of {domain}",
        queued_urls=[start_url],
    )


def deterministic_kickoff(registry: ToolRegistry) -> None:
    assert STATE is not None
    ui_phase("Bootstrap Phase")

    steps = [
        # Recon phase
        ("fetch_page", {"url": STATE.start_url}),
        ("fetch_robots", {}),
        ("fetch_sitemap", {}),
        ("bulk_audit_next", {"batch_size": BOOTSTRAP_BATCH}),
        # Security phase
        ("security_ssl", {}),
        ("security_headers_deep", {"url": STATE.start_url}),
        ("security_cookies", {}),
        ("security_sensitive_paths", {}),
        ("security_cors", {}),
        ("security_email", {}),
        ("security_info_disclosure", {}),
        ("check_broken_links", {"sample_limit": 40}),
    ]

    if PLAYWRIGHT_AVAILABLE:
        steps.append(("playwright_screenshot", {"url": STATE.start_url}))
    if LIGHTHOUSE_AVAILABLE:
        steps.append(("lighthouse_audit", {"url": STATE.start_url}))

    for tool_name, args in steps:
        result = registry.call(tool_name, **args)
        detail = args.get("url", "")
        summary = ""
        if result.ok:
            try:
                d = json.loads(result.output)
                parts = []
                if "status_code" in d:
                    parts.append(f"{d['status_code']}")
                if "title" in d:
                    parts.append(f'"{d["title"][:40]}"')
                if "internal_links_found" in d:
                    parts.append(f"{d['internal_links_found']} links")
                if "urls_found" in d:
                    parts.append(f"{d['urls_found']} URLs")
                if "checked" in d:
                    parts.append(f"{d['checked']} checked")
                if "broken" in d and isinstance(d["broken"], list):
                    parts.append(f"{len(d['broken'])} broken")
                if "scores" in d:
                    parts.append(
                        " ".join(f"{k}:{v:.0%}" for k, v in d["scores"].items()
                                 if v is not None))
                if "screenshot" in d:
                    parts.append(d["screenshot"])
                summary = " │ ".join(parts)
            except Exception:
                summary = result.output[:80]
        else:
            summary = result.error[:80]

        ui_tool(tool_name, detail, result.ok, result.duration_s, summary)

        STATE.recent_events.append({
            "type": "tool_result", "step": STATE.step,
            "tool": tool_name, "ok": result.ok,
            "output": limited_event(result.output),
            "error": limited_event(result.error),
            "duration_s": result.duration_s,
        })
        sig = f"{tool_name}:{json.dumps(args, sort_keys=True)}"
        add_sig(sig)


def run_agent(domain: str = DEFAULT_DOMAIN, resume: bool = True,
              fresh: bool = False) -> None:
    global STATE
    agent_start = time.time()

    cp = str(CHECKPOINT_PATH)

    if not fresh and resume and os.path.exists(cp):
        STATE = AgentState.load(cp)
        console.print(f"[bold green]Resumed[/] session for [bold]{STATE.domain}[/]")
    else:
        STATE = bootstrap_state(domain)
        console.print(f"[bold green]New session[/] for [bold]{STATE.domain}[/]")

    ui_banner(STATE.domain, profile=getattr(run_agent, '_profile', 'standard'))

    registry = ToolRegistry()
    # Recon & crawling
    registry.register("fetch_page", tool_fetch_page)
    registry.register("check_headers", tool_check_headers)
    registry.register("fetch_robots", lambda: tool_fetch_robots())
    registry.register("fetch_sitemap", lambda: tool_fetch_sitemap())
    registry.register("bulk_audit_next", tool_bulk_audit_next)
    registry.register("check_broken_links", tool_check_broken_links)
    registry.register("check_redirects", lambda: tool_check_redirects())
    registry.register("check_duplicate_meta", lambda: tool_check_duplicate_meta())
    # Security scanning
    registry.register("security_ssl", lambda: tool_security_ssl())
    registry.register("security_cookies", tool_security_cookies)
    registry.register("security_sensitive_paths", lambda: tool_security_sensitive_paths())
    registry.register("security_cors", tool_security_cors)
    registry.register("security_mixed_content", lambda: tool_security_mixed_content())
    registry.register("security_email", lambda: tool_security_email())
    registry.register("security_info_disclosure", tool_security_info_disclosure)
    registry.register("security_headers_deep", tool_security_headers_deep)
    # Terminal & tool install
    registry.register("run_command", tool_run_command)
    registry.register("install_tool", tool_install_tool)
    registry.register("ask_user", tool_ask_user)
    # Browser & lighthouse
    registry.register("playwright_screenshot", tool_playwright_screenshot)
    registry.register("playwright_extract", tool_playwright_extract)
    registry.register("lighthouse_audit", tool_lighthouse_audit)
    # Status & reporting
    registry.register("site_snapshot", lambda: tool_site_snapshot())
    registry.register("write_json_report", tool_write_json_report)
    registry.register("write_markdown_summary", tool_write_markdown_summary)

    # Deterministic kickoff
    if len(STATE.pages) == 0 and len(STATE.recent_events) == 0:
        deterministic_kickoff(registry)
        STATE.checkpoint(cp)

    # LLM-driven loop
    ui_phase("LLM Phase")

    try:
        for _ in range(MAX_STEPS):
            assert STATE is not None
            STATE.step += 1
            ui_step(STATE.step)

            # Show dashboard every 4 steps
            if STATE.step % 4 == 1:
                ui_dashboard(STATE)

            # LLM decides
            t0 = time.time()
            decision = chat_json([
                {"role": "system", "content": build_system_prompt()},
                {"role": "user", "content": build_user_prompt(STATE)},
            ])
            llm_dur = time.time() - t0

            action = decision.get("action", "")
            why = decision.get("why", decision.get("reason",
                               decision.get("summary", "")))
            ui_llm(action, why[:80], llm_dur)

            STATE.recent_events.append({
                "type": "decision", "step": STATE.step, "data": decision,
            })

            if action == "tool":
                tool_name = decision.get("tool", "")
                args = decision.get("args", {}) or {}
                sig = f"{tool_name}:{json.dumps(args, sort_keys=True)}"

                if sig in STATE.recent_tool_signatures[-6:]:
                    STATE.notes.append(f"Skipped repeat: {sig}")
                    console.print(
                        f"  [dim]⤳ skipped (duplicate action)[/]")
                    continue

                result = registry.call(tool_name, **args)
                # Only record signature for successful calls
                # so retries after tool install actually run
                if result.ok:
                    add_sig(sig)

                # Build summary
                summary = ""
                if result.ok:
                    try:
                        d = json.loads(result.output)
                        summary = " │ ".join(
                            f"{k}: {v}" for k, v in
                            list(d.items())[:4]
                            if isinstance(v, (str, int, float))
                        )[:120]
                    except Exception:
                        summary = result.output[:80]
                else:
                    summary = result.error[:80]

                ui_tool(tool_name, args.get("url", ""),
                        result.ok, result.duration_s, summary)

                STATE.recent_events.append({
                    "type": "tool_result", "step": STATE.step,
                    "tool": tool_name, "ok": result.ok,
                    "output": limited_event(result.output),
                    "error": limited_event(result.error),
                    "duration_s": result.duration_s,
                })

            elif action == "summarize":
                STATE.notes.append(decision.get("summary", ""))

            elif action == "finish":
                STATE.notes.append(
                    f"Finished: {decision.get('reason', '')}")
                console.print("  [bold green]Finishing up…[/]")
                summarize_memory()
                registry.call("write_json_report")
                ui_tool("write_json_report", str(JSON_REPORT),
                        True, 0.0, "saved")
                registry.call("write_markdown_summary")
                ui_tool("write_markdown_summary", str(MD_REPORT),
                        True, 0.0, "saved")
                STATE.checkpoint(cp)
                ui_done(time.time() - agent_start)
                _close_browser()
                return

            else:
                STATE.notes.append(f"Unknown action: {decision}")

            # Periodic memory summary
            if STATE.step % 4 == 0:
                summarize_memory()

            STATE.checkpoint(cp)

    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]⚠ Interrupted — saving checkpoint…[/]")
        if STATE:
            STATE.checkpoint(cp)
        _close_browser()
        return

    # Budget exhausted
    assert STATE is not None
    console.print("\n[bold yellow]Step budget reached — writing reports…[/]")
    summarize_memory()
    registry.call("write_json_report")
    registry.call("write_markdown_summary")
    STATE.checkpoint(cp)
    ui_done(time.time() - agent_start)
    _close_browser()


# ═══════════════════════════════════════════════════════════
#  INTERACTIVE STARTUP
# ═══════════════════════════════════════════════════════════
def interactive_startup() -> Tuple[str, str, bool]:
    """Interactive menu when no CLI args given. Returns (domain, profile, fresh)."""
    console.print(_ASCII_BANNER)
    console.print(Panel(
        "[bold]Autonomous Pentest Agent[/]\n"
        "[dim]Authorized penetration testing only. You must have explicit\n"
        "permission to test the target domain.[/]",
        border_style="bright_red", padding=(1, 2),
    ))
    raw = Prompt.ask("\n[bold]Target domain[/]", default=DEFAULT_DOMAIN)
    domain = raw.strip().strip("/")  # Clean trailing slash
    profile = Prompt.ask(
        "[bold]Scan profile[/]",
        choices=["quick", "standard", "deep"],
        default="standard",
    )
    fresh = not Confirm.ask(
        "[bold]Resume from checkpoint if available?[/]", default=True
    )
    console.print()
    return domain, profile, fresh


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    _domain = DEFAULT_DOMAIN
    _resume = True
    _fresh = False
    _cli = False
    for arg in sys.argv[1:]:
        if arg == "--resume":
            _resume = True
            _cli = True
        elif arg == "--fresh":
            _fresh = True
            _cli = True
        elif not arg.startswith("-"):
            _domain = arg
            _cli = True

    if not _cli:
        # Interactive mode
        _domain, _profile, _fresh = interactive_startup()
        p = SCAN_PROFILES.get(_profile, SCAN_PROFILES["standard"])
        MAX_STEPS = p["max_steps"]
        BOOTSTRAP_BATCH = p["batch"]
        run_agent._profile = _profile  # type: ignore
    run_agent(_domain, resume=not _fresh, fresh=_fresh)