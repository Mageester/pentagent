# pyre-ignore-all-errors
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
import inspect
import ipaddress
import json
import hashlib
from html import escape as html_escape
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

for _stream in (sys.stdout, sys.stderr):
    try:
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════
#  PHASE 0 — SELF-BOOTSTRAP  (before 3rd-party imports)
# ═══════════════════════════════════════════════════════════
_REQUIRED = {
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
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=300,
        )
        return "ok" if r.returncode == 0 else f"warn: {(r.stderr or '')[:100]}"
    except Exception as e:
        return f"fail: {e}"


def _bootstrap_lighthouse() -> Tuple[bool, str]:
    if not shutil.which("npx"):
        return False, "Node.js not found — Lighthouse disabled"
    try:
        r = subprocess.run(
            ["npx", "--yes", "lighthouse", "--version"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=90,
        )
        if r.returncode == 0:
            return True, f"v{r.stdout.strip()}"
    except Exception:
        pass
    return False, "Lighthouse unavailable"


def _bootstrap_ollama(model: str) -> Tuple[bool, str]:
    try:
        r = subprocess.run(
            ["ollama", "--version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=10,
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
        ["ollama", "list"], capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=15,
    )
    installed_models = {
        line.split()[0]
        for line in r2.stdout.splitlines()
        if line.strip() and not line.lower().startswith("name ")
    }
    if model not in installed_models:
        print(f"[bootstrap] Pulling {model} …")
        subprocess.run(["ollama", "pull", model], timeout=1800)
    return True, ver


def _detect_tools() -> Dict[str, bool]:
    """Detect security tools in PATH."""
    tools = ["nmap", "sqlmap", "nuclei", "subfinder", "httpx",
             "ffuf", "nikto", "gobuster", "dirsearch", "wpscan",
             "testssl.sh", "whatweb", "wfuzz", "amass", "git",
             "curl", "jq", "dig", "whois", "openssl"]
    found = {}
    for t in tools:
        found[t] = shutil.which(t) is not None
    # sqlmap via python module
    if not found["sqlmap"] and importlib.util.find_spec("sqlmap") is not None:
        found["sqlmap"] = True
    # Check WSL availability
    found["wsl"] = shutil.which("wsl") is not None
    # Check Burp Suite Pro
    found["burpsuite"] = BURP_JAR_PATH.exists()
    return found

BURP_JAR_PATH = pathlib.Path(r"C:\Burp\burpsuite_pro_v2025.jar")
BURP_LOADER_PATH = pathlib.Path(r"C:\Burp\loader.jar")


def _bootstrap_lighthouse_runtime() -> Tuple[bool, str]:
    local_npx = shutil.which("npx")
    local_node = shutil.which("node")
    if local_npx and local_node:
        try:
            r = subprocess.run(
                [local_npx, "--yes", "lighthouse", "--version"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=90,
            )
            if r.returncode == 0:
                return True, f"local v{r.stdout.strip()}"
        except Exception:
            pass

    for distro in _detect_wsl_distros():
        try:
            r = subprocess.run(
                [
                    "wsl", "-d", distro, "-u", "root", "bash", "-lc",
                    "command -v npx >/dev/null 2>&1 && command -v node >/dev/null 2>&1",
                ],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=15,
            )
            if r.returncode == 0:
                return True, f"wsl:{distro}"
        except Exception:
            continue

    return False, "Lighthouse unavailable"


def _playwright_chromium_path() -> str:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return getattr(p.chromium, "executable_path", "") or ""
    except Exception:
        return ""


def _detect_wsl_distros() -> List[str]:
    """Detect installed WSL distributions."""
    if not shutil.which("wsl"):
        return []
    try:
        r = subprocess.run(
            ["wsl", "--list", "--quiet"],
            capture_output=True, text=False, timeout=10,
        )
        if r.returncode != 0:
            return []
        raw = r.stdout or b""
        try:
            text = raw.decode("utf-16le")
        except Exception:
            text = raw.decode("utf-8", errors="ignore")
        distros = []
        for line in text.splitlines():
            name = line.strip().strip("\x00").strip("\ufeff")
            if name and name.lower() not in ('windows subsystem for linux',):
                distros.append(name)
        return distros
    except Exception:
        return []


# ── Execute bootstrap ────────────────────────────────────
print("[bootstrap] Checking dependencies …")
_bootstrap_packages()
_PW_STATUS = _bootstrap_playwright()
_LH_OK, _LH_MSG = _bootstrap_lighthouse_runtime()
_DETECTED_TOOLS = _detect_tools()
_WSL_DISTROS = _detect_wsl_distros()
if _WSL_DISTROS:
    print(f"[bootstrap] WSL distros found: {', '.join(_WSL_DISTROS)}")
    preferred = next(
        (d for d in _WSL_DISTROS if "kali" in d.lower()),
        next((d for d in _WSL_DISTROS if "athena" in d.lower()), _WSL_DISTROS[0]),
    )
    if preferred:
        print(f"[bootstrap] Preferred WSL distro: {preferred}")
if _DETECTED_TOOLS.get("burpsuite"):
    print(f"[bootstrap] Burp Suite Pro detected at {BURP_JAR_PATH}")

# ═══════════════════════════════════════════════════════════
#  PHASE 1 — THIRD-PARTY IMPORTS  (guaranteed present)
# ═══════════════════════════════════════════════════════════
import requests  # type: ignore
import urllib3  # type: ignore
from bs4 import BeautifulSoup  # type: ignore
from rich.console import Console  # type: ignore
from rich.panel import Panel  # type: ignore
from rich.table import Table  # type: ignore
from rich.text import Text  # type: ignore
from rich.rule import Rule  # type: ignore
from rich.prompt import Prompt, Confirm  # type: ignore
from rich import box  # type: ignore
from rich.markup import escape as rich_escape  # type: ignore

from security_tools import (  # type: ignore
    check_ssl, check_cookies, check_sensitive_paths,
    check_cors, check_mixed_content, check_email_security,
    check_info_disclosure, check_security_headers_deep,
)
from llm_backends import build_backend, describe_backend  # type: ignore
from workspace import PentWorkspace  # type: ignore
from gateway import PentGateway  # type: ignore
from skill_registry import (  # type: ignore
    build_skill_catalog,
    skill_category_counts,
    skill_overview_lines,
    skill_snapshot,
)

# ═══════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════
DEFAULT_MODEL = "qwen3-coder:30b"
DEFAULT_PROVIDER = "ollama"
DEFAULT_API_BASE = os.getenv("PENTAGENT_API_BASE", "").strip()
DEFAULT_API_KEY_ENV = os.getenv("PENTAGENT_API_KEY_ENV", "OPENAI_API_KEY").strip() or "OPENAI_API_KEY"
MODEL = DEFAULT_MODEL
MODEL_PROVIDER = DEFAULT_PROVIDER
MODEL_API_BASE = DEFAULT_API_BASE
MODEL_API_KEY_ENV = DEFAULT_API_KEY_ENV
DEFAULT_DOMAIN = ""

WORKSPACE = PentWorkspace.from_env().ensure()
OUTPUT_DIR = WORKSPACE.artifacts_dir
CHECKPOINT_PATH = WORKSPACE.checkpoint_path()
JSON_REPORT = OUTPUT_DIR / "audit_report.json"
MD_REPORT = OUTPUT_DIR / "audit_summary.md"
HTML_REPORT = OUTPUT_DIR / "audit_summary.html"
SCREENSHOTS_DIR = OUTPUT_DIR / "screenshots"
LIGHTHOUSE_DIR = OUTPUT_DIR / "lighthouse"
SCAN_LOGS_DIR = OUTPUT_DIR / "scan_logs"
GATEWAY: Optional[PentGateway] = None

MAX_STEPS = 50
REQUEST_TIMEOUT = 20
MAX_EVENT_CHARS = 3000
BOOTSTRAP_BATCH = 6
COMMAND_TIMEOUT = 900

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
llm = None

http = requests.Session()
http.headers.update({"User-Agent": "SiteAuditAgent/2.0 (+self-audit)"})
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console(legacy_windows=True)

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

_ASCII_BANNER = r"""
[bold bright_red]   ____                        __              ____            __[/]
[bold bright_red]  / __ \____  ____ _____  ____/ /_____        / __ \___  _____/ /[/]
[bold bright_red] / /_/ / __ \/ __ `/ __ \/ __  / __ \      / /_/ / _ \/ ___/ / [/]
[bold bright_red]/ ____/ /_/ / /_/ / / / / /_/ / /_/ /     / ____/  __/ /  / /  [/]
[bold bright_red]/_/    \____/\__,_/_/ /_/\__,_/\____/     /_/    \___/_/  /_/   [/]
[bold bright_cyan]              Autonomous Pentest Agent v3.0[/]
[dim]                    Powered by Qwen3 · Ollama · Playwright[/]
"""


def ui_banner(domain: str, profile: str = "standard") -> None:
    console.print(_ASCII_BANNER)
    pw_icon = "[green]✔[/]" if PLAYWRIGHT_AVAILABLE else "[red]✘[/]"
    lh_icon = "[green]✔[/]" if LIGHTHOUSE_AVAILABLE else "[red]✘[/]"
    avail = [t for t, ok in _DETECTED_TOOLS.items() if ok]
    avail_str = ", ".join(avail) if avail else "[dim]none detected[/]"
    backend_text = describe_backend(llm)
    lines = [
        f"[dim]Target:[/]   [bold bright_white]{domain}[/]",
        f"[dim]Model:[/]    [bold]{MODEL}[/]",
        f"[dim]Provider:[/] [bold]{MODEL_PROVIDER}[/] [dim]({compact_text(backend_text, 52)})[/]",
        f"[dim]Profile:[/]  [bold]{profile}[/]",
        f"[dim]Workspace:[/] [bold]{WORKSPACE.agent_id}[/] [dim]({compact_text(str(WORKSPACE.root), 52)})[/]",
    ]
    if STATE is not None and getattr(STATE, "target_profile", "").strip():
        lines.append(f"[dim]Target Type:[/] [bold]{STATE.target_profile}[/]")
    if STATE is not None and getattr(STATE, "autonomy_mode", "").strip():
        lines.append(f"[dim]Autonomy:[/]   [bold]{STATE.autonomy_mode}[/]")
    if STATE is not None and getattr(STATE, "operator_task", "").strip():
        lines.append(f"[dim]Mission:[/]  [bold]{compact_text(STATE.operator_task, 140)}[/]")
    lines.extend([
        "",
        f"  [green]✔[/] Ollama   {pw_icon} Playwright   {lh_icon} Lighthouse",
        f"  [dim]External tools:[/] {avail_str}",
        f"  [dim]Skills:[/] {len(SKILL_CATALOG)} built-in skills across {len(SKILL_COUNTS)} categories",
        f"  [dim]Dashboard:[/] {GATEWAY.dashboard_url if GATEWAY else f'http://127.0.0.1:{WORKSPACE.dashboard_port}/'}",
    ])
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


def _latest_note_text(state: "AgentState") -> str:
    for note in reversed(state.notes):
        note = (note or "").strip()
        if note:
            return compact_text(note, 160)
    return ""


def _latest_finding_text(state: "AgentState") -> str:
    if not state.findings:
        return ""
    finding = state.findings[-1]
    kind = finding.get("kind", "finding")
    severity = finding.get("severity", "info")
    url = finding.get("url", "")
    detail = compact_text(str(finding.get("detail", "")), 180)
    parts = [f"{severity}:{kind}"]
    if url:
        parts.append(url)
    if detail:
        parts.append(detail)
    return " | ".join(parts)


def _latest_tool_text(state: "AgentState") -> str:
    for event in reversed(state.recent_events):
        if event.get("type") != "tool_result":
            continue
        tool = event.get("tool", "")
        ok = "ok" if event.get("ok") else "fail"
        duration = event.get("duration_s", 0.0)
        output = compact_text(str(event.get("output", "")), 120)
        error = compact_text(str(event.get("error", "")), 120)
        detail = output or error
        return f"{tool} [{ok}] {duration:.1f}s {detail}".strip()
    return ""


def _latest_decision_text(state: "AgentState") -> str:
    for event in reversed(state.recent_events):
        if event.get("type") != "decision":
            continue
        data = event.get("data", {})
        if not isinstance(data, dict):
            data = {}
        action = str(data.get("action", "")).strip()
        tool = str(data.get("tool", "")).strip()
        why = str(
            data.get("why")
            or data.get("reason")
            or data.get("summary")
            or ""
        ).strip()
        parts = [piece for piece in (action, tool, why) if piece]
        return " | ".join(parts[:3])
    return ""


def _queue_preview(state: "AgentState", limit: int = 4) -> str:
    if not state.queued_urls:
        return ""
    return ", ".join(state.queued_urls[:limit])


def ui_dashboard(state: "AgentState") -> None:
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="left", ratio=2)
    grid.add_column(justify="left", ratio=2)
    grid.add_column(justify="left", ratio=2)
    goal = compact_text(state.goal, 88)
    task = compact_text(getattr(state, "operator_task", ""), 88)
    autonomy = compact_text(getattr(state, "autonomy_mode", ""), 16)
    latest_finding = _latest_finding_text(state)
    latest_note = _latest_note_text(state)
    latest_tool = _latest_tool_text(state)
    latest_decision = _latest_decision_text(state)
    queue_preview = _queue_preview(state)
    graph_summary = _attack_graph_summary(state)
    target_profile = getattr(state, "target_profile", "") or _target_profile_from_state()
    tool_health = _tool_health_summary(state, limit=3)
    tool_health_text = "; ".join(
        f"{item['tool']}:{item['failure']}/{item['timeouts']}"
        for item in tool_health
    ) or "clean"
    provider_text = compact_text(describe_backend(llm), 56)
    workspace_text = compact_text(str(WORKSPACE.root), 56)
    dashboard_text = GATEWAY.dashboard_url if GATEWAY else f"http://127.0.0.1:{WORKSPACE.dashboard_port}/"
    if state.mode == "network":
        grid.add_row(
            f"[bold cyan]Subnets[/]  {len(getattr(state, 'network_subnets', []))}",
            f"[bold yellow]Hosts[/]  {len(getattr(state, 'network_hosts', []))}",
            f"[bold white]Goal[/]  {goal}",
        )
        grid.add_row(
            f"[bold magenta]Queue[/]  {len(state.queued_urls)}",
            f"[bold red]Findings[/]  {len(state.findings)}",
            f"[dim]Next[/]  {compact_text(queue_preview or 'none', 88)}",
        )
        grid.add_row(
            f"[bold green]Steps[/]  {state.step}/{MAX_STEPS}",
            f"[dim]Mode[/]  network",
            f"[dim]Autonomy[/]  {autonomy or 'free'}",
            f"[dim]Mission[/]  {task or 'none'}",
        )
        grid.add_row(
            f"[dim]Provider[/]  {provider_text}",
            f"[dim]Skills[/]  {len(SKILL_CATALOG)}",
            f"[dim]Categories[/]  {len(SKILL_COUNTS)}",
            f"[dim]Graph[/]  {graph_summary['nodes']}n/{graph_summary['edges']}e",
        )
        grid.add_row(
            f"[dim]Profile[/]  {target_profile}",
            f"[dim]Autonomy[/]  {autonomy or 'free'}",
            f"[dim]Last tool[/]  {latest_tool or 'none'}",
            f"[dim]Tool health[/]  {compact_text(tool_health_text, 88)}",
        )
        grid.add_row(
            f"[dim]Workspace[/]  {workspace_text}",
            f"[dim]Dashboard[/]  {dashboard_text}",
            "",
            "",
        )
        grid.add_row(
            f"[dim]Latest note[/]  {latest_note or 'none'}",
            f"[dim]Latest finding[/]  {latest_finding or 'none'}",
            f"[dim]Latest decision[/]  {latest_decision or 'none'}",
            "",
            "",
        )
    else:
        grid.add_row(
            f"[bold cyan]Pages[/]  {len(state.pages)}",
            f"[bold yellow]Queue[/]  {len(state.queued_urls)}",
            f"[bold white]Goal[/]  {goal}",
        )
        grid.add_row(
            f"[bold red]Findings[/]  {len(state.findings)}",
            f"[bold green]Steps[/]  {state.step}/{MAX_STEPS}",
            f"[dim]Next[/]  {compact_text(queue_preview or 'none', 88)}",
        )
        grid.add_row(
            f"[dim]Profile[/]  {target_profile}",
            f"[dim]Autonomy[/]  {autonomy or 'free'}",
            f"[dim]Mission[/]  {task or 'none'}",
            f"[dim]Graph[/]  {graph_summary['nodes']}n/{graph_summary['edges']}e",
        )
        grid.add_row(
            f"[dim]Provider[/]  {provider_text}",
            f"[dim]Skills[/]  {len(SKILL_CATALOG)}",
            f"[dim]Categories[/]  {len(SKILL_COUNTS)}",
            f"[dim]Tool health[/]  {compact_text(tool_health_text, 88)}",
        )
        grid.add_row(
            f"[dim]Workspace[/]  {workspace_text}",
            f"[dim]Dashboard[/]  {dashboard_text}",
            "",
            "",
        )
        grid.add_row(
            f"[dim]Last tool[/]  {latest_tool or 'none'}",
            f"[dim]Latest note[/]  {latest_note or 'none'}",
            f"[dim]Latest finding[/]  {latest_finding or 'none'}",
            f"[dim]Latest decision[/]  {latest_decision or 'none'}",
        )
    console.print(Panel(grid, title="[bold]Dashboard[/]",
                        border_style="bright_blue", padding=(0, 2)))


def ui_done(elapsed: float) -> None:
    console.print(Panel(
        f"[bold green]✅  Audit complete[/]\n"
        f"Reports saved to [bold]{OUTPUT_DIR}/[/] (JSON, Markdown, HTML)\n"
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
    operator_task: str = ""
    autonomy_mode: str = "free"
    llm_provider: str = "ollama"
    llm_base_url: str = ""
    llm_api_key_env: str = "OPENAI_API_KEY"
    target_profile: str = ""
    mode: str = "web"
    step: int = 0
    network_subnets: List[str] = field(default_factory=list)
    network_hosts: List[Dict[str, Any]] = field(default_factory=list)
    queued_urls: List[str] = field(default_factory=list)
    seen_urls: Set[str] = field(default_factory=set)
    pages: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    recent_events: List[Dict[str, Any]] = field(default_factory=list)
    memory_summary: str = ""
    recent_tool_signatures: List[str] = field(default_factory=list)
    tool_repeat_counts: Dict[str, int] = field(default_factory=dict)
    last_action_signature: str = ""
    attack_graph_nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    attack_graph_edges: List[Dict[str, Any]] = field(default_factory=list)
    tool_health: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "domain": self.domain,
            "mode": self.mode,
            "start_url": self.start_url,
            "goal": self.goal,
            "operator_task": self.operator_task,
            "autonomy_mode": self.autonomy_mode,
            "llm_provider": self.llm_provider,
            "llm_base_url": self.llm_base_url,
            "llm_api_key_env": self.llm_api_key_env,
            "target_profile": self.target_profile,
            "step": self.step,
            "network_subnets": self.network_subnets,
            "network_hosts": self.network_hosts,
            "queued_urls": self.queued_urls,
            "seen_urls": sorted(self.seen_urls),
            "pages": self.pages,
            "findings": self.findings,
            "notes": self.notes,
            "recent_events": self.recent_events[-20:],
            "memory_summary": self.memory_summary,
            "recent_tool_signatures": self.recent_tool_signatures,
            "tool_repeat_counts": self.tool_repeat_counts,
            "last_action_signature": self.last_action_signature,
            "attack_graph_nodes": self.attack_graph_nodes,
            "attack_graph_edges": self.attack_graph_edges,
            "tool_health": self.tool_health,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentState":
        return cls(
            session_id=data["session_id"],
            domain=data["domain"],
            mode=data.get("mode", "web"),
            start_url=data["start_url"],
            goal=data["goal"],
            operator_task=data.get("operator_task", ""),
            autonomy_mode=data.get("autonomy_mode", "free"),
            llm_provider=data.get("llm_provider", "ollama"),
            llm_base_url=data.get("llm_base_url", ""),
            llm_api_key_env=data.get("llm_api_key_env", "OPENAI_API_KEY"),
            target_profile=data.get("target_profile", ""),
            step=data.get("step", 0),
            network_subnets=data.get("network_subnets", []),
            network_hosts=data.get("network_hosts", []),
            queued_urls=data.get("queued_urls", []),
            seen_urls=set(data.get("seen_urls", [])),
            pages=data.get("pages", {}),
            findings=data.get("findings", []),
            notes=data.get("notes", []),
            recent_events=data.get("recent_events", []),
            memory_summary=data.get("memory_summary", ""),
            recent_tool_signatures=data.get("recent_tool_signatures", []),
            tool_repeat_counts=data.get("tool_repeat_counts", {}),
            last_action_signature=data.get("last_action_signature", ""),
            attack_graph_nodes=data.get("attack_graph_nodes", {}),
            attack_graph_edges=data.get("attack_graph_edges", []),
            tool_health=data.get("tool_health", {}),
        )

    def checkpoint(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "AgentState":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


def _persist_workspace_session() -> None:
    if STATE is None:
        return
    try:
        WORKSPACE.write_session_manifest(STATE.to_dict())
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
#  TOOL REGISTRY
# ═══════════════════════════════════════════════════════════
class ToolRegistry:
    def __init__(self) -> None:
        self.tools: Dict[str, Callable[..., ToolResult]] = {}

    def register(self, name: str, fn: Callable[..., ToolResult]) -> None:
        self.tools[name] = fn

    def _resolve_name(self, name: str) -> str:
        if name in self.tools:
            return name
        canonical = _canonical_tool_name(name)
        for candidate in (
            canonical,
            canonical.replace("__", "_"),
            name.strip().lower(),
        ):
            if candidate in self.tools:
                return candidate
        return ""

    def call(self, name: str, **kwargs: Any) -> ToolResult:
        resolved_name = self._resolve_name(name)
        if not resolved_name:
            return ToolResult(ok=False, output="", error=f"Unknown tool: {name}")
        start = time.time()
        try:
            fn = self.tools[resolved_name]
            try:
                sig = inspect.signature(fn)
                params = list(sig.parameters.values())
                accepts_var_kwargs = any(
                    p.kind == inspect.Parameter.VAR_KEYWORD for p in params
                )
                if not accepts_var_kwargs:
                    kwargs = {
                        k: v for k, v in kwargs.items()
                        if k in sig.parameters
                    }
                    missing = [
                        p.name for p in params
                        if p.kind in (
                            inspect.Parameter.POSITIONAL_ONLY,
                            inspect.Parameter.POSITIONAL_OR_KEYWORD,
                            inspect.Parameter.KEYWORD_ONLY,
                        )
                        and p.default is inspect.Signature.empty
                        and p.name not in kwargs
                    ]
                    if missing:
                        return ToolResult(
                            ok=False,
                            output="",
                            error=f"Missing required args for {name}: {', '.join(missing)}",
                        )
                for p in params:
                    if p.name not in kwargs:
                        continue
                    value = kwargs[p.name]
                    annotation = p.annotation
                    if isinstance(value, str):
                        text = value.strip()
                        if not text:
                            continue
                        looks_float = re.fullmatch(r"[-+]?\d+(?:\.\d+)?", text) is not None
                        ann_text = str(annotation).lower()
                        if annotation in {int, "int"} or "int" in ann_text:
                            if looks_float:
                                kwargs[p.name] = int(float(text))
                        elif annotation in {float, "float"} or "float" in ann_text:
                            if looks_float:
                                kwargs[p.name] = float(text)
                        elif annotation in {bool, "bool"} or "bool" in ann_text:
                            lowered = text.lower()
                            if lowered in {"1", "true", "yes", "y", "on"}:
                                kwargs[p.name] = True
                            elif lowered in {"0", "false", "no", "n", "off"}:
                                kwargs[p.name] = False
            except (TypeError, ValueError):
                pass

            result = fn(**kwargs)
            result.duration_s = time.time() - start
            if STATE is not None:
                _record_tool_health(resolved_name, result)
                _graph_add_node(
                    "tool",
                    resolved_name,
                    label=resolved_name,
                    attrs={
                        "last_ok": result.ok,
                        "last_duration_s": round(result.duration_s, 2),
                    },
                )
            return result
        except Exception:
            result = ToolResult(
                ok=False, output="", error=traceback.format_exc(),
                duration_s=time.time() - start,
            )
            if STATE is not None:
                _record_tool_health(resolved_name or name, result)
            return result


# ═══════════════════════════════════════════════════════════
#  GLOBALS
# ═══════════════════════════════════════════════════════════
STATE: Optional[AgentState] = None


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════
def normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    out = f"{scheme}://{netloc}{path}{query}"
    if out.endswith("/") and path != "/":
        out = out[:-1]
    return out


def same_domain(url: str, domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if STATE is not None and STATE.mode == "network":
        return _network_host_in_scope(host)
    dom = domain.lower().split(":", 1)[0]
    return host == dom or host.endswith("." + dom)


def compact_text(text: str, max_len: int = 300) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:max_len]


def _coerce_int_value(value: Any, default: int) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError
        return max(int(float(str(value).strip())), 1)
    except Exception:
        return default


def _canonical_tool_name(name: str) -> str:
    return re.sub(r"[\s\-]+", "_", (name or "").strip().lower())


def _split_operator_tasks(task_text: str) -> List[str]:
    items = []
    for part in re.split(r"[;\n]+", task_text or ""):
        cleaned = part.strip().strip("-•").strip()
        if cleaned:
            items.append(cleaned)
    return items[:12]


def _operator_task_items() -> List[str]:
    assert STATE is not None
    return _split_operator_tasks(getattr(STATE, "operator_task", ""))


def _operator_task_block() -> str:
    items = _operator_task_items() if STATE is not None else []
    if not items:
        return ""
    return "\n".join(f"- {item}" for item in items)


def _network_host_in_scope(host: str) -> bool:
    assert STATE is not None
    host_l = (host or "").strip().lower()
    if not host_l:
        return False

    subnet_sources = list(getattr(STATE, "network_subnets", []) or [])
    if STATE.domain and STATE.domain not in {"auto"}:
        if "/" in STATE.domain:
            subnet_sources.append(STATE.domain)

    try:
        ip = ipaddress.ip_address(host_l)
    except ValueError:
        ip = None

    if ip is not None:
        for subnet in subnet_sources:
            try:
                if ip in ipaddress.ip_network(subnet, strict=False):
                    return True
            except Exception:
                continue
        return False

    discovered = set()
    for rec in getattr(STATE, "network_hosts", []) or []:
        host_name = (rec.get("host") or "").strip().lower()
        if host_name:
            discovered.add(host_name)
        hostname = (rec.get("hostname") or "").strip().lower()
        if hostname:
            discovered.add(hostname)
    return host_l in discovered


def _graph_node_id(kind: str, value: str) -> str:
    kind_l = _normalized_finding_kind(kind) if kind else "node"
    value_l = compact_text(value or "", 180).lower()
    if not value_l:
        value_l = "unknown"
    raw = f"{kind_l}:{value_l}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _graph_add_node(kind: str, value: str, label: str = "",
                   attrs: Optional[Dict[str, Any]] = None) -> str:
    assert STATE is not None
    node_id = _graph_node_id(kind, value)
    node = STATE.attack_graph_nodes.setdefault(node_id, {
        "id": node_id,
        "kind": _normalized_finding_kind(kind),
        "value": compact_text(value, 400),
        "label": compact_text(label or value, 180),
        "attrs": {},
    })
    if attrs:
        node.setdefault("attrs", {}).update(attrs)
    return node_id


def _graph_add_edge(src: str, dst: str, relation: str,
                    attrs: Optional[Dict[str, Any]] = None) -> None:
    assert STATE is not None
    if not src or not dst or src == dst:
        return
    edge = {
        "src": src,
        "dst": dst,
        "relation": relation,
    }
    if attrs:
        edge["attrs"] = attrs
    if edge not in STATE.attack_graph_edges:
        STATE.attack_graph_edges.append(edge)


def _current_tool_name() -> str:
    assert STATE is not None
    for event in reversed(STATE.recent_events):
        if event.get("type") == "tool_result" and event.get("tool"):
            return str(event.get("tool"))
        if event.get("type") == "decision" and event.get("data", {}).get("tool"):
            return str(event.get("data", {}).get("tool"))
    return ""


def _record_tool_health(tool_name: str, result: ToolResult) -> None:
    assert STATE is not None
    name = _canonical_tool_name(tool_name)
    if not name:
        return
    stats = STATE.tool_health.setdefault(name, {
        "calls": 0,
        "success": 0,
        "failure": 0,
        "timeouts": 0,
    })
    stats["calls"] += 1
    if result.ok:
        stats["success"] += 1
    else:
        stats["failure"] += 1
        err = (result.error or "").lower()
        if "timed out" in err:
            stats["timeouts"] += 1


def _target_profile_from_state() -> str:
    assert STATE is not None
    if STATE.mode == "network":
        return "network"
    host = _target_host_label(STATE.domain or STATE.start_url)
    if host == "localhost" or host.endswith((".localhost", ".local", ".lan", ".internal", ".home.arpa")):
        return "local-lab-web"
    if any(token in (STATE.goal or "").lower() for token in ("api", "graphql", "rest", "json")):
        return "api-heavy-web"
    if any(page.get("form_count") for page in STATE.pages.values()):
        return "form-heavy-web"
    if any(page.get("asset_counts", {}).get("scripts", 0) > 10 for page in STATE.pages.values()):
        return "spa-like-web"
    return "web-app"


def _refresh_target_profile() -> None:
    assert STATE is not None
    STATE.target_profile = _target_profile_from_state()


def _infer_target_profile(domain: str, mode: str, start_url: str = "") -> str:
    if mode == "network":
        return "network"
    host = _target_host_label(domain or start_url)
    if host == "localhost" or host.endswith((".localhost", ".local", ".lan", ".internal", ".home.arpa")):
        return "local-lab-web"
    return "web-app"


def record_finding(kind: str, severity: str, url: str, detail: str) -> None:
    assert STATE is not None
    kind = _normalized_finding_kind(kind)
    severity = (severity or "").strip().lower() or "info"
    url_n = normalize_url(url) if url else url
    detail_n = compact_text(detail, 800)
    key = (kind, url_n, detail_n.lower())
    existing = None
    for finding in reversed(STATE.findings[-60:]):
        if (
            finding.get("kind") == kind
            and finding.get("url") == url_n
            and compact_text(str(finding.get("detail", "")), 800).lower() == detail_n.lower()
        ):
            existing = finding
            break

    tool_name = _current_tool_name()
    evidence = {
        "step": STATE.step,
        "tool": tool_name,
    }
    if existing is not None:
        evidence_list = existing.setdefault("evidence", [])
        if evidence not in evidence_list:
            evidence_list.append(evidence)
        existing["evidence_count"] = len(evidence_list)
        existing["validated"] = existing["evidence_count"] >= 2
        existing["confidence"] = min(
            1.0,
            0.35 + 0.2 * existing["evidence_count"] + (0.15 if severity in {"high", "critical"} else 0.0),
        )
        existing["severity"] = max(existing.get("severity", severity), severity, key=_severity_rank)
        return

    finding = {
        "kind": kind,
        "severity": severity,
        "url": url_n,
        "detail": detail_n,
        "evidence": [evidence],
        "evidence_count": 1,
        "validated": False,
        "confidence": 0.45 if severity in {"high", "critical"} else 0.3,
    }
    STATE.findings.append(finding)
    finding_id = _graph_add_node(
        "finding",
        f"{kind}:{url_n}:{detail_n}",
        label=f"{severity}:{kind}",
        attrs=finding,
    )
    source_id = _graph_add_node("surface", url_n or STATE.domain, label=url_n or STATE.domain)
    _graph_add_edge(source_id, finding_id, "supports", {"kind": kind, "severity": severity})


def limited_event(data: Any) -> str:
    if isinstance(data, str):
        return data[:MAX_EVENT_CHARS]
    return json.dumps(data, indent=2)[:MAX_EVENT_CHARS]


def add_sig(signature: str) -> None:
    assert STATE is not None
    STATE.recent_tool_signatures.append(signature)
    STATE.recent_tool_signatures = STATE.recent_tool_signatures[-8:]


def _queue_unique_url(url: str) -> bool:
    assert STATE is not None
    candidate = normalize_url(url)
    if not candidate or candidate in STATE.seen_urls or candidate in STATE.queued_urls:
        return False
    if not same_domain(candidate, STATE.domain):
        return False
    STATE.queued_urls.append(candidate)
    return True


def _bump_repeat_count(signature: str) -> int:
    assert STATE is not None
    current = int(STATE.tool_repeat_counts.get(signature, 0)) + 1
    STATE.tool_repeat_counts[signature] = current
    STATE.last_action_signature = signature
    return current


def _append_unique_network_host(record: Dict[str, Any]) -> Dict[str, Any]:
    assert STATE is not None
    host = (record.get("host") or "").strip().lower()
    if not host:
        return record
    for existing in STATE.network_hosts:
        if (existing.get("host") or "").strip().lower() != host:
            continue
        if record.get("hostname") and not existing.get("hostname"):
            existing["hostname"] = record["hostname"]
        if record.get("status"):
            existing["status"] = record["status"]
        if record.get("last_target"):
            existing["last_target"] = record["last_target"]
        if record.get("last_scan"):
            existing["last_scan"] = record["last_scan"]

        existing_ports = {
            (str(p.get("port")), str(p.get("proto")))
            for p in existing.get("ports", [])
            if isinstance(p, dict)
        }
        for port in record.get("ports", []) or []:
            if not isinstance(port, dict):
                continue
            key = (str(port.get("port")), str(port.get("proto")))
            if key not in existing_ports:
                existing.setdefault("ports", []).append(port)
                existing_ports.add(key)

        existing_urls = set(existing.get("web_urls", []))
        for url in record.get("web_urls", []) or []:
            if url not in existing_urls:
                existing.setdefault("web_urls", []).append(url)
                existing_urls.add(url)

        existing_sources = set(existing.get("sources", []))
        for src in record.get("sources", []) or []:
            if src not in existing_sources:
                existing.setdefault("sources", []).append(src)
                existing_sources.add(src)
        return existing

    STATE.network_hosts.append(record)
    return record


def _normalize_scope_target(raw: str, mode: str = "web") -> str:
    raw = (raw or "").strip()
    if mode == "network":
        return raw.strip("/") or "auto"
    if not raw:
        raw = DEFAULT_DOMAIN
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    host = parsed.hostname or parsed.netloc or candidate.split("/", 1)[0]
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return host.lower()


def _state_origin_url() -> str:
    assert STATE is not None
    if STATE.mode == "network":
        for candidate in getattr(STATE, "queued_urls", []) or []:
            if candidate.startswith(("http://", "https://")):
                parsed = urlparse(candidate)
                if parsed.scheme and parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
        if getattr(STATE, "network_hosts", []):
            host = (STATE.network_hosts[0].get("host") or "").strip()
            if host:
                return f"http://{host}"
        if getattr(STATE, "network_subnets", []):
            subnet = STATE.network_subnets[0].split("/", 1)[0].strip()
            if subnet:
                return f"http://{subnet}"
    if STATE.start_url:
        parsed = urlparse(STATE.start_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{STATE.domain}"


def _state_ssl_target() -> Tuple[str, int]:
    assert STATE is not None
    if STATE.start_url:
        parsed = urlparse(STATE.start_url)
        if parsed.hostname:
            return (
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )
    return STATE.domain, 443


def _url_to_slug(url: str) -> str:
    p = urlparse(url)
    host = p.hostname or ""
    if p.port:
        host = f"{host}_{p.port}"
    raw = f"{host}{p.path}".strip("/") or "index"
    raw = re.sub(r"[^\w\-]+", "_", raw)
    if p.query:
        raw = f"{raw}_{hashlib.sha1(p.query.encode('utf-8')).hexdigest()[:8]}"
    return raw[:80]


def _append_unique_note(note: str) -> None:
    assert STATE is not None
    note = (note or "").strip()
    if note and note not in STATE.notes[-8:]:
        STATE.notes.append(note)


def _extract_form_fields(form: Any) -> List[Dict[str, Any]]:
    fields: List[Dict[str, Any]] = []
    for tag in form.find_all(["input", "textarea", "select"]):
        name = tag.get("name", "") or ""
        field_type = (tag.get("type") or tag.name or "").lower()
        value = tag.get("value", "") or ""
        fields.append({
            "name": name,
            "type": field_type,
            "value_present": bool(value),
            "hidden": field_type == "hidden",
        })
    return fields


def _attack_surface_clues(url: str, title: str = "", h1: str = "",
                          body_text: str = "",
                          forms: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    assert STATE is not None
    clues: List[str] = []
    text = " ".join(part for part in [title, h1, body_text] if part).lower()
    parsed = urlparse(url if "://" in url else f"https://{url}")
    query_params = parse_qs(parsed.query)

    if any(_is_object_reference_param(name) for name in query_params):
        names = ", ".join(sorted(query_params))
        clue = f"Object-reference style query parameter(s) present: {names}"
        clues.append(clue)
        record_finding(
            "attack_surface",
            "low",
            normalize_url(url),
            f"Possible parameter tampering surface: {names}",
        )

    if any(
        re.search(r"(controlled by request parameter|request parameter|parameter)", text)
        and token in text
        for token in ("user id", "id", "account", "object", "reference")
    ):
        clue = "Page text suggests a parameter-controlled object reference or IDOR surface"
        clues.append(clue)
        record_finding(
            "idor",
            "medium",
            normalize_url(url),
            "Page text suggests object control by request parameter; test adjacent IDs and access control boundaries.",
        )

    if forms:
        for form in forms:
            method = str(form.get("method", "GET")).upper()
            inputs = form.get("inputs", []) or []
            field_names = [str(inp.get("name", "")).strip() for inp in inputs if inp.get("name")]
            has_token = any(
                any(tok in name.lower() for tok in _CSRF_TOKEN_HINTS)
                for name in field_names
            )
            has_sensitive_ref = any(
                _is_object_reference_param(name)
                for name in field_names
            )

            if method == "POST" and not has_token:
                clue = "State-changing form lacks an obvious CSRF token"
                clues.append(clue)
                record_finding(
                    "csrf",
                    "low",
                    normalize_url(url),
                    "POST form has no obvious CSRF token/nonce field; verify anti-CSRF protection.",
                )

            if has_sensitive_ref:
                clue = "Form includes object-reference style field names"
                clues.append(clue)
                record_finding(
                    "attack_surface",
                    "low",
                    normalize_url(url),
                    f"Form field names suggest object reference testing: {', '.join(field_names[:8])}",
                )

    if any(word in text for word in ("login", "password", "account", "admin", "reset password")):
        clues.append("Authentication or account-management surface present")

    if clues:
        _append_unique_note(
            f"Attack surface clues for {normalize_url(url)}: {', '.join(clues[:4])}"
        )
    return clues


def _tool_result_text(result: ToolResult) -> str:
    chunks = [result.output or "", result.error or ""]
    try:
        data = json.loads(result.output or "{}")
        if isinstance(data, dict):
            chunks.append(str(data.get("stdout", "")))
            chunks.append(str(data.get("stderr", "")))
        elif isinstance(data, list):
            chunks.append(json.dumps(data))
    except Exception:
        pass
    return "\n".join(chunks)


_OBJECT_REFERENCE_PARAM_NAMES = {
    "id", "uid", "user", "user_id", "userid", "account", "account_id",
    "order", "order_id", "product", "product_id", "item", "item_id",
    "doc", "document", "document_id", "file", "path", "page", "role",
    "ticket", "invoice", "ref", "customer", "customer_id", "profile",
    "tenant", "tenant_id", "workspace", "workspace_id", "team", "team_id",
}
_CSRF_TOKEN_HINTS = {"csrf", "xsrf", "token", "nonce", "authenticity"}
_GOBUSTER_WORDS = [
    "admin", "login", "signin", "signup", "dashboard", "api", "assets",
    "static", "images", "css", "js", "uploads", "upload", "files", "file",
    "private", "internal", "config", "backup", "backups", "dev", "test",
    "old", "tmp", "temp", "docs", "doc", "debug", "status", "health",
    "robots.txt", "sitemap.xml", "phpinfo.php", "server-status", "graphql",
    "swagger", "openapi", "actuator", "console", "cgi-bin", "wp-admin",
    "wp-login.php", "xmlrpc.php", "index.php", "admin.php", "shell.php",
]
_EXPLOIT_FINDING_KINDS = {
    "idor", "csrf", "sqli", "xss", "lfi", "rfi", "rce", "ssrf",
    "open_redirect", "auth", "access_control", "parameter_tamper",
    "command_injection", "path_traversal", "upload", "deserialization",
}


def _normalized_finding_kind(kind: str) -> str:
    cleaned = (kind or "").strip().lower().replace("-", "_")
    if cleaned in {"headers", "header"}:
        return "security_headers"
    return cleaned or "misc"


def _is_object_reference_param(name: str, value: str = "") -> bool:
    name_l = (name or "").strip().lower()
    value_l = (value or "").strip().lower()
    if name_l in _OBJECT_REFERENCE_PARAM_NAMES:
        return True
    if any(token in name_l for token in ("id", "user", "account", "order", "product", "item", "doc", "file", "page", "role", "tenant", "workspace", "team", "customer")):
        return True
    return value_l.isdigit() or bool(re.fullmatch(r"[0-9a-fA-F-]{16,}", value_l))


def _response_signature(resp: requests.Response) -> Dict[str, Any]:
    body = resp.text or ""
    soup = BeautifulSoup(body, "lxml") if body else None
    title = ""
    h1 = ""
    if soup is not None:
        if soup.title:
            title = compact_text(soup.title.get_text(" ", strip=True), 120)
        h1_tag = soup.find("h1")
        if h1_tag:
            h1 = compact_text(h1_tag.get_text(" ", strip=True), 120)
    text_blob = compact_text(
        soup.get_text(" ", strip=True) if soup is not None else body,
        1200,
    )
    return {
        "status": resp.status_code,
        "length": len(body),
        "title": title,
        "h1": h1,
        "body_hash": hashlib.sha256(text_blob.encode("utf-8")).hexdigest()[:16],
    }


def _parameter_value_candidates(name: str, value: str, sample_limit: int) -> List[str]:
    name_l = (name or "").lower()
    value = value or ""
    candidates: List[str] = []
    if value.isdigit():
        num = int(value)
        candidates.extend([
            str(max(num - 1, 0)),
            str(num + 1),
            "1",
            "2",
            "3",
            "10",
            "9999",
        ])
    elif re.fullmatch(r"[0-9a-fA-F-]{16,}", value):
        candidates.extend([
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        ])
    else:
        if any(token in name_l for token in ("id", "user", "account", "order", "product", "item", "doc", "file", "page", "role")):
            candidates.extend(["1", "2", "3", "10", "admin", "test", "guest"])
        else:
            candidates.extend(["1", "2", "admin", "test"])

    deduped: List[str] = []
    for candidate in candidates:
        if candidate == value:
            continue
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped[: max(sample_limit, 1)]


def _signature_delta(base: Dict[str, Any], other: Dict[str, Any]) -> int:
    score = 0
    if base["status"] != other["status"]:
        score += 3
    if base["title"] != other["title"] and base["title"] and other["title"]:
        score += 1
    if base["h1"] != other["h1"] and base["h1"] and other["h1"]:
        score += 1
    if base["body_hash"] != other["body_hash"]:
        score += 1
    delta = abs(base["length"] - other["length"])
    if delta > max(50, int(base["length"] * 0.1)):
        score += 2
    return score


def _windows_path_to_wsl(path: Path) -> str:
    raw = str(path.resolve()).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", raw)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return raw


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
        "query_params": sorted(parse_qs(urlparse(final_url).query).keys()),
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
            inputs = _extract_form_fields(fm)
            has_token = any(
                any(tok in str(inp.get("name", "")).lower() for tok in ("csrf", "xsrf", "token", "nonce", "authenticity"))
                for inp in inputs
            )
            page["forms"].append({
                "action": fm.get("action", ""),
                "method": fm.get("method", "GET").upper(),
                "inputs": inputs[:20],
                "csrf_token_present": has_token,
            })

        _attack_surface_clues(final_url, page["title"], page["h1"], "", page["forms"])

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
    _graph_add_node(
        "page",
        final_url,
        label=page.get("title") or final_url,
        attrs={
            "status_code": page["status_code"],
            "title": page.get("title", ""),
            "h1": page.get("h1", ""),
            "forms": page.get("form_count", 0),
            "internal_links": len(page.get("internal_links", [])),
        },
    )
    _refresh_target_profile()

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
    url = f"{_state_origin_url()}/robots.txt"
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
    url = f"{_state_origin_url()}/sitemap.xml"
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


def tool_site_map(target: str = "", include_queue: bool = True,
                  max_pages: int = 50) -> ToolResult:
    assert STATE is not None
    seed = normalize_url(target or STATE.start_url or _state_origin_url())
    seed_note = ""
    seed_result: Optional[ToolResult] = None

    if (STATE.mode == "web" and seed and same_domain(seed, STATE.domain)
            and seed not in STATE.pages):
        try:
            seed_result = tool_fetch_page(seed)
            if seed_result.ok:
                seed_note = f"Seeded map with {seed}"
            else:
                seed_note = f"Seed fetch failed: {seed_result.error[:160]}"
        except Exception as e:
            seed_result = ToolResult(ok=False, output="", error=str(e))
            seed_note = f"Seed fetch failed: {str(e)[:160]}"

    try:
        snapshot_data = json.loads(tool_site_snapshot().output)
    except Exception:
        snapshot_data = {
            "domain": STATE.domain,
            "pages_seen": len(STATE.pages),
            "queued_urls": len(STATE.queued_urls),
            "findings_total": len(STATE.findings),
        }

    page_summaries = []
    for url, pg in list(STATE.pages.items())[:max_pages]:
        page_summaries.append({
            "url": url,
            "status_code": pg.get("status_code"),
            "title": pg.get("title", ""),
            "h1": pg.get("h1", ""),
            "internal_links": len(pg.get("internal_links", [])),
            "external_links": len(pg.get("external_links", [])),
            "forms": pg.get("form_count", 0),
            "issues": pg.get("issues", []),
        })

    data: Dict[str, Any] = {
        **snapshot_data,
        "target": seed,
        "seed_note": seed_note,
        "page_summaries": page_summaries,
        "queue_preview": STATE.queued_urls[:max_pages] if include_queue else [],
    }
    if seed_result is not None:
        data["seed_fetch"] = {
            "ok": seed_result.ok,
            "error": seed_result.error[:200] if seed_result.error else "",
            "output": seed_result.output[:300] if seed_result.output else "",
        }
    return ToolResult(ok=True, output=json.dumps(data, indent=2))


# ═══════════════════════════════════════════════════════════
#  PLAYWRIGHT TOOLS
# ═══════════════════════════════════════════════════════════
def tool_playwright_screenshot(url: str) -> ToolResult:
    if not PLAYWRIGHT_AVAILABLE:
        return ToolResult(ok=False, output="",
                          error="Playwright not available")
    assert STATE is not None
    url = normalize_url(url)
    page = None
    try:
        browser = _get_browser()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        url = _playwright_goto_with_fallbacks(page, url)
        slug = _url_to_slug(url)
        path = SCREENSHOTS_DIR / f"{slug}.png"
        page.screenshot(path=str(path), full_page=True)
        return ToolResult(ok=True, output=json.dumps(
            {"url": url, "screenshot": str(path)}, indent=2))
    except Exception as e:
        return ToolResult(ok=False, output="",
                          error=f"Screenshot failed: {e}")
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass


def _playwright_goto_with_fallbacks(page: Any, url: str) -> str:
    """Navigate with progressively more tolerant fallbacks."""
    candidates = [url]
    if url.startswith("https://"):
        candidates.append("http://" + url[len("https://"):])
    elif url.startswith("http://"):
        candidates.append("https://" + url[len("http://"):])

    wait_modes = ("networkidle", "load", "domcontentloaded")
    errors = []
    for candidate in candidates:
        for wait_until in wait_modes:
            try:
                page.goto(candidate, timeout=30000, wait_until=wait_until)
                return candidate
            except Exception as e:
                errors.append(f"{candidate} [{wait_until}]: {e}")
    raise RuntimeError("; ".join(errors[-4:]))


def tool_playwright_extract(url: str) -> ToolResult:
    if not PLAYWRIGHT_AVAILABLE:
        return ToolResult(ok=False, output="",
                          error="Playwright not available")
    assert STATE is not None
    url = normalize_url(url)
    page = None
    try:
        browser = _get_browser()
        page = browser.new_page()
        console_errors = []
        page.on("pageerror", lambda e: console_errors.append(str(e)[:200]))
        url = _playwright_goto_with_fallbacks(page, url)
        title = page.title()
        text = page.inner_text("body")[:3000]
        _attack_surface_clues(url, title, "", text, None)
        return ToolResult(ok=True, output=json.dumps({
            "url": url, "rendered_title": title,
            "body_text_preview": text,
            "console_errors": console_errors[:10],
        }, indent=2))
    except Exception as e:
        return ToolResult(ok=False, output="",
                          error=f"DOM extract failed: {e}")
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════
#  LIGHTHOUSE TOOL
# ═══════════════════════════════════════════════════════════
def tool_playwright(url: str = "", mode: str = "extract") -> ToolResult:
    assert STATE is not None
    target = url or STATE.start_url
    mode_l = (mode or "extract").strip().lower()
    if mode_l in {"screenshot", "shot", "image"}:
        return tool_playwright_screenshot(target)
    return tool_playwright_extract(target)


def tool_lighthouse_audit(url: str) -> ToolResult:
    global LIGHTHOUSE_AVAILABLE
    assert STATE is not None
    url = normalize_url(url)
    slug = _url_to_slug(url)
    out_path = LIGHTHOUSE_DIR / f"{slug}.json"
    page = STATE.pages.get(url, {})
    status_code = int(page.get("status_code") or 0)
    if status_code >= 500:
        note = f"Skipping Lighthouse because the cached page returned {status_code}"
        _append_unique_note(note)
        return ToolResult(ok=True, output=json.dumps({
            "url": url,
            "skipped": True,
            "reason": note,
        }, indent=2))
    def _load_report(via: str) -> ToolResult:
        global LIGHTHOUSE_AVAILABLE
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cats = data.get("categories", {})
        scores = {}
        for key, cat in cats.items():
            scores[key] = cat.get("score")
            if cat.get("score") is not None and cat["score"] < 0.5:
                record_finding("lighthouse", "high", url,
                               f"{key} score: {cat['score']:.0%}")
        LIGHTHOUSE_AVAILABLE = True
        return ToolResult(ok=True, output=json.dumps({
            "url": url, "scores": scores,
            "report_path": str(out_path),
            "via": via,
        }, indent=2))

    local_error = ""
    local_ok = bool(shutil.which("npx") and shutil.which("node"))
    if local_ok:
        LIGHTHOUSE_AVAILABLE = True
        try:
            npx_exe = shutil.which("npx") or "npx"
            lighthouse_tmp = LIGHTHOUSE_DIR / "tmp"
            lighthouse_tmp.mkdir(parents=True, exist_ok=True)
            local_env = os.environ.copy()
            local_env.update({
                "TMP": str(lighthouse_tmp),
                "TEMP": str(lighthouse_tmp),
                "TMPDIR": str(lighthouse_tmp),
            })
            chrome_path = _playwright_chromium_path()
            if not chrome_path:
                for candidate in (
                    "chromium", "chromium-browser", "chrome",
                    "google-chrome", "google-chrome-stable",
                ):
                    chrome_path = shutil.which(candidate) or ""
                    if chrome_path:
                        break
            if not chrome_path:
                raise FileNotFoundError("No Chromium executable available for Lighthouse")
            import socket as _socket
            import urllib.request as _urlrequest
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                browser_port = sock.getsockname()[1]
            browser_profile = lighthouse_tmp / f"profile-{slug}"
            browser_profile.mkdir(parents=True, exist_ok=True)
            browser_args = [
                chrome_path,
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                f"--remote-debugging-port={browser_port}",
                f"--user-data-dir={browser_profile}",
                "about:blank",
            ]
            browser_proc = subprocess.Popen(
                browser_args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=local_env,
            )
            try:
                deadline = time.time() + 20
                while time.time() < deadline:
                    try:
                        _urlrequest.urlopen(
                            f"http://127.0.0.1:{browser_port}/json/version",
                            timeout=1,
                        ).read()
                        break
                    except Exception:
                        time.sleep(0.5)
                else:
                    raise RuntimeError("Chromium did not expose a debugging port")

                cmd = [
                    npx_exe, "--yes", "lighthouse", url,
                    "--output=json", f"--output-path={out_path}",
                    f"--port={browser_port}", "--quiet",
                ]
                r = subprocess.run(
                    cmd,
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=120,
                    env=local_env,
                )
                if r.returncode == 0 and out_path.exists():
                    return _load_report("local")
                local_error = f"Lighthouse exit {r.returncode}: {(r.stderr or '')[:200]}"
            finally:
                if browser_proc is not None:
                    try:
                        browser_proc.terminate()
                        browser_proc.wait(timeout=10)
                    except Exception:
                        try:
                            browser_proc.kill()
                        except Exception:
                            pass
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, output="",
                              error="Lighthouse timed out (120s)")
        except Exception as e:
            local_error = f"Lighthouse error: {e}"

    wsl_distros = _detect_wsl_distros()
    if not wsl_distros:
        return ToolResult(
            ok=False,
            output="",
            error=local_error or "Lighthouse not available (Node.js required)",
        )

    distro = _preferred_wsl_distro("npx")
    if not distro:
        return ToolResult(ok=False, output="",
                          error=local_error or "Lighthouse not available (no WSL distro)")

    out_path_wsl = _windows_path_to_wsl(out_path)
    chrome_path = ""
    for candidate in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        try:
            probe = _wsl_run(f"command -v {candidate}", distro, 15, user="root")
            if probe.returncode == 0 and probe.stdout.strip():
                chrome_path = probe.stdout.strip().splitlines()[-1].strip()
                break
        except Exception:
            continue
    if not chrome_path:
        chromium_install = tool_install_tool("chromium")
        if chromium_install.ok:
            for candidate in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
                try:
                    probe = _wsl_run(f"command -v {candidate}", distro, 15, user="root")
                    if probe.returncode == 0 and probe.stdout.strip():
                        chrome_path = probe.stdout.strip().splitlines()[-1].strip()
                        break
                except Exception:
                    continue
    command = (
        f"npx --yes lighthouse {shlex.quote(url)} "
        f"--output=json --output-path={shlex.quote(out_path_wsl)} "
        f"--chrome-flags={shlex.quote('--headless --no-sandbox --disable-dev-shm-usage --disable-gpu')} "
        f"--quiet"
    )
    if chrome_path:
        command = (
            f"npx --yes lighthouse {shlex.quote(url)} "
            f"--output=json --output-path={shlex.quote(out_path_wsl)} "
            f"--chrome-flags={shlex.quote('--headless --no-sandbox --disable-dev-shm-usage --disable-gpu')} "
            f"--chrome-path {shlex.quote(chrome_path)} --quiet"
        )
    for attempt in range(2):
        try:
            r = _wsl_run(command, distro, 150, user="root")
            if r.returncode == 0 and out_path.exists():
                return _load_report(f"wsl:{distro}")
            stderr_text = (r.stderr or "").lower()
            if attempt == 0 and ("npx" in stderr_text or "node" in stderr_text or "not found" in stderr_text):
                install_result = tool_install_tool("lighthouse")
                if install_result.ok:
                    continue
            if attempt == 0 and "chrome" in stderr_text and not chrome_path:
                chromium_install = tool_install_tool("chromium")
                if chromium_install.ok:
                    continue
            if local_error:
                return ToolResult(
                    ok=False,
                    output="",
                    error=f"{local_error}; Lighthouse exit {r.returncode}: {(r.stderr or '')[:200]}",
                )
            return ToolResult(ok=False, output="",
                              error=f"Lighthouse exit {r.returncode}: {(r.stderr or '')[:200]}")
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, output="",
                              error="Lighthouse timed out (150s)")
        except Exception as e:
            if local_error:
                return ToolResult(ok=False, output="",
                                  error=f"{local_error}; Lighthouse error: {e}")
            return ToolResult(ok=False, output="",
                              error=f"Lighthouse error: {e}")

    return ToolResult(ok=False, output="",
                      error=local_error or "Lighthouse could not be executed.")


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


_WSL_ROUTED_TOOLS = {
    "amass", "arjun", "curl", "dirb", "dirsearch", "dig", "dnsenum",
    "dnsrecon", "enum4linux", "enum4linux-ng", "ffuf", "feroxbuster",
    "git", "gobuster", "hydra", "httpx", "httpx-toolkit", "jq",
    "masscan", "nbtscan", "nikto", "nmap", "nuclei", "openssl",
    "paramspider", "recon-ng", "rustscan", "smbclient", "snmpwalk",
    "sqlmap", "subfinder", "testssl.sh", "theharvester", "wafw00f",
    "whatweb", "whois", "wfuzz", "wpscan",
}

_WSL_APT_PACKAGES = {
    "amass": ["amass"],
    "arjun": ["arjun"],
    "curl": ["curl"],
    "dirb": ["dirb"],
    "dirsearch": ["dirsearch"],
    "dig": ["dnsutils"],
    "chromium": ["chromium", "chromium-browser"],
    "dnsenum": ["dnsenum"],
    "dnsrecon": ["dnsrecon"],
    "enum4linux": ["enum4linux", "enum4linux-ng"],
    "enum4linux-ng": ["enum4linux-ng", "enum4linux"],
    "ffuf": ["ffuf"],
    "git": ["git"],
    "feroxbuster": ["feroxbuster"],
    "gobuster": ["gobuster"],
    "hydra": ["hydra"],
    "httpx": ["httpx-toolkit", "httpx"],
    "httpx-toolkit": ["httpx-toolkit", "httpx"],
    "jq": ["jq"],
    "masscan": ["masscan"],
    "nbtscan": ["nbtscan"],
    "nikto": ["nikto"],
    "nmap": ["nmap"],
    "nuclei": ["nuclei"],
    "paramspider": ["paramspider"],
    "recon-ng": ["recon-ng"],
    "rustscan": ["rustscan"],
    "smbclient": ["smbclient"],
    "snmpwalk": ["snmp", "snmp-mibs-downloader"],
    "sqlmap": ["sqlmap"],
    "subfinder": ["subfinder"],
    "testssl.sh": ["testssl.sh"],
    "theharvester": ["theharvester"],
    "wafw00f": ["wafw00f"],
    "whatweb": ["whatweb"],
    "whois": ["whois"],
    "wfuzz": ["wfuzz"],
    "wpscan": ["wpscan"],
}

_WSL_TOOL_CACHE: Dict[str, Dict[str, bool]] = {}


def _wsl_tool_available(distro: str, tool_name: str) -> bool:
    distro_key = distro.lower()
    raw_tool = tool_name.strip().rstrip(".exe")
    if not distro_key or not raw_tool:
        return False
    cached = _WSL_TOOL_CACHE.setdefault(distro_key, {})
    candidates = []
    for candidate in (raw_tool, raw_tool.lower()):
        candidate = candidate.strip()
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        if candidate in cached:
            return cached[candidate]
    try:
        for candidate in candidates:
            r = subprocess.run(
                [
                    "wsl", "-d", distro, "-u", "root", "--",
                    "bash", "-lc", f"command -v {candidate} >/dev/null 2>&1",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            cached[candidate] = r.returncode == 0
            if cached[candidate]:
                return True
    except Exception:
        for candidate in candidates:
            cached[candidate] = False
    return any(cached.get(candidate, False) for candidate in candidates)


def _preferred_wsl_distro(tool_name: str = "") -> str:
    if not _WSL_DISTROS:
        return ""
    for needle in ("kali", "athena"):
        for distro in _WSL_DISTROS:
            if needle in distro.lower():
                return distro
    if tool_name:
        for distro in _WSL_DISTROS:
            if _wsl_tool_available(distro, tool_name):
                return distro
    return _WSL_DISTROS[0]


def _command_entrypoint(command: str) -> str:
    parts = command.strip().split()
    if not parts:
        return ""
    idx = 0
    if parts[0].lower() == "sudo":
        idx = 1
        while idx < len(parts) and parts[idx].startswith("-"):
            idx += 1
    return parts[idx] if idx < len(parts) else ""


def _command_timeout_floor(command: str) -> int:
    parsed = _parse_wsl_command(command)
    if parsed is not None:
        _, inner_command, _ = parsed
        entrypoint = _command_entrypoint(inner_command).lower().rstrip(".exe")
    else:
        entrypoint = _command_entrypoint(command).lower().rstrip(".exe")
    return {
        "nmap": 300,
        "nuclei": 300,
        "sqlmap": 600,
        "lighthouse": 180,
        "nikto": 180,
        "gobuster": 180,
        "feroxbuster": 180,
    }.get(entrypoint, 0)


def _shell_join(tokens: List[str]) -> str:
    specials = {"&&", "||", "|", ";", "&", ">", ">>", "<", "(", ")"}
    pieces = []
    for token in tokens:
        if token in specials:
            pieces.append(token)
        else:
            pieces.append(shlex.quote(token))
    return " ".join(pieces)


def _parse_wsl_command(command: str) -> Optional[Tuple[str, str, str]]:
    text = command.strip()
    if not text.lower().startswith("wsl"):
        return None
    try:
        parts = shlex.split(text, posix=True)
    except ValueError:
        return None
    if not parts or parts[0].lower() not in {"wsl", "wsl.exe"}:
        return None

    distro = ""
    user = "root"
    saw_target = False
    idx = 1
    while idx < len(parts):
        token = parts[idx].lower()
        if token in {"-d", "--distribution"} and idx + 1 < len(parts):
            distro = parts[idx + 1]
            saw_target = True
            idx += 2
            continue
        if token in {"-u", "--user"} and idx + 1 < len(parts):
            user = parts[idx + 1]
            saw_target = True
            idx += 2
            continue
        if token in {"--cd"} and idx + 1 < len(parts):
            idx += 2
            continue
        if token in {"--", "-e", "--exec"}:
            idx += 1
            break
        if token.startswith("-") and not saw_target:
            return None
        break

    inner = _shell_join(parts[idx:])
    if not inner:
        return None
    return (distro or _preferred_wsl_distro(), inner, user)


def _should_route_to_wsl(command: str) -> bool:
    if not _WSL_DISTROS:
        return False
    entrypoint = _command_entrypoint(command).lower().rstrip(".exe")
    return entrypoint in _WSL_ROUTED_TOOLS


def _wsl_run(command: str, distro: str, timeout: int,
             user: str = "root") -> subprocess.CompletedProcess[str]:
    wsl_args = ["wsl", "-d", distro]
    if user:
        wsl_args += ["-u", user]
    wsl_args += ["bash", "-lc", command]
    return subprocess.run(
        wsl_args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        cwd=str(OUTPUT_DIR),
    )


def _install_tool_in_wsl(tool_name: str) -> ToolResult:
    distro = _preferred_wsl_distro(tool_name)
    if not distro:
        return ToolResult(ok=False, output="", error="No WSL distro available")

    if _wsl_tool_available(distro, tool_name):
        return ToolResult(ok=True, output=json.dumps({
            "installed": tool_name,
            "via": "existing-wsl",
            "distro": distro,
        }, indent=2))

    candidates = _WSL_APT_PACKAGES.get(tool_name.lower(), [tool_name.lower()])
    last_error = ""
    for package in candidates:
        try:
            r = subprocess.run(
                [
                    "wsl", "-d", distro, "-u", "root", "bash", "-lc",
                    (
                        "export DEBIAN_FRONTEND=noninteractive; "
                        "apt-get update && "
                        f"apt-get install -y {package}"
                    ),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=1800,
            )
            if r.returncode == 0:
                return ToolResult(
                    ok=True,
                    output=json.dumps({
                        "installed": tool_name,
                        "package": package,
                        "via": "wsl-apt",
                        "distro": distro,
                    }, indent=2),
                )
            last_error = (r.stderr or r.stdout)[-500:]
        except Exception as e:
            last_error = str(e)

    return ToolResult(
        ok=False,
        output="",
        error=f"WSL install failed for {tool_name}: {last_error}",
    )


def tool_run_command(command: str, timeout: int = 120) -> ToolResult:
    """Execute a shell command. The LLM decides what to run."""
    assert STATE is not None

    # Auto-approve all commands (fully autonomous)
    if _is_risky(command):
        console.print(f"\n  [bold red]⚠ RISKY COMMAND EXECUTION APPROVED (AUTO):[/]")
        console.print(f"  [yellow]{command}[/]")

    timeout = _coerce_int_value(timeout, 120)
    timeout = max(timeout, _command_timeout_floor(command))
    timeout = min(timeout, COMMAND_TIMEOUT)
    log_path = SCAN_LOGS_DIR / f"cmd_{time.time_ns()}_{uuid.uuid4().hex[:8]}.txt"
    try:
        wsl_command = _parse_wsl_command(command)
        routed_to_wsl = wsl_command is not None or _should_route_to_wsl(command)
        if wsl_command is not None:
            distro, inner_command, user = wsl_command
            console.print(
                f"  [dim]Routing direct WSL command to distro:[/] [bold]{distro}[/]"
            )
            r = _wsl_run(inner_command, distro, timeout, user=user)
        elif _should_route_to_wsl(command):
            entrypoint = _command_entrypoint(command)
            distro = _preferred_wsl_distro(entrypoint)
            console.print(
                f"  [dim]Routing command to WSL distro:[/] [bold]{distro}[/]"
            )
            r = _wsl_run(command, distro, timeout)
        else:
            r = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout, cwd=str(OUTPUT_DIR),
            )

        if r.returncode != 0:
            stderr_text = (r.stderr or "").lower()
            missing_tool = ""
            m = re.search(r"(?:bash|sh):\s*([^:\s]+): command not found", stderr_text)
            if m:
                missing_tool = m.group(1)
            if not missing_tool:
                m = re.search(
                    r"'([^']+)' is not recognized as an internal or external command",
                    stderr_text,
                )
                if m:
                    missing_tool = m.group(1)
            if not missing_tool:
                missing_tool = _command_entrypoint(command).lower().rstrip(".exe")
            if ("command not found" in stderr_text or "not found" in stderr_text
                    or "not recognized" in stderr_text):
                install_tool_result = tool_install_tool(missing_tool)
                if install_tool_result.ok:
                    if wsl_command is not None:
                        distro, inner_command, user = wsl_command
                        console.print(
                            f"  [dim]Retrying direct WSL command after installing {missing_tool}...[/]"
                        )
                        r = _wsl_run(inner_command, distro, timeout, user=user)
                    elif routed_to_wsl:
                        distro = _preferred_wsl_distro(missing_tool)
                        console.print(
                            f"  [dim]Retrying command in WSL after installing {missing_tool}...[/]"
                        )
                        r = _wsl_run(command, distro, timeout)
                    else:
                        console.print(
                            f"  [dim]Retrying command after installing {missing_tool}...[/]"
                        )
                        r = subprocess.run(
                            command, shell=True, capture_output=True, text=True,
                            encoding="utf-8", errors="replace",
                            timeout=timeout, cwd=str(OUTPUT_DIR),
                        )

        stdout_text = r.stdout or ""
        stderr_text = r.stderr or ""
        stdout = stdout_text[-4000:] if len(stdout_text) > 4000 else stdout_text
        stderr = stderr_text[-2000:] if len(stderr_text) > 2000 else stderr_text
        # Log full output
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(
                f"$ {command}\n\n--- stdout ---\n{stdout_text}"
                f"\n--- stderr ---\n{stderr_text}\n"
            )
        return ToolResult(ok=r.returncode == 0, output=json.dumps({
            "command": command, "returncode": r.returncode,
            "stdout": stdout, "stderr": stderr, "log": str(log_path),
        }, indent=2))
    except subprocess.TimeoutExpired as e:
        stdout_text = getattr(e, "stdout", "") or ""
        stderr_text = getattr(e, "stderr", "") or ""
        try:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(
                    f"$ {command}\n\n--- stdout ---\n{stdout_text}"
                    f"\n--- stderr ---\n{stderr_text}\n"
                )
        except Exception:
            pass
        return ToolResult(ok=False, output=json.dumps({
            "command": command,
            "returncode": None,
            "stdout": stdout_text[-4000:] if len(stdout_text) > 4000 else stdout_text,
            "stderr": stderr_text[-2000:] if len(stderr_text) > 2000 else stderr_text,
            "log": str(log_path),
            "timed_out": True,
            "timeout_s": timeout,
        }, indent=2), error=f"Timed out ({timeout}s)")
    except Exception as e:
        return ToolResult(ok=False, output="", error=str(e))


def tool_ask_user(question: str) -> ToolResult:
    """Ask the operator a question and return their response."""
    console.print(f"\n  [bold bright_cyan]🤖 Agent wanted to ask you (bypassed):[/]")
    console.print(f"  [bold]{question}[/]")
    answer = "You are fully autonomous. Please do not ask me questions. Figure it out and proceed."
    return ToolResult(ok=True, output=json.dumps({"question": question, "answer": answer}))


def tool_install_tool(tool_name: str) -> ToolResult:
    """Attempt to install a security tool via WSL apt, winget, or pip."""
    tool_key = tool_name.lower().strip().rstrip(".exe")
    if tool_key in {"burp", "burpsuite", "burpsuitepro"}:
        if BURP_JAR_PATH.exists():
            return ToolResult(ok=True, output=json.dumps({
                "installed": "burpsuite",
                "via": "existing-jar",
                "path": str(BURP_JAR_PATH),
            }, indent=2))
        return ToolResult(
            ok=False,
            output="",
            error="Burp Suite Pro JAR not found at the configured path.",
        )

    if tool_key == "lighthouse":
        global LIGHTHOUSE_AVAILABLE
        if LIGHTHOUSE_AVAILABLE or (shutil.which("npx") and shutil.which("node")):
            LIGHTHOUSE_AVAILABLE = True
            return ToolResult(ok=True, output=json.dumps({
                "installed": "lighthouse",
                "via": "existing-node",
                "note": "Use the lighthouse_audit tool.",
            }, indent=2))
        if _WSL_DISTROS:
            distro = _preferred_wsl_distro("nodejs")
            if distro:
                try:
                    r = subprocess.run(
                        [
                            "wsl", "-d", distro, "-u", "root", "bash", "-lc",
                            (
                                "export DEBIAN_FRONTEND=noninteractive; "
                                "apt-get update && apt-get install -y nodejs npm"
                            ),
                        ],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=1800,
                    )
                    if r.returncode == 0:
                        LIGHTHOUSE_AVAILABLE = True
                        return ToolResult(ok=True, output=json.dumps({
                            "installed": "lighthouse",
                            "via": "wsl-node",
                            "distro": distro,
                            "output": (r.stdout or "")[-500:],
                        }, indent=2))
                except Exception as e:
                    pass
        if shutil.which("winget"):
            try:
                r = subprocess.run(
                    [
                        "winget", "install", "--id", "OpenJS.NodeJS",
                        "--accept-package-agreements", "--accept-source-agreements",
                        "-e",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=1800,
                )
                if r.returncode == 0:
                    LIGHTHOUSE_AVAILABLE = True
                    return ToolResult(ok=True, output=json.dumps({
                        "installed": "lighthouse",
                        "via": "winget-node",
                        "output": (r.stdout or "")[-500:],
                    }, indent=2))
            except Exception as e:
                return ToolResult(ok=False, output="", error=f"winget install failed: {e}")
        return ToolResult(
            ok=False,
            output="",
            error="Could not install Node.js/npm required for Lighthouse.",
        )

    if _WSL_DISTROS and tool_key in _WSL_APT_PACKAGES:
        return _install_tool_in_wsl(tool_key)

    pip_tools = {
        "sqlmap": "sqlmap",
        "dirsearch": "dirsearch",
        "wapiti": "wapiti3",
    }
    winget_tools = {
        "nmap": "Insecure.Nmap",
        "ffuf": "ffuf",
        "nuclei": "ProjectDiscovery.Nuclei",
        "subfinder": "ProjectDiscovery.Subfinder",
        "httpx": "ProjectDiscovery.httpx",
    }

    if tool_key in pip_tools:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet",
                 pip_tools[tool_key]],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return ToolResult(ok=True, output=json.dumps({
                "installed": tool_key, "via": "pip"
            }))
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"pip install failed: {e}")

    if tool_key in winget_tools and shutil.which("winget"):
        try:
            r = subprocess.run(
                ["winget", "install", "--id", winget_tools[tool_key],
                 "--accept-package-agreements", "--accept-source-agreements", "-e"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=300,
            )
            return ToolResult(ok=r.returncode == 0, output=json.dumps({
                "installed": tool_key, "via": "winget",
                "output": (r.stdout or "")[-500:]
            }), error=(r.stderr or "")[-300:] if r.returncode != 0 else "")
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"winget install failed: {e}")

    return ToolResult(
        ok=False,
        output="",
        error=f"Don't know how to install '{tool_name}'. Install manually.",
    )


def tool_install(package: str = "", destination: str = "",
                 source: str = "") -> ToolResult:
    assert STATE is not None
    package_name = (package or "").strip()
    dest = (destination or "").strip()
    src = (source or "").strip()

    requested = " ".join(part for part in [package_name, src, dest] if part).lower()
    wants_nuclei_templates = (
        "nuclei-templates" in requested or package_name.lower() == "nuclei-templates"
    )
    if wants_nuclei_templates:
        repo = src or "https://github.com/projectdiscovery/nuclei-templates.git"
        dest = dest or "/usr/local/share/nuclei-templates"
        distro = _preferred_wsl_distro("git")
        if not distro:
            return ToolResult(
                ok=False,
                output="",
                error="No WSL distro available to install nuclei templates.",
            )
        if _wsl_run(f"test -d {shlex.quote(dest)}/.git", distro, 30).returncode == 0:
            r = _wsl_run(
                f"git -C {shlex.quote(dest)} pull --ff-only",
                distro,
                1200,
            )
            if r.returncode != 0 and "not found" in (r.stderr or "").lower():
                install_result = tool_install_tool("git")
                if install_result.ok:
                    r = _wsl_run(
                        f"git -C {shlex.quote(dest)} pull --ff-only",
                        distro,
                        1200,
                    )
            return ToolResult(
                ok=r.returncode == 0,
                output=json.dumps({
                    "installed": "nuclei-templates",
                    "destination": dest,
                    "via": "wsl-git-pull",
                    "stdout": (r.stdout or "")[-1000:],
                    "stderr": (r.stderr or "")[-500:],
                }, indent=2),
                error=(r.stderr or "")[-500:] if r.returncode != 0 else "",
            )
        if _wsl_run(f"test -d {shlex.quote(dest)}", distro, 30).returncode == 0:
            return ToolResult(ok=True, output=json.dumps({
                "installed": "nuclei-templates",
                "destination": dest,
                "via": "existing-directory",
            }, indent=2))
        r = _wsl_run(
            f"git clone {shlex.quote(repo)} {shlex.quote(dest)}",
            distro,
            1200,
        )
        if r.returncode != 0 and "not found" in (r.stderr or "").lower():
            install_result = tool_install_tool("git")
            if install_result.ok:
                r = _wsl_run(
                    f"git clone {shlex.quote(repo)} {shlex.quote(dest)}",
                    distro,
                    1200,
                )
        return ToolResult(
            ok=r.returncode == 0,
            output=json.dumps({
                "installed": "nuclei-templates",
                "destination": dest,
                "via": "wsl-git-clone",
                "stdout": (r.stdout or "")[-1000:],
                "stderr": (r.stderr or "")[-500:],
            }, indent=2),
            error=(r.stderr or "")[-500:] if r.returncode != 0 else "",
        )

    if src and src.startswith(("http://", "https://", "git@", "ssh://")):
        if not dest:
            dest = pathlib.Path(src.rsplit("/", 1)[-1]).stem or "repo"
        distro = _preferred_wsl_distro("git") if dest.startswith("/") else ""
        command = f"git clone {shlex.quote(src)} {shlex.quote(dest)}"
        if distro:
            return tool_run_command(f"wsl -d {distro} {command}", timeout=1200)
        try:
            r = subprocess.run(
                ["git", "clone", src, dest],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=1200,
            )
            return ToolResult(
                ok=r.returncode == 0,
                output=json.dumps({
                    "installed": src,
                    "destination": dest,
                    "via": "git",
                    "stdout": (r.stdout or "")[-1000:],
                    "stderr": (r.stderr or "")[-500:],
                }, indent=2),
                error=(r.stderr or "")[-500:] if r.returncode != 0 else "",
            )
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"git clone failed: {e}")

    if package_name:
        return tool_install_tool(package_name)

    if dest and src:
        try:
            src_path = pathlib.Path(src)
            dest_path = pathlib.Path(dest)
            if src_path.is_dir():
                shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
            else:
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dest_path)
            return ToolResult(ok=True, output=json.dumps({
                "installed": src,
                "destination": dest,
                "via": "filesystem-copy",
            }, indent=2))
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"filesystem copy failed: {e}")

    return ToolResult(
        ok=False,
        output="",
        error="install requires package, source, or destination arguments",
    )


def _target_to_host(target: str) -> str:
    raw = (target or "").strip()
    if not raw and STATE is not None:
        raw = STATE.domain
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or raw
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return host
    return raw


def _looks_like_ip_or_cidr(value: str) -> bool:
    text = (value or "").strip()
    if not text:
        return False
    try:
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
            return True
        ipaddress.ip_address(text)
        return True
    except Exception:
        return False


def _target_host_label(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"//{raw}"
    parsed = urlparse(candidate)
    host = parsed.hostname or raw.split("/", 1)[0]
    return (host or raw).strip().lower()


def _supports_subdomain_recon(value: str) -> bool:
    host = _target_host_label(value)
    if not host:
        return False
    if _looks_like_ip_or_cidr(host):
        return False
    if host == "localhost" or host.endswith((".localhost", ".local", ".lan", ".internal", ".home.arpa")):
        return False
    return "." in host


def _sanitize_nuclei_args(extra_args: str) -> str:
    tokens = shlex.split(extra_args or "")
    cleaned: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in {"-validate", "--validate"}:
            i += 1
            continue
        if tok in {"-u", "--url", "--config", "--remote-template-domain",
                   "--template-id", "-o", "--output"}:
            i += 2 if i + 1 < len(tokens) else 1
            continue
        if tok in {"-t", "--templates"}:
            if i + 1 < len(tokens):
                tmpl = tokens[i + 1]
                if (
                    tmpl.startswith("http://")
                    or tmpl.startswith("https://")
                    or "raw.githubusercontent.com" in tmpl
                    or "config/techniques" in tmpl
                ):
                    i += 2
                    continue
                normalized = _normalize_nuclei_template_value(tmpl)
                if normalized:
                    cleaned.extend([tok, normalized])
                i += 2
                continue
            i += 1
            continue
        cleaned.append(tok)
        i += 1
    return " ".join(cleaned).strip()


def _normalize_nuclei_template_value(value: str) -> str:
    template_dir = "/usr/local/share/nuclei-templates"
    raw = (value or "").strip().strip('"').strip("'")
    if not raw:
        return template_dir
    if raw.lower() == "all":
        return template_dir
    if raw.startswith(("http://", "https://")) or "raw.githubusercontent.com" in raw:
        return ""
    if "config/techniques" in raw:
        return ""
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    if not parts:
        return template_dir
    valid_parts = []
    for part in parts:
        if part.startswith(("http://", "https://")) or "raw.githubusercontent.com" in part:
            continue
        if "config/techniques" in part:
            continue
        if pathlib.Path(part).exists():
            valid_parts.append(part)
    if valid_parts:
        return ",".join(valid_parts)
    if raw.endswith("/all") or raw.endswith("\\all"):
        return template_dir
    return template_dir


_NUCLEI_FINDING_KIND_MAP = {
    "http-missing-security-headers": "security_headers",
    "missing-sri": "security_headers",
    "robots-txt": "crawl",
    "robots-txt-endpoint": "crawl",
    "dns-waf-detect": "fingerprint",
    "waf-detect": "fingerprint",
    "tls-version": "ssl",
    "ssl-issuer": "ssl",
    "ssl-dns-names": "ssl",
    "spf-record-detect": "email_security",
    "dmarc-detect": "email_security",
    "dkim-record-detect": "email_security",
    "caa-fingerprint": "dns",
    "mx-fingerprint": "dns",
    "nameserver-fingerprint": "dns",
    "rdap-whois": "fingerprint",
}


def _record_nuclei_findings(target: str, nuclei_output: str) -> None:
    pattern = re.compile(
        r"^\[(?P<name>[^\]]+)\]\s+\[[^\]]+\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<rest>.+)$"
    )
    seen: Set[Tuple[str, str, str, str]] = set()
    for line in (nuclei_output or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        severity = match.group("severity").strip().lower()
        if severity not in {"low", "medium", "high", "critical"}:
            continue
        template = match.group("name").split(":", 1)[0].strip().lower()
        kind = _NUCLEI_FINDING_KIND_MAP.get(template, "nuclei")
        detail = compact_text(line, 240)
        key = (kind, severity, target, detail)
        if key in seen:
            continue
        seen.add(key)
        record_finding(kind, severity, target, detail)


def _sanitize_whatweb_args(extra_args: str) -> str:
    tokens = shlex.split(extra_args or "")
    cleaned: List[str] = []
    for tok in tokens:
        if tok == "--no-color":
            tok = "--color=never"
        if tok not in cleaned:
            cleaned.append(tok)
    if "--no-errors" not in cleaned:
        cleaned.insert(0, "--no-errors")
    if "--color=never" not in cleaned:
        cleaned.append("--color=never")
    return " ".join(cleaned).strip()


def _sanitize_gobuster_args(extra_args: str) -> str:
    tokens = shlex.split(extra_args or "")
    cleaned: List[str] = []
    skip_with_value = {
        "-b", "--status-codes-blacklist",
        "-m", "--mode",
        "-u", "--url",
        "-w", "--wordlist",
        "-s", "--status-codes",
    }
    skip_tokens = {
        "dir", "dns", "fuzz", "--dir", "--dns", "--fuzz",
    }
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in skip_with_value:
            i += 2 if i + 1 < len(tokens) else 1
            continue
        if tok in skip_tokens:
            i += 1
            continue
        cleaned.append(tok)
        i += 1
    return " ".join(cleaned).strip()


_NETWORK_WEB_PORTS = {
    80, 81, 443, 3000, 5000, 7001, 7002, 8000, 8001, 8080, 8081,
    8443, 8888, 9000, 9443, 10443,
}


def _parse_nmap_inventory(target: str, output_text: str, scan_label: str = "nmap") -> None:
    assert STATE is not None
    for line in (output_text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("Host:"):
            continue
        m = re.match(
            r"^Host:\s+(?P<host>\S+)\s+\((?P<hostname>.*?)\)\s+(?P<rest>.+)$",
            stripped,
        )
        if not m:
            continue
        host = m.group("host").strip()
        hostname = m.group("hostname").strip()
        rest = m.group("rest").strip()
        status = "up" if "Status: Up" in rest or "Status: up" in rest else ""

        ports_blob = ""
        if "Ports:" in rest:
            ports_blob = rest.split("Ports:", 1)[1]
            for marker in ("Ignored State:", "Seq Index:", "OS:"):
                if marker in ports_blob:
                    ports_blob = ports_blob.split(marker, 1)[0]

        ports: List[Dict[str, Any]] = []
        open_services: List[str] = []
        web_urls: List[str] = []
        for entry in ports_blob.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = [p.strip() for p in entry.split("/")]
            if len(parts) < 4 or not parts[0].isdigit():
                continue
            port_num = int(parts[0])
            state = parts[1].lower()
            proto = parts[2].lower()
            service = parts[4].strip() if len(parts) > 4 else ""
            ports.append({
                "port": port_num,
                "state": state,
                "proto": proto,
                "service": service,
            })
            if state in {"open", "open|filtered"}:
                open_services.append(
                    f"{port_num}/{proto}/{service or 'unknown'}"
                )
                service_l = service.lower()
                if (
                    port_num in _NETWORK_WEB_PORTS
                    or service_l in {"http", "https", "http-alt", "http-proxy"}
                    or "http" in service_l
                    or "https" in service_l
                    or "ssl" in service_l
                ):
                    scheme = (
                        "https"
                        if port_num in {443, 8443, 9443, 10443}
                        or "https" in service_l
                        or "ssl" in service_l
                        else "http"
                    )
                    if (scheme == "http" and port_num == 80) or (
                        scheme == "https" and port_num == 443
                    ):
                        web_url = f"{scheme}://{host}"
                    else:
                        web_url = f"{scheme}://{host}:{port_num}"
                    web_urls.append(web_url)

        host_record = _append_unique_network_host({
            "host": host,
            "hostname": hostname,
            "status": status or ("up" if open_services else "unknown"),
            "ports": ports,
            "web_urls": [],
            "sources": [f"{scan_label}:{target}"],
            "last_target": target,
            "last_scan": scan_label,
        })

        for web_url in web_urls:
            if web_url not in host_record.setdefault("web_urls", []):
                host_record["web_urls"].append(web_url)
            if web_url not in STATE.seen_urls and web_url not in STATE.queued_urls:
                STATE.queued_urls.append(web_url)

        if open_services:
            _append_unique_note(
                f"{scan_label} {host}: {', '.join(open_services[:6])}"
            )


def tool_nmap(target: str = "", extra_args: str = "-sV -sC --top-ports 100 -T4 -Pn",
              timeout: int = 600, ports: str = "",
              scan_type: str = "") -> ToolResult:
    assert STATE is not None
    host = _target_to_host(target or STATE.domain)
    timeout = _coerce_int_value(timeout, 600)
    flags = extra_args.strip()
    scan_map = {
        "syn": "-sS",
        "connect": "-sT",
        "udp": "-sU",
        "ack": "-sA",
        "window": "-sW",
        "maimon": "-sM",
        "null": "-sN",
        "fin": "-sF",
        "xmas": "-sX",
    }
    if ports and "-p" not in flags and "--top-ports" not in flags:
        flags = f"{flags} -p {shlex.quote(str(ports).strip())}".strip()
    scan_key = scan_type.lower().strip()
    if scan_key in scan_map and scan_map[scan_key] not in flags:
        flags = f"{flags} {scan_map[scan_key]}".strip()
    if "-Pn" not in flags and "-sn" not in flags:
        flags = f"{flags} -Pn".strip()
    if "-oG" not in flags and "-oX" not in flags and "-oN" not in flags:
        flags = f"{flags} -oG -".strip()
    command = f"nmap {flags} {shlex.quote(host)}".strip()
    result = tool_run_command(command, timeout=timeout)
    text = _tool_result_text(result)
    _parse_nmap_inventory(host, text, "nmap")
    lowered = text.lower()
    if result.ok:
        if any(phrase in lowered for phrase in (
            "filtered tcp ports",
            "0 open",
            "all 1000 scanned ports",
            "no-response",
            "ignored states",
        )):
            _append_unique_note(
                "Nmap found no obvious network services; pivot to HTTP crawling, content discovery, and parameter testing."
            )
        elif re.search(r"\b80/tcp\s+open\b|\b443/tcp\s+open\b|open\s+http", lowered):
            _append_unique_note(
                "Web service exposed on 80/443; prioritize HTTP content discovery, JS rendering, and active web testing."
            )
    return result


def tool_nuclei(url: str = "", extra_args: str = "-timeout 5 -retries 1 -rate-limit 50",
                timeout: int = 600) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    timeout = _coerce_int_value(timeout, 600)
    sanitized = _sanitize_nuclei_args(extra_args)
    if "-t" not in sanitized and "--templates" not in sanitized:
        sanitized = f"-t /usr/local/share/nuclei-templates {sanitized}".strip()
    command = f"nuclei -u {shlex.quote(target)} {sanitized}".strip()
    result = tool_run_command(command, timeout=timeout)
    text = _tool_result_text(result).lower()
    template_issue = any(phrase in text for phrase in (
        "could not find template",
        "no templates found",
        "no results found",
        "0 templates",
    ))
    if template_issue:
        install_result = tool_install(package="nuclei-templates")
        if install_result.ok:
            template_dir = "/usr/local/share/nuclei-templates"
            retry_sanitized = _sanitize_nuclei_args(sanitized)
            if "-t" not in retry_sanitized and "--templates" not in retry_sanitized:
                retry_sanitized = f"-t {shlex.quote(template_dir)} {retry_sanitized}".strip()
            retry_command = f"nuclei -u {shlex.quote(target)} {retry_sanitized}".strip()
            retry_result = tool_run_command(retry_command, timeout=timeout)
            retry_text = _tool_result_text(retry_result).lower()
            if retry_result.ok and not any(phrase in retry_text for phrase in (
                "could not find template",
                "no templates found",
                "no results found",
                "0 templates",
            )):
                _append_unique_note(
                    "Nuclei templates were auto-installed and the scan was retried."
                )
                return retry_result
            result = retry_result
            text = retry_text
    if result.ok and template_issue:
        _append_unique_note(
            "Nuclei output indicates a template/path issue; retry with local nuclei-templates or a different template set."
        )
    if result.ok:
        _record_nuclei_findings(target, _tool_result_text(result))
    return result


def tool_sqlmap(url: str = "", extra_args: str = "--batch --random-agent",
                timeout: int = 600) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    command = f"sqlmap -u {shlex.quote(target)} {extra_args.strip()}".strip()
    return tool_run_command(command, timeout=timeout)


def tool_whatweb(url: str = "", extra_args: str = "--no-errors --color=never",
                 timeout: int = 180) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    if not same_domain(target, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {target}")
    sanitized = _sanitize_whatweb_args(extra_args)
    command = f"whatweb {sanitized} {shlex.quote(target)}".strip()
    result = tool_run_command(command, timeout=timeout)
    payload = {}
    try:
        payload = json.loads(result.output or "{}")
    except Exception:
        payload = {}
    text = _tool_result_text(result).lower()
    fingerprints = []
    for token in (
        "wordpress", "drupal", "joomla", "magento", "php", "apache",
        "nginx", "iis", "cloudflare", "jquery", "bootstrap", "laravel",
        "django", "rails", "express", "tomcat",
    ):
        if token in text:
            fingerprints.append(token)
    if fingerprints:
        unique = sorted(set(fingerprints))
        payload.update({
            "target": target,
            "fingerprints": unique,
        })
        _append_unique_note(
            f"WhatWeb fingerprint for {target}: {', '.join(unique)}"
        )
        return ToolResult(ok=result.ok, output=json.dumps(payload, indent=2), error=result.error)
    payload.update({
        "target": target,
        "fingerprints": [],
    })
    if result.output:
        try:
            data = json.loads(result.output)
            if isinstance(data, dict):
                payload.setdefault("stdout", data.get("stdout", ""))
                payload.setdefault("stderr", data.get("stderr", ""))
                payload.setdefault("log", data.get("log", ""))
        except Exception:
            pass
    return ToolResult(ok=result.ok, output=json.dumps(payload, indent=2), error=result.error)


def tool_nikto(url: str = "", extra_args: str = "-nointeractive -ask no",
               timeout: int = 240) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    if not same_domain(target, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {target}")
    command = f"nikto -h {shlex.quote(target)} {extra_args.strip()}".strip()
    result = tool_run_command(command, timeout=timeout)
    text = _tool_result_text(result)
    noteworthy: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if stripped.startswith("+") and any(term in lower for term in (
            "cgi", "default", "interesting", "outdated", "admin", "backup",
            "directory", "xss", "upload", "shell", "server-status",
            "phpinfo", "exposed", "vulnerable", "auth",
        )):
            noteworthy.append(stripped)
    for item in noteworthy[:8]:
        sev = "medium" if any(term in item.lower() for term in (
            "cgi", "outdated", "shell", "upload", "phpinfo", "server-status",
            "vulnerable", "exposed",
        )) else "low"
        record_finding("nikto", sev, target, compact_text(item, 240))
    if noteworthy:
        _append_unique_note(
            f"Nikto surfaced {len(noteworthy)} noteworthy items on {target}"
        )
    payload = {
        "target": target,
        "noteworthy_count": len(noteworthy),
        "noteworthy": noteworthy[:12],
    }
    try:
        data = json.loads(result.output or "{}")
        if isinstance(data, dict):
            payload.update({
                "stdout": data.get("stdout", ""),
                "stderr": data.get("stderr", ""),
                "log": data.get("log", ""),
            })
    except Exception:
        pass
    return ToolResult(ok=result.ok, output=json.dumps(payload, indent=2), error=result.error)


def tool_gobuster(url: str = "", extra_args: str = "-q -x php,txt,html,js -t 20",
                  timeout: int = 240) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    if not same_domain(target, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {target}")
    baseline_status = STATE.pages.get(target, {}).get("status_code")
    if not isinstance(baseline_status, int) or baseline_status <= 0:
        try:
            baseline_status = http.get(
                target,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            ).status_code
        except Exception:
            baseline_status = 404
    distro = _preferred_wsl_distro("gobuster")
    if not distro:
        return ToolResult(ok=False, output="", error="No WSL distro available for gobuster")

    sanitized = _sanitize_gobuster_args(extra_args)
    wordlist_cmd = "printf '%s\\n' " + " ".join(shlex.quote(word) for word in _GOBUSTER_WORDS)
    inner_command = (
        "tmp=$(mktemp); "
        f"{wordlist_cmd} > \"$tmp\"; "
        f"gobuster dir -u {shlex.quote(target)} -w \"$tmp\" -b {int(baseline_status)} "
        f"{sanitized}; "
        "rc=$?; rm -f \"$tmp\"; exit $rc"
    )
    command = f"wsl -d {shlex.quote(distro)} bash -lc {shlex.quote(inner_command)}"
    result = tool_run_command(command, timeout=timeout)
    text = _tool_result_text(result)
    discovered: List[Dict[str, Any]] = []
    for line in text.splitlines():
        match = re.search(r"(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)", line)
        if not match:
            continue
        path = match.group("path")
        status = int(match.group("status"))
        discovered.append({"path": path, "status": status})
        lowered = path.lower()
        severity = "medium" if status in {200, 401, 403} or any(
            token in lowered for token in (
                "admin", "login", "signin", "signup", "dashboard", "api",
                "config", "backup", "private", "debug", "test", "upload",
                "internal", "shell",
            )
        ) else "low"
        record_finding(
            "discovery",
            severity,
            urljoin(target if target.endswith("/") else f"{target}/", path.lstrip("/")),
            f"Discovered path via Gobuster: {path} (status {status})",
        )
    if discovered:
        _append_unique_note(
            f"Gobuster discovered {len(discovered)} candidate paths on {target}"
        )
    payload = {
        "url": target,
        "baseline_status": int(baseline_status),
        "discovered_count": len(discovered),
        "discovered": discovered[:20],
    }
    try:
        data = json.loads(result.output or "{}")
        if isinstance(data, dict):
            payload.update({
                "stdout": data.get("stdout", ""),
                "stderr": data.get("stderr", ""),
                "log": data.get("log", ""),
            })
    except Exception:
        pass
    return ToolResult(ok=result.ok, output=json.dumps(payload, indent=2), error=result.error)


def _run_wsl_tool_command(tool_name: str, inner_command: str,
                          timeout: int = 180, user: str = "root") -> ToolResult:
    distro = _preferred_wsl_distro(tool_name)
    if not distro:
        return ToolResult(
            ok=False,
            output="",
            error=f"No WSL distro available for {tool_name}",
        )
    command = (
        f"wsl -d {shlex.quote(distro)} -u {shlex.quote(user)} "
        f"bash -lc {shlex.quote(inner_command)}"
    )
    return tool_run_command(command, timeout=timeout)


def tool_subfinder(domain: str = "", extra_args: str = "-all -silent",
                   timeout: int = 180) -> ToolResult:
    assert STATE is not None
    target = (domain or STATE.domain or "").strip()
    if not target:
        return ToolResult(ok=False, output="", error="Missing domain")
    if "/" in target or not _supports_subdomain_recon(target):
        note = f"subfinder skipped for non-public host target: {target}"
        _append_unique_note(note)
        return ToolResult(ok=True, output=json.dumps({
            "domain": target,
            "discovered_count": 0,
            "discovered": [],
            "skipped": True,
            "reason": note,
        }, indent=2))

    sanitized = extra_args.strip()
    inner_command = f"subfinder -d {shlex.quote(target)} {sanitized}".strip()
    result = _run_wsl_tool_command("subfinder", inner_command, timeout=timeout)
    text = _tool_result_text(result)
    discovered: List[str] = []
    for line in text.splitlines():
        subdomain = line.strip().lower()
        if not subdomain or subdomain.startswith("["):
            continue
        if "." not in subdomain:
            continue
        if subdomain not in discovered:
            discovered.append(subdomain)
            record_finding("discovery", "low", subdomain,
                           f"Subdomain discovered via subfinder: {subdomain}")
            for scheme in ("https", "http"):
                _queue_unique_url(f"{scheme}://{subdomain}")
    if discovered:
        _append_unique_note(
            f"Subfinder discovered {len(discovered)} subdomain(s) for {target}"
        )
        try:
            httpx_result = tool_httpx(targets="\n".join(discovered[:40]), timeout=min(timeout, 240))
            if httpx_result.ok:
                _append_unique_note(
                    f"HTTPX validated live subdomains for {target}"
                )
        except Exception:
            pass
    return ToolResult(ok=result.ok, output=json.dumps({
        "domain": target,
        "discovered_count": len(discovered),
        "discovered": discovered[:100],
    }, indent=2), error=result.error)


def tool_httpx(targets: str = "", url: str = "",
               extra_args: str = "-json -silent -follow-redirects -tech-detect -title -status-code",
               timeout: int = 180) -> ToolResult:
    assert STATE is not None
    target_text = (targets or url or STATE.start_url or "").strip()
    if not target_text:
        return ToolResult(ok=False, output="", error="Missing URL or targets")

    target_list: List[str] = []
    if targets:
        for item in re.split(r"[\r\n,]+", targets):
            item = item.strip()
            if item:
                if "://" in item:
                    target_list.append(normalize_url(item))
                else:
                    target_list.append(normalize_url(f"https://{item}"))
                    target_list.append(normalize_url(f"http://{item}"))
    else:
        target_list.append(normalize_url(target_text))
    target_list = list(dict.fromkeys(target_list))

    temp_list_path: Optional[Path] = None
    try:
        if len(target_list) == 1:
            inner_command = (
                f"httpx -u {shlex.quote(target_list[0])} {extra_args.strip()}".strip()
            )
        else:
            temp_list_path = OUTPUT_DIR / f"httpx_targets_{uuid.uuid4().hex}.txt"
            with open(temp_list_path, "w", encoding="utf-8") as f:
                f.write("\n".join(target_list) + "\n")
            inner_command = (
                f"httpx -l {shlex.quote(_windows_path_to_wsl(temp_list_path))} "
                f"{extra_args.strip()}".strip()
            )
        result = _run_wsl_tool_command("httpx", inner_command, timeout=timeout)
    finally:
        if temp_list_path and temp_list_path.exists():
            try:
                temp_list_path.unlink()
            except Exception:
                pass

    text = _tool_result_text(result)
    live_results: List[Dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            data = json.loads(stripped)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        live_url = normalize_url(str(data.get("url") or data.get("host") or ""))
        if not live_url:
            continue
        entry = {
            "url": live_url,
            "status_code": data.get("status_code", data.get("status")),
            "title": compact_text(str(data.get("title", "")), 160),
            "tech": data.get("tech", data.get("technologies", [])),
        }
        live_results.append(entry)
        if _queue_unique_url(live_url):
            record_finding("discovery", "low", live_url,
                           f"Live endpoint discovered via httpx: {live_url}")
        techs = entry.get("tech")
        if isinstance(techs, list) and techs:
            _append_unique_note(
                f"HTTPX fingerprinted {live_url} with {', '.join(map(str, techs[:4]))}"
            )
        elif entry.get("title"):
            _append_unique_note(
                f"HTTPX confirmed {live_url}: {entry['title']}"
            )
    if not live_results:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("http://", "https://")):
                live_results.append({"url": stripped})
                _queue_unique_url(stripped)
    return ToolResult(ok=result.ok, output=json.dumps({
        "targets": target_list[:50],
        "live_count": len(live_results),
        "live": live_results[:100],
    }, indent=2), error=result.error)


def tool_wafw00f(url: str = "", extra_args: str = "", timeout: int = 180) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    if not same_domain(target, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {target}")
    inner_command = f"wafw00f {extra_args.strip()} {shlex.quote(target)}".strip()
    result = _run_wsl_tool_command("wafw00f", inner_command, timeout=timeout)
    text = _tool_result_text(result)
    waf_lines: List[str] = []
    detected = False
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped:
            continue
        if any(term in lower for term in ("waf detected", "is behind", "firewall")):
            detected = True
            waf_lines.append(stripped)
        elif "no waf" in lower or "not behind" in lower:
            waf_lines.append(stripped)
    if detected:
        record_finding("fingerprint", "low", target,
                       f"WAF detected via wafw00f: {', '.join(waf_lines[:3])}")
        _append_unique_note(f"WAF detected on {target}: {waf_lines[0] if waf_lines else 'wafw00f output'}")
    elif waf_lines:
        _append_unique_note(f"wafw00f checked {target}")
    return ToolResult(ok=result.ok, output=json.dumps({
        "target": target,
        "waf_detected": detected,
        "noteworthy": waf_lines[:20],
    }, indent=2), error=result.error)


def tool_enum4linux(host: str = "", extra_args: str = "-a",
                    timeout: int = 300) -> ToolResult:
    assert STATE is not None
    target = _target_to_host(host or STATE.domain)
    if not target:
        return ToolResult(ok=False, output="", error="Missing host")
    inner_command = f"enum4linux {extra_args.strip()} {shlex.quote(target)}".strip()
    result = _run_wsl_tool_command("enum4linux", inner_command, timeout=timeout)
    text = _tool_result_text(result)
    noteworthy: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped:
            continue
        if any(term in lower for term in ("anonymous login", "disk", "share", "users", "password policy")):
            noteworthy.append(stripped)
    if noteworthy:
        record_finding("discovery", "low", target,
                       f"enum4linux notable output: {compact_text(noteworthy[0], 200)}")
        _append_unique_note(f"enum4linux surfaced {len(noteworthy)} notable line(s) on {target}")
    return ToolResult(ok=result.ok, output=json.dumps({
        "target": target,
        "noteworthy_count": len(noteworthy),
        "noteworthy": noteworthy[:50],
    }, indent=2), error=result.error)


def tool_snmpwalk(host: str = "", extra_args: str = "-v2c -c public",
                  timeout: int = 180) -> ToolResult:
    assert STATE is not None
    target = _target_to_host(host or STATE.domain)
    if not target:
        return ToolResult(ok=False, output="", error="Missing host")
    inner_command = f"snmpwalk {extra_args.strip()} {shlex.quote(target)} 1.3.6.1.2.1.1".strip()
    result = _run_wsl_tool_command("snmpwalk", inner_command, timeout=timeout)
    text = _tool_result_text(result)
    indicators: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped:
            continue
        if any(term in lower for term in ("sysdescr", "sysname", "syslocation", "syscontact")):
            indicators.append(stripped)
    if indicators:
        record_finding("info_disclosure", "low", target,
                       f"SNMP exposed system information: {compact_text(indicators[0], 200)}")
        _append_unique_note(f"snmpwalk exposed system information on {target}")
    return ToolResult(ok=result.ok, output=json.dumps({
        "target": target,
        "indicator_count": len(indicators),
        "indicators": indicators[:20],
    }, indent=2), error=result.error)


def _sanitize_ffuf_args(extra_args: str) -> str:
    tokens = shlex.split(extra_args or "")
    cleaned: List[str] = []
    skip_next = False
    for idx, tok in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if tok in {"-u", "--url", "-w", "--wordlist", "-o", "--output"}:
            skip_next = True
            continue
        if tok in {"-of", "--output-format"}:
            skip_next = True
            continue
        cleaned.append(tok)
    return " ".join(cleaned).strip()


def tool_ffuf(url: str = "", extra_args: str = "-mc all -t 20",
              timeout: int = 240) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    if not same_domain(target, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {target}")

    distro = _preferred_wsl_distro("ffuf")
    if not distro:
        return ToolResult(ok=False, output="", error="No WSL distro available for ffuf")

    base = target.rstrip("/")
    wordlist_path = OUTPUT_DIR / f"ffuf_words_{uuid.uuid4().hex}.txt"
    out_path = OUTPUT_DIR / f"ffuf_{uuid.uuid4().hex}.json"
    with open(wordlist_path, "w", encoding="utf-8") as f:
        f.write("\n".join(_GOBUSTER_WORDS) + "\n")
    sanitized = _sanitize_ffuf_args(extra_args)
    inner_command = (
        f"ffuf -u {shlex.quote(base)}/FUZZ -w {shlex.quote(_windows_path_to_wsl(wordlist_path))} "
        f"-of json -o {shlex.quote(_windows_path_to_wsl(out_path))} {sanitized}"
    ).strip()
    try:
        result = _run_wsl_tool_command("ffuf", inner_command, timeout=timeout)
        discovered: List[Dict[str, Any]] = []
        if out_path.exists():
            try:
                with open(out_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data.get("results", [])[:120]:
                    if not isinstance(item, dict):
                        continue
                    found_url = normalize_url(str(item.get("url") or ""))
                    if not found_url:
                        continue
                    status = int(item.get("status", 0) or 0)
                    discovered.append({
                        "url": found_url,
                        "status": status,
                        "length": item.get("length", 0),
                    })
                    if _queue_unique_url(found_url):
                        severity = "medium" if status in {200, 201, 202, 301, 302, 307, 401, 403} else "low"
                        record_finding("discovery", severity, found_url,
                                       f"ffuf discovered {found_url} (status {status})")
            except Exception:
                pass
        if discovered:
            _append_unique_note(f"ffuf discovered {len(discovered)} path(s) on {target}")
        return ToolResult(ok=result.ok, output=json.dumps({
            "target": target,
            "discovered_count": len(discovered),
            "discovered": discovered[:100],
        }, indent=2), error=result.error)
    finally:
        for path in (wordlist_path, out_path):
            try:
                if path.exists():
                    path.unlink()
            except Exception:
                pass


def tool_parameter_tamper(url: str = "", sample_limit: int = 6) -> ToolResult:
    assert STATE is not None
    target = normalize_url(url or STATE.start_url)
    if not same_domain(target, STATE.domain):
        return ToolResult(ok=False, output="", error=f"Out of scope: {target}")

    parsed = urlparse(target)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if not query:
        return ToolResult(ok=True, output=json.dumps({
            "url": target,
            "baseline": {},
            "tested": [],
            "suspicions": [],
            "note": "No query parameters present",
        }, indent=2))

    try:
        baseline_resp = http.get(
            target,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
    except Exception as e:
        return ToolResult(ok=False, output="", error=f"Baseline request failed: {e}")

    baseline = _response_signature(baseline_resp)
    tested: List[Dict[str, Any]] = []
    suspicions: List[Dict[str, Any]] = []

    for name, values in list(query.items())[:8]:
        original = values[0] if values else ""
        if not _is_object_reference_param(name, original) and not any(v.isdigit() for v in values):
            continue

        param_result = {
            "parameter": name,
            "original": original,
            "candidates": [],
        }
        candidates = _parameter_value_candidates(name, original, sample_limit)
        for candidate in candidates:
            mutated = {k: list(v) for k, v in query.items()}
            mutated[name] = [candidate]
            mutated_url = parsed._replace(query=urlencode(mutated, doseq=True)).geturl()
            try:
                resp = http.get(
                    mutated_url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                )
                sig = _response_signature(resp)
                delta = _signature_delta(baseline, sig)
                param_result["candidates"].append({
                    "value": candidate,
                    "status": sig["status"],
                    "length": sig["length"],
                    "delta": delta,
                })
                if delta >= 3:
                    evidence = (
                        f"Parameter {name} changed from {original!r} to {candidate!r}: "
                        f"status {baseline['status']} -> {sig['status']}, "
                        f"length {baseline['length']} -> {sig['length']}"
                    )
                    suspicions.append({
                        "parameter": name,
                        "value": candidate,
                        "evidence": evidence,
                    })
                    record_finding("idor", "medium", target, evidence)
                    break
            except Exception as e:
                param_result["candidates"].append({
                    "value": candidate,
                    "error": str(e),
                })
        tested.append(param_result)

    if suspicions:
        _append_unique_note(
            f"Parameter tamper probe on {target}: {', '.join(item['parameter'] for item in suspicions[:4])}"
        )

    return ToolResult(ok=True, output=json.dumps({
        "url": target,
        "baseline": baseline,
        "tested": tested,
        "suspicions": suspicions,
    }, indent=2))


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
    host, port = _state_ssl_target()
    return _wrap_security(check_ssl(host, port), "ssl", _state_origin_url())


def tool_security_cookies(url: str = "") -> ToolResult:
    assert STATE is not None
    url = url or STATE.start_url
    return _wrap_security(check_cookies(url, http), "cookies", url)


def tool_security_sensitive_paths() -> ToolResult:
    assert STATE is not None
    return _wrap_security(
        check_sensitive_paths(STATE.domain, http, base_url=_state_origin_url()),
        "exposure",
        _state_origin_url(),
    )


def tool_security_cors(url: str = "") -> ToolResult:
    assert STATE is not None
    url = url or STATE.start_url
    return _wrap_security(
        check_cors(url, STATE.domain, http, origin_base=_state_origin_url()),
        "cors",
        url,
    )


def tool_security_mixed_content() -> ToolResult:
    assert STATE is not None
    return _wrap_security(check_mixed_content(STATE.pages),
                          "mixed_content", f"https://{STATE.domain}")


def tool_security_email() -> ToolResult:
    assert STATE is not None
    host, _ = _state_ssl_target()
    return _wrap_security(check_email_security(host),
                          "email_security", host)


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


def tool_attack_surface_review(page_url: str = "") -> ToolResult:
    assert STATE is not None
    url = normalize_url(page_url or STATE.start_url or _state_origin_url())
    page = STATE.pages.get(url)
    if page is None and same_domain(url, STATE.domain):
        try:
            fetch_result = tool_fetch_page(url)
            if not fetch_result.ok:
                return ToolResult(
                    ok=False,
                    output="",
                    error=f"attack_surface_review fetch failed: {fetch_result.error}",
                )
            page = STATE.pages.get(normalize_url(url))
        except Exception as e:
            return ToolResult(ok=False, output="", error=f"attack_surface_review failed: {e}")

    page = page or {}
    clues = _attack_surface_clues(
        page.get("url", url),
        page.get("title", ""),
        page.get("h1", ""),
        "",
        page.get("forms", []),
    )
    query_params = page.get("query_params", [])
    recommendations: List[str] = []
    if any("idor" in clue.lower() for clue in clues):
        recommendations.append(
            "Test adjacent object IDs and verify authorization on each object reference."
        )
    if any("csrf" in clue.lower() for clue in clues):
        recommendations.append(
            "Verify state-changing requests require a valid CSRF token or SameSite protections."
        )
    if page.get("form_count"):
        recommendations.append(
            "Map form actions and replay requests through Burp/Playwright to identify hidden server-side controls."
        )
    if query_params:
        recommendations.append(
            "Fuzz query parameters individually and compare response body, redirects, and authorization behavior."
        )
    if not recommendations:
        recommendations.append(
            "Continue web enumeration: content discovery, parameter discovery, and authenticated flows if present."
        )

    tamper_data: Dict[str, Any] = {}
    if (
        page.get("status_code", 0) < 500
        and (query_params or any(form.get("method", "").upper() == "POST" for form in page.get("forms", [])))
    ):
        try:
            tamper_result = tool_parameter_tamper(page.get("url", url))
            if tamper_result.ok:
                tamper_data = json.loads(tamper_result.output or "{}")
                if tamper_data.get("suspicions"):
                    recommendations.append(
                        "Parameter tamper probe returned differential responses; validate the highlighted parameters manually."
                    )
        except Exception as e:
            tamper_data = {"error": str(e)}

    payload = {
        "url": page.get("url", url),
        "status_code": page.get("status_code"),
        "title": page.get("title", ""),
        "h1": page.get("h1", ""),
        "query_params": query_params,
        "form_count": page.get("form_count", 0),
        "forms": [
            {
                "action": form.get("action", ""),
                "method": form.get("method", ""),
                "csrf_token_present": form.get("csrf_token_present", False),
                "fields": [
                    inp.get("name", "")
                    for inp in form.get("inputs", [])[:10]
                    if inp.get("name")
                ],
            }
            for form in page.get("forms", [])[:8]
        ],
        "clues": clues,
        "recommendations": recommendations,
    }
    if tamper_data:
        payload["parameter_tamper"] = tamper_data
    if clues:
        _append_unique_note(
            f"Attack-surface review on {payload['url']}: {', '.join(clues[:4])}"
        )
    return ToolResult(ok=True, output=json.dumps(payload, indent=2))


def _security_target_url(target: str = "") -> str:
    assert STATE is not None
    raw = (target or "").strip()
    if not raw:
        raw = STATE.start_url or _state_origin_url()
    if "://" not in raw:
        raw = f"https://{raw}"
    return normalize_url(raw)


def _probe_wildcard_dns(target: str) -> Dict[str, Any]:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or target).split(":", 1)[0].strip()
    probes = []
    for _ in range(3):
        subdomain = f"{uuid.uuid4().hex[:12]}.{host}"
        try:
            infos = socket.getaddrinfo(subdomain, 443, type=socket.SOCK_STREAM)
            ips = sorted({
                item[4][0] for item in infos
                if item and item[4] and item[4][0]
            })
            probes.append({
                "subdomain": subdomain,
                "resolved": bool(ips),
                "ips": ips[:8],
            })
        except Exception as e:
            probes.append({
                "subdomain": subdomain,
                "resolved": False,
                "error": str(e)[:120],
            })

    wildcard_suspected = sum(1 for p in probes if p.get("resolved")) >= 2
    if wildcard_suspected:
        record_finding("dns", "medium", target,
                       f"Wildcard DNS suspected for {host}")
    return {
        "target": target,
        "host": host,
        "wildcard_suspected": wildcard_suspected,
        "probes": probes,
    }


def _probe_internal_ip_leaks(target: str) -> Dict[str, Any]:
    url = _security_target_url(target)
    resp = http.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    body = resp.text or ""
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    pattern = re.compile(
        r"\b("
        r"10(?:\.\d{1,3}){3}|"
        r"127(?:\.\d{1,3}){3}|"
        r"169\.254(?:\.\d{1,3}){2}|"
        r"192\.168(?:\.\d{1,3}){2}|"
        r"172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}"
        r")\b"
    )
    matches = sorted(set(pattern.findall(body + "\n" + header_blob)))
    if matches:
        record_finding("info_disclosure", "medium", resp.url,
                       f"Potential internal IP leak(s): {', '.join(matches[:6])}")
    return {
        "url": normalize_url(resp.url),
        "status_code": resp.status_code,
        "matches": matches,
    }


def tool_security_check(target: str = "", checks: Any = None) -> ToolResult:
    assert STATE is not None
    target_url = _security_target_url(target)
    check_list: List[str] = []
    if isinstance(checks, list):
        check_list = [str(item).strip() for item in checks if str(item).strip()]
    elif isinstance(checks, str):
        check_list = [part.strip() for part in re.split(r"[,\s]+", checks) if part.strip()]
    elif checks is not None:
        check_list = [str(checks).strip()] if str(checks).strip() else []

    if not check_list:
        check_list = [
            "headers",
            "info-disclosure",
            "wildcard-dns-detect",
        ]

    results: List[Dict[str, Any]] = []
    for raw_check in check_list:
        check = _canonical_tool_name(raw_check)
        label = raw_check.strip()
        result_payload: Dict[str, Any] = {"check": label}
        try:
            if check in {"wildcard_dns_detect", "wildcard_dns", "dns_wildcard"}:
                payload = _probe_wildcard_dns(target_url)
                result_payload.update({"ok": True, "data": payload})
            elif check in {"misconfigured_server", "server_misconfiguration"}:
                headers = tool_check_headers(target_url)
                headers_payload = json.loads(headers.output) if headers.output else {}
                deep = tool_security_headers_deep(target_url)
                deep_payload = json.loads(deep.output) if deep.output else {}
                info = tool_security_info_disclosure(target_url)
                info_payload = json.loads(info.output) if info.output else {}
                result_payload.update({
                    "ok": headers.ok and deep.ok and info.ok,
                    "data": {
                        "headers": headers_payload,
                        "deep_headers": deep_payload,
                        "info_disclosure": info_payload,
                    },
                })
            elif check in {"exposed_internal_ip", "internal_ip_leak", "internal_ip"}:
                payload = _probe_internal_ip_leaks(target_url)
                result_payload.update({"ok": True, "data": payload})
            elif check in {"headers", "security_headers"}:
                tool_result = tool_check_headers(target_url)
                result_payload.update({
                    "ok": tool_result.ok,
                    "data": json.loads(tool_result.output) if tool_result.output else {},
                })
            elif check in {"info_disclosure", "information_disclosure"}:
                tool_result = tool_security_info_disclosure(target_url)
                result_payload.update({
                    "ok": tool_result.ok,
                    "data": json.loads(tool_result.output) if tool_result.output else {},
                })
            elif check in {"ssl", "tls"}:
                parsed = urlparse(target_url)
                host = parsed.hostname or STATE.domain
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                tool_result = _wrap_security(check_ssl(host, port), "ssl", target_url)
                result_payload.update({
                    "ok": tool_result.ok,
                    "data": json.loads(tool_result.output) if tool_result.output else {},
                })
            elif check in {"cookies", "cookie"}:
                tool_result = tool_security_cookies(target_url)
                result_payload.update({
                    "ok": tool_result.ok,
                    "data": json.loads(tool_result.output) if tool_result.output else {},
                })
            elif check in {"cors"}:
                tool_result = tool_security_cors(target_url)
                result_payload.update({
                    "ok": tool_result.ok,
                    "data": json.loads(tool_result.output) if tool_result.output else {},
                })
            elif check in {"mixed_content", "mixedcontent"}:
                tool_result = tool_security_mixed_content()
                result_payload.update({
                    "ok": tool_result.ok,
                    "data": json.loads(tool_result.output) if tool_result.output else {},
                })
            elif check in {"email", "spf_dmarc", "email_security"}:
                parsed = urlparse(target_url)
                host = parsed.hostname or STATE.domain
                tool_result = _wrap_security(check_email_security(host),
                                             "email_security", host)
                result_payload.update({
                    "ok": tool_result.ok,
                    "data": json.loads(tool_result.output) if tool_result.output else {},
                })
            else:
                fallback = tool_check_headers(target_url)
                result_payload.update({
                    "ok": fallback.ok,
                    "data": {
                        "fallback": "headers",
                        "result": json.loads(fallback.output) if fallback.output else {},
                    },
                })
        except Exception as e:
            result_payload.update({"ok": False, "error": str(e)})
        results.append(result_payload)

    overall_ok = any(item.get("ok") for item in results)
    return ToolResult(
        ok=overall_ok,
        output=json.dumps({
            "target": target_url,
            "requested_checks": check_list,
            "results": results,
        }, indent=2),
    )


# ═══════════════════════════════════════════════════════════
#  REPORT GENERATION TOOLS
# ═══════════════════════════════════════════════════════════
def tool_write_json_report(path: str = "") -> ToolResult:
    assert STATE is not None
    p = path or str(JSON_REPORT)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(STATE.to_dict(), f, indent=2)
    return ToolResult(ok=True, output=json.dumps({"written": p}))


def _severity_rank(severity: str) -> int:
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }.get((severity or "").lower(), 5)


def _group_findings_for_report(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for finding in findings:
        kind = _normalized_finding_kind(str(finding.get("kind", "")))
        key = (
            kind,
            str(finding.get("severity", "")),
            str(finding.get("url", "")),
            str(finding.get("detail", "")),
        )
        item = grouped.setdefault(key, {
            "kind": key[0],
            "severity": key[1],
            "url": key[2],
            "detail": key[3],
            "count": 0,
            "evidence_count": 0,
            "validated": False,
            "confidence": 0.0,
        })
        item["count"] += 1
        item["evidence_count"] += int(finding.get("evidence_count", 1) or 1)
        item["validated"] = item["validated"] or bool(finding.get("validated"))
        item["confidence"] = max(item["confidence"], float(finding.get("confidence", 0.0) or 0.0))
    items = list(grouped.values())
    items.sort(
        key=lambda f: (
            _severity_rank(f["severity"]),
            -float(f.get("confidence", 0.0) or 0.0),
            f["kind"],
            f["url"],
            f["detail"],
        )
    )
    return items


def _remediation_for_finding(kind: str, detail: str) -> str:
    kind_l = _normalized_finding_kind(kind)
    detail_l = (detail or "").lower()
    if kind_l == "security_headers":
        if "hsts" in detail_l:
            return "Set Strict-Transport-Security with a long max-age and includeSubDomains where appropriate."
        if "csp" in detail_l:
            return "Add a restrictive Content-Security-Policy and tighten it iteratively."
        if "x-content-type-options" in detail_l:
            return "Set X-Content-Type-Options: nosniff."
        if "x-frame-options" in detail_l:
            return "Set X-Frame-Options: DENY or use CSP frame-ancestors."
        if "referrer-policy" in detail_l:
            return "Set a Referrer-Policy such as strict-origin-when-cross-origin."
        if "permissions-policy" in detail_l:
            return "Set a Permissions-Policy that disables unused browser features."
        return "Harden the response headers for browser-side security."
    if kind_l == "http":
        return "Investigate the backend or reverse proxy causing the timeout/error; verify availability, origin health, and upstream latency."
    if kind_l == "crawl":
        return "Fix the route so robots.txt and sitemap.xml return predictable responses instead of timing out."
    if kind_l == "email_security":
        return "Publish SPF and DMARC records, then monitor DMARC reports and align mail senders."
    if kind_l == "discovery":
        return "Review the discovered endpoint manually, verify access control, and test authentication and input handling."
    if kind_l == "nikto":
        return "Validate the exposed resource or misconfiguration Nikto surfaced, then remove, patch, or restrict it."
    if kind_l == "fingerprint":
        return "Use the fingerprinted stack to drive targeted version-specific checks and hardening."
    if kind_l == "idor":
        return "Enforce server-side authorization on every object reference and never trust client-supplied IDs or account identifiers."
    if kind_l == "csrf":
        return "Protect state-changing requests with CSRF tokens, SameSite cookies, and origin/referrer checks."
    if kind_l == "info_disclosure":
        return "Remove stack traces, internal paths, debug headers, and other sensitive details from responses."
    if kind_l == "links":
        return "Repair or remove broken links and verify that all critical routes resolve correctly."
    if kind_l == "lighthouse":
        return "Address the specific Lighthouse category that scored poorly and re-test after changes."
    if kind_l == "seo":
        return "Add missing metadata only if the page is meant to be indexed; this is usually not a security issue."
    if kind_l == "attack_surface":
        return "Use the surfaced parameters, forms, and URLs to run targeted tampering and authorization checks."
    return "Verify the issue manually and apply the least-privilege fix at the application or infrastructure layer."


def _build_report_context() -> Dict[str, Any]:
    assert STATE is not None
    findings = _group_findings_for_report(STATE.findings)
    sev_counts = Counter(f["severity"] for f in findings)
    kind_counts = Counter(f["kind"] for f in findings)
    ranked_kinds = [kind for kind, _ in kind_counts.most_common(12)]
    exploit_kinds = [kind for kind in ranked_kinds if kind in _EXPLOIT_FINDING_KINDS]
    baseline_kinds = [
        kind for kind in ranked_kinds
        if kind not in _EXPLOIT_FINDING_KINDS and kind not in {"seo", "email_security"}
    ]
    top_kinds = (exploit_kinds[:4] + baseline_kinds[:4]) or ranked_kinds[:6]
    exploit_findings = [f for f in findings if f["kind"] in _EXPLOIT_FINDING_KINDS]
    high_findings = [f for f in findings if _severity_rank(f["severity"]) <= 1]
    notes = [n for n in STATE.notes if n.strip()]
    attack_notes = [
        n for n in notes
        if any(word in n.lower() for word in (
            "attack surface", "pivot", "parameter", "idor", "csrf",
            "nmap", "nuclei", "whatweb", "nikto", "gobuster",
            "fingerprint", "discovery",
        ))
    ]
    pages = sorted(
        STATE.pages.values(),
        key=lambda p: str(p.get("url", "")),
    )
    recent_events = STATE.recent_events[-20:]
    graph_summary = _attack_graph_summary(STATE)
    tool_health = _tool_health_summary(STATE, limit=12)
    return {
        "findings": findings,
        "sev_counts": sev_counts,
        "kind_counts": kind_counts,
        "ranked_kinds": ranked_kinds,
        "exploit_kinds": exploit_kinds,
        "baseline_kinds": baseline_kinds,
        "top_kinds": top_kinds,
        "exploit_findings": exploit_findings,
        "high_findings": high_findings,
        "notes": notes,
        "attack_notes": attack_notes,
        "pages": pages,
        "recent_events": recent_events,
        "graph_summary": graph_summary,
        "tool_health": tool_health,
        "target_profile": getattr(STATE, "target_profile", "") or _target_profile_from_state(),
        "llm_provider": getattr(STATE, "llm_provider", DEFAULT_PROVIDER),
        "llm_base_url": getattr(STATE, "llm_base_url", ""),
        "llm_api_key_env": getattr(STATE, "llm_api_key_env", DEFAULT_API_KEY_ENV),
        "skill_counts": SKILL_COUNTS,
        "skill_total": len(SKILL_CATALOG),
    }


def tool_write_report() -> ToolResult:
    assert STATE is not None
    json_result = tool_write_json_report()
    md_result = tool_write_markdown_summary()
    html_result = tool_write_html_report()
    return ToolResult(ok=json_result.ok and md_result.ok and html_result.ok,
                      output=json.dumps({
                          "json_report": json.loads(json_result.output)
                          if json_result.output else {},
                          "markdown_report": json.loads(md_result.output)
                          if md_result.output else {},
                          "html_report": json.loads(html_result.output)
                          if html_result.output else {},
                      }, indent=2),
                      error="; ".join(
                          part for part in [
                              json_result.error,
                              md_result.error,
                              html_result.error,
                          ]
                          if part
                      ))


def tool_write_markdown_summary(path: str = "") -> ToolResult:
    assert STATE is not None
    p = path or str(MD_REPORT)
    ctx = _build_report_context()
    findings = ctx["findings"]
    sev_counts = ctx["sev_counts"]
    top_kinds = ctx["top_kinds"]
    exploit_findings = ctx["exploit_findings"]
    high_findings = ctx["high_findings"]
    attack_notes = ctx["attack_notes"]
    notes = ctx["notes"]
    graph_summary = ctx["graph_summary"]
    tool_health = ctx["tool_health"]
    target_profile = ctx["target_profile"]
    llm_provider = ctx["llm_provider"]
    skill_total = ctx["skill_total"]
    skill_counts = ctx["skill_counts"]

    lines: List[str] = []
    lines.append(f"# Website Audit Summary for `{STATE.domain}`")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- Target profile: {target_profile}.")
    lines.append(f"- LLM provider: {llm_provider}.")
    lines.append(f"- Built-in skills: {skill_total} across {len(skill_counts)} categories.")
    lines.append(f"- Autonomy mode: {getattr(STATE, 'autonomy_mode', 'free')}.")
    if getattr(STATE, "operator_task", "").strip():
        lines.append("- Operator mission:")
        for item in _operator_task_items():
            lines.append(f"  - {item}")
    if findings:
        lines.append(
            f"- {len(findings)} unique findings captured across {len(STATE.pages)} pages."
        )
        lines.append(
            f"- Severity mix: {sev_counts.get('critical', 0)} critical, {sev_counts.get('high', 0)} high, {sev_counts.get('medium', 0)} medium, {sev_counts.get('low', 0)} low."
        )
        lines.append(
            f"- Attack graph: {graph_summary['nodes']} nodes, {graph_summary['edges']} edges, {graph_summary['validated_findings']} validated findings."
        )
        lines.append(f"- Exploit-style leads: {len(exploit_findings)}.")
        if top_kinds:
            lines.append(
                f"- Primary categories: {', '.join(top_kinds)}."
            )
        if high_findings:
            lines.append(
                f"- Highest-priority items: {len(high_findings)} confirmed high/critical findings."
            )
    else:
        lines.append("- No findings were recorded in this run.")

    if tool_health:
        lines.append("- Tool health: " + "; ".join(
            f"{item['tool']} ({item['failure']} failures, {item['timeouts']} timeouts)"
            for item in tool_health[:5]
        ))

    if attack_notes:
        lines.append("")
        lines.append("## Active Attack-Surface Notes")
        for note in attack_notes[-8:]:
            lines.append(f"- {note}")

    if STATE.mode == "network" and getattr(STATE, "network_hosts", []):
        lines.append("")
        lines.append("## Network Inventory")
        for rec in STATE.network_hosts[:24]:
            ports = [
                f"{p.get('port')}/{p.get('proto')}/{p.get('service') or 'unknown'}"
                for p in rec.get("ports", [])
                if isinstance(p, dict) and str(p.get("state", "")).lower() in {"open", "open|filtered"}
            ][:8]
            line = rec.get("host", "")
            if rec.get("hostname"):
                line += f" ({rec.get('hostname')})"
            if ports:
                line += f" — {', '.join(ports)}"
            lines.append(f"- {line}")

    lines.append("")
    lines.append("## Confirmed Findings")
    if findings:
        for finding in findings[:80]:
            sev = finding["severity"].upper()
            count = finding["count"]
            kind = finding["kind"]
            url = finding["url"]
            detail = finding["detail"]
            fix = _remediation_for_finding(kind, detail)
            lines.append("")
            lines.append(f"### [{sev}] {kind}")
            lines.append(f"- URL: `{url}`")
            if count > 1:
                lines.append(f"- Repeated: {count} times")
            lines.append(f"- Evidence: {detail}")
            lines.append(f"- Fix: {fix}")
    else:
        lines.append("- No confirmed findings to report.")

    if STATE.memory_summary:
        lines.append("")
        lines.append("## Durable Notes")
        lines.append(STATE.memory_summary.strip())

    lines.append("")
    lines.append("## Next Tests")
    if attack_notes:
        for note in attack_notes[-5:]:
            lines.append(f"- {note}")
    else:
        lines.append("- Continue targeted web enumeration and parameter testing on any discovered forms or object references.")

    md = "\n".join(lines).rstrip() + "\n"
    with open(p, "w", encoding="utf-8") as f:
        f.write(md)
    return ToolResult(ok=True, output=json.dumps({
        "written": p,
        "unique_findings": len(findings),
        "high_findings": len(high_findings),
    }, indent=2))


def tool_write_html_report(path: str = "") -> ToolResult:
    assert STATE is not None
    p = path or str(HTML_REPORT)
    ctx = _build_report_context()
    findings = ctx["findings"]
    sev_counts = ctx["sev_counts"]
    kind_counts = ctx["kind_counts"]
    top_kinds = ctx["top_kinds"]
    exploit_findings = ctx["exploit_findings"]
    high_findings = ctx["high_findings"]
    notes = ctx["notes"]
    attack_notes = ctx["attack_notes"]
    pages = ctx["pages"]
    recent_events = ctx["recent_events"]
    graph_summary = ctx["graph_summary"]
    tool_health = ctx["tool_health"]
    target_profile = ctx["target_profile"]
    llm_provider = ctx["llm_provider"]
    skill_total = ctx["skill_total"]
    skill_counts = ctx["skill_counts"]

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    severity_labels = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    def badge(severity: str) -> str:
        sev = (severity or "info").lower()
        return f'<span class="badge sev-{html_escape(sev)}">{html_escape(severity_labels.get(sev, sev.title()))}</span>'

    def pre_json(value: Any) -> str:
        return f'<pre class="json">{html_escape(json.dumps(value, indent=2, ensure_ascii=False))}</pre>'

    def fmt_value(value: Any) -> str:
        if value is None or value == "":
            return '<span class="muted">-</span>'
        if isinstance(value, list):
            if not value:
                return '<span class="muted">[]</span>'
            return "<ul class=\"list\">" + "".join(
                f"<li>{html_escape(str(item))}</li>" for item in value
            ) + "</ul>"
        if isinstance(value, dict):
            return pre_json(value)
        return html_escape(str(value))

    summary_cards = [
        ("Pages", str(len(STATE.pages))),
        ("Findings", str(len(findings))),
        ("Validated", str(graph_summary["validated_findings"])),
        ("Critical", str(sev_counts.get("critical", 0))),
        ("High", str(sev_counts.get("high", 0))),
        ("Medium", str(sev_counts.get("medium", 0))),
        ("Low", str(sev_counts.get("low", 0))),
        ("Info", str(sev_counts.get("info", 0))),
        ("Notes", str(len(notes))),
        ("Provider", str(llm_provider)),
        ("Skills", str(skill_total)),
        ("Categories", str(len(skill_counts))),
        ("Graph Nodes", str(graph_summary["nodes"])),
        ("Graph Edges", str(graph_summary["edges"])),
    ]
    if STATE.mode == "network":
        summary_cards.extend([
            ("Subnets", str(len(getattr(STATE, "network_subnets", [])))),
            ("Hosts", str(len(getattr(STATE, "network_hosts", [])))),
            ("Queue", str(len(STATE.queued_urls))),
        ])
    if tool_health:
        summary_cards.append(("Weakest Tool", tool_health[0]["tool"]))

    finding_cards: List[str] = []
    for finding in findings:
        sev = finding["severity"].lower()
        kind = finding["kind"]
        url = finding["url"]
        detail = finding["detail"]
        count = finding["count"]
        fix = _remediation_for_finding(kind, detail)
        finding_cards.append(
            f"""
            <article class="finding-card sev-{html_escape(sev)}">
              <div class="finding-head">
                {badge(sev)}
                <span class="kind">{html_escape(kind)}</span>
                <span class="muted">{html_escape(str(count))}x</span>
              </div>
              <div class="finding-title">{html_escape(detail)}</div>
              <div class="finding-meta"><span class="label">URL</span> {html_escape(url)}</div>
              <div class="finding-meta"><span class="label">Confidence</span> {html_escape(f"{float(finding.get('confidence', 0.0) or 0.0):.0%}")}</div>
              <div class="finding-meta"><span class="label">Validated</span> {html_escape("yes" if finding.get("validated") else "no")}</div>
              <div class="finding-meta"><span class="label">Evidence Count</span> {html_escape(str(finding.get('evidence_count', count)))}</div>
              <div class="finding-meta"><span class="label">Fix</span> {html_escape(fix)}</div>
            </article>
            """
        )

    page_cards: List[str] = []
    for page in pages:
        issue_list = page.get("issues") or []
        issues_html = "".join(f"<li>{html_escape(str(issue))}</li>" for issue in issue_list)
        if not issues_html:
            issues_html = '<li class="muted">No page issues recorded.</li>'
        asset_counts = page.get("asset_counts") or {}
        page_cards.append(
            f"""
            <article class="page-card">
              <h3>{html_escape(page.get("title") or page.get("url") or "Untitled page")}</h3>
              <div class="page-url">{html_escape(page.get("url") or "")}</div>
              <div class="page-grid">
                <div><span class="label">Requested</span><div>{fmt_value(page.get("requested_url"))}</div></div>
                <div><span class="label">Status</span><div>{fmt_value(page.get("status_code"))}</div></div>
                <div><span class="label">Content Type</span><div>{fmt_value(page.get("content_type"))}</div></div>
                <div><span class="label">Canonical</span><div>{fmt_value(page.get("canonical"))}</div></div>
                <div><span class="label">H1</span><div>{fmt_value(page.get("h1"))}</div></div>
                <div><span class="label">Meta Description</span><div>{fmt_value(page.get("meta_description"))}</div></div>
                <div><span class="label">Internal Links</span><div>{fmt_value(len(page.get("internal_links") or []))}</div></div>
                <div><span class="label">External Links</span><div>{fmt_value(len(page.get("external_links") or []))}</div></div>
                <div><span class="label">Forms</span><div>{fmt_value(page.get("form_count"))}</div></div>
                <div><span class="label">Query Params</span><div>{fmt_value(len(page.get("query_params") or []))}</div></div>
                <div><span class="label">Assets</span><div>{fmt_value(asset_counts)}</div></div>
              </div>
              <div class="section-label">Issues</div>
              <ul class="list">{issues_html}</ul>
              <details>
                <summary>Raw page data</summary>
                {pre_json(page)}
                </details>
            </article>
            """
        )

    network_cards: List[str] = []
    if STATE.mode == "network":
        for rec in getattr(STATE, "network_hosts", [])[:24]:
            open_ports = [
                f"{p.get('port')}/{p.get('proto')}/{p.get('service') or 'unknown'}"
                for p in rec.get("ports", [])
                if isinstance(p, dict) and str(p.get("state", "")).lower() in {"open", "open|filtered"}
            ][:12]
            web_urls = rec.get("web_urls", [])[:8]
            sources = rec.get("sources", [])[:4]
            network_cards.append(
                f"""
                <article class="page-card">
                  <h3>{html_escape(rec.get("host") or "Unknown host")}</h3>
                  <div class="page-url">{html_escape(rec.get("hostname") or "")}</div>
                  <div class="page-grid">
                    <div><span class="label">Status</span><div>{fmt_value(rec.get("status"))}</div></div>
                    <div><span class="label">Open Ports</span><div>{fmt_value(open_ports)}</div></div>
                    <div><span class="label">Web URLs</span><div>{fmt_value(web_urls)}</div></div>
                    <div><span class="label">Sources</span><div>{fmt_value(sources)}</div></div>
                  </div>
                  <details>
                    <summary>Raw host data</summary>
                    {pre_json(rec)}
                  </details>
                </article>
                """
            )

    event_cards: List[str] = []
    for event in recent_events:
        event_cards.append(
            f"""
            <details class="event-card">
              <summary>
                <span class="muted">Step {html_escape(str(event.get("step", "")))} •</span>
                <span>{html_escape(str(event.get("type", "event")))} •</span>
                <span>{html_escape(str(event.get("tool", event.get("action", "entry"))))}</span>
              </summary>
              {pre_json(event)}
            </details>
            """
        )

    raw_state = pre_json(STATE.to_dict())
    if STATE.mode == "network":
        network_inventory_html = (
            '<section class="section"><h2>Network Inventory</h2><div class="columns">'
            + ("".join(network_cards) if network_cards else '<div class="muted">No network hosts were captured.</div>')
            + "</div></section>"
        )
    else:
        network_inventory_html = ""
    tool_health_html = ""
    if tool_health:
        tool_rows = "".join(
            f"<li><strong>{html_escape(item['tool'])}</strong>: "
            f"{html_escape(str(item['calls']))} calls, "
            f"{html_escape(str(item['success']))} success, "
            f"{html_escape(str(item['failure']))} failures, "
            f"{html_escape(str(item['timeouts']))} timeouts</li>"
            for item in tool_health
        )
        tool_health_html = (
            '<section class="section"><h2>Tool Health</h2><ul class="list">'
            + tool_rows
            + "</ul></section>"
        )
    if getattr(STATE, "operator_task", "").strip():
        operator_task_html = (
            '<section class="section"><h2>Operator Mission</h2><pre class="json">'
            f"{html_escape(STATE.operator_task.strip())}</pre></section>"
        )
    else:
        operator_task_html = ""
    high_summary = f"{len(high_findings)} confirmed high/critical findings"
    exploit_summary = f"{len(exploit_findings)} exploit-style leads"
    top_kind_text = ", ".join(top_kinds) if top_kinds else "n/a"
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PentAgent Report - {html_escape(STATE.domain)}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b1020;
      --bg2: #121a31;
      --card: rgba(15, 23, 42, 0.92);
      --card-border: rgba(148, 163, 184, 0.18);
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent2: #818cf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #22c55e;
      --info: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, Segoe UI, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(56, 189, 248, 0.16), transparent 26%),
        radial-gradient(circle at top right, rgba(129, 140, 248, 0.12), transparent 22%),
        linear-gradient(180deg, var(--bg), var(--bg2));
      color: var(--text);
    }}
    a {{ color: #93c5fd; text-decoration: none; }}
    .wrap {{ max-width: 1360px; margin: 0 auto; padding: 24px; }}
    .hero {{
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 24px;
      box-shadow: 0 18px 50px rgba(0, 0, 0, 0.35);
    }}
    .eyebrow {{
      text-transform: uppercase;
      letter-spacing: 0.18em;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 10px;
    }}
    h1, h2, h3 {{ margin: 0; }}
    h1 {{ font-size: clamp(30px, 4vw, 48px); line-height: 1.05; }}
    .subhead {{
      margin-top: 12px;
      color: var(--muted);
      max-width: 980px;
      line-height: 1.6;
    }}
    .summary-grid, .page-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
    }}
    .summary-card, .finding-card, .page-card, .event-card, .raw-card {{
      background: rgba(2, 6, 23, 0.5);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      padding: 16px;
    }}
    .summary-card .label, .label, .section-label {{
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 11px;
    }}
    .summary-card .value {{
      font-size: 28px;
      font-weight: 700;
      margin-top: 6px;
    }}
    .section {{
      margin-top: 24px;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 20px;
    }}
    .section > h2 {{
      margin-bottom: 14px;
      font-size: 22px;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      margin-right: 8px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .sev-critical {{ color: #fff; background: var(--critical); }}
    .sev-high {{ color: #fff; background: var(--high); }}
    .sev-medium {{ color: #111827; background: var(--medium); }}
    .sev-low {{ color: #06121f; background: var(--low); }}
    .sev-info {{ color: #08111d; background: var(--info); }}
    .finding-list {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 12px;
    }}
    .finding-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .kind {{
      color: #cbd5e1;
      font-weight: 700;
      text-transform: lowercase;
    }}
    .finding-title {{
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 10px;
      line-height: 1.4;
    }}
    .finding-meta {{
      color: var(--muted);
      margin-top: 8px;
      line-height: 1.5;
      overflow-wrap: anywhere;
    }}
    .page-card h3 {{
      margin-bottom: 6px;
      font-size: 18px;
    }}
    .page-url {{
      color: #93c5fd;
      font-size: 13px;
      margin-bottom: 12px;
      overflow-wrap: anywhere;
    }}
    .page-grid > div {{
      background: rgba(15, 23, 42, 0.4);
      border-radius: 14px;
      padding: 12px;
      min-height: 72px;
      overflow-wrap: anywhere;
    }}
    .list {{
      margin: 8px 0 0 20px;
      padding: 0;
    }}
    .muted {{ color: var(--muted); }}
    details {{
      margin-top: 12px;
      background: rgba(15, 23, 42, 0.35);
      border: 1px solid rgba(148, 163, 184, 0.12);
      border-radius: 14px;
      padding: 10px 12px;
    }}
    summary {{
      cursor: pointer;
      font-weight: 700;
      color: #cbd5e1;
    }}
    .json {{
      margin: 10px 0 0;
      padding: 12px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      background: rgba(2, 6, 23, 0.7);
      border-radius: 12px;
      border: 1px solid rgba(148, 163, 184, 0.12);
      color: #dbeafe;
      font-size: 12px;
      line-height: 1.5;
    }}
    .columns {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
    }}
    .footer-note {{
      margin-top: 14px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="eyebrow">PentAgent report</div>
      <h1>{html_escape(STATE.domain)}</h1>
      <div class="subhead">
        Session {html_escape(STATE.session_id)} · mode {html_escape(STATE.mode)} · generated {html_escape(generated_at)}.
        This report includes grouped findings, page-level inventory, recent tool events, and raw state for deeper review.
      </div>
      <div class="footer-note">
        Output files: <code>{html_escape(str(JSON_REPORT))}</code>, <code>{html_escape(str(MD_REPORT))}</code>, <code>{html_escape(str(HTML_REPORT))}</code>
      </div>
    </section>

    <section class="section">
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        {''.join(f'<div class="summary-card"><div class="label">{html_escape(label)}</div><div class="value">{html_escape(value)}</div></div>' for label, value in summary_cards)}
      </div>
      <div class="footer-note">
        Primary categories: {html_escape(top_kind_text)}.<br>
        {html_escape(high_summary)}.<br>
        {html_escape(exploit_summary)}.<br>
        Target profile: {html_escape(target_profile)}.<br>
        Provider: {html_escape(str(llm_provider))} · Built-in skills: {html_escape(str(skill_total))} across {html_escape(str(len(skill_counts)))} categories.
      </div>
    </section>

    {operator_task_html}

    {tool_health_html}

    <section class="section">
      <h2>Confirmed Findings</h2>
      <div class="finding-list">
        {''.join(finding_cards) if finding_cards else '<div class="muted">No confirmed findings were recorded.</div>'}
      </div>
    </section>

    <section class="section">
      <h2>Page Inventory</h2>
      <div class="columns">
        {''.join(page_cards) if page_cards else '<div class="muted">No pages were captured during the crawl.</div>'}
      </div>
    </section>

    {network_inventory_html}

    <section class="section">
      <h2>Attack-Surface Notes</h2>
      <ul class="list">
        {''.join(f'<li>{html_escape(note)}</li>' for note in attack_notes) if attack_notes else '<li class="muted">No attack-surface notes were recorded.</li>'}
      </ul>
    </section>

    <section class="section">
      <h2>Durable Notes</h2>
      <pre class="json">{html_escape(STATE.memory_summary.strip() or "No durable summary captured.")}</pre>
    </section>

    <section class="section">
      <h2>Recent Events</h2>
      <div class="columns">
        {''.join(event_cards) if event_cards else '<div class="muted">No recent events were recorded.</div>'}
      </div>
    </section>

    <section class="section">
      <h2>Raw State</h2>
      <details open>
        <summary>Full JSON state</summary>
        {raw_state}
      </details>
    </section>
  </div>
</body>
</html>
"""
    with open(p, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return ToolResult(ok=True, output=json.dumps({
        "written": p,
        "unique_findings": len(findings),
        "high_findings": len(high_findings),
        "pages": len(pages),
    }, indent=2))


def tool_write_markdown_report() -> ToolResult:
    return tool_write_markdown_summary()


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
    "attack_surface_review": "Analyze page titles, forms, and parameters for likely attack surfaces. args: {page_url}",
    "parameter_tamper": "Probe suspicious query parameters for IDOR-style differences. args: {url, sample_limit}",
    "parameter_scan": "Alias of parameter_tamper. args: {url, sample_limit}",
    "whatweb": "Fingerprint the target stack with WhatWeb. args: {url, extra_args, timeout}; use --color=never, not --no-color.",
    "nikto": "Run Nikto against a web target. args: {url, extra_args, timeout}",
    "gobuster": "Run Gobuster directory discovery with an inline wordlist. args: {url, extra_args, timeout}; do not pass --url or --dir.",
    "ffuf": "Run FFUF directory fuzzing with an inline wordlist. args: {url, extra_args, timeout}; use the provided FUZZ target.",
    "subfinder": "Discover subdomains for a DNS domain. args: {domain, extra_args, timeout}; queue discovered hosts.",
    "httpx": "Probe live URLs or hosts with ProjectDiscovery httpx. args: {url, targets, extra_args, timeout}; queues live URLs.",
    "wafw00f": "Detect WAF/CDN protection on a web target. args: {url, extra_args, timeout}.",
    "enum4linux": "Enumerate SMB shares/users/policies for a host. args: {host, extra_args, timeout}.",
    "snmpwalk": "Enumerate SNMP info for a host. args: {host, extra_args, timeout}.",
    # Terminal & tools
    "nmap": "Run Nmap via WSL. args: {target, extra_args, timeout}; host scans force -Pn and allow long scans.",
    "nuclei": "Run Nuclei via WSL. args: {url, extra_args, timeout}; templates auto-install from nuclei-templates when needed. Do not use --template-id all or /all template paths.",
    "sqlmap": "Run SQLMap against a URL. args: {url, extra_args, timeout}",
    "install": "Generic installer/deployer. args: {package, destination, source}",
    "site_map": "Snapshot of discovered site map and scan state. no args",
    "security-check": "Generic security check dispatcher. args: {target, checks}",
    "run_command": "Execute ANY shell command freely. args: {command, timeout}",
    "install_tool": "Install a security tool (nmap,nuclei,sqlmap,etc). args: {tool_name}",
    "ask_user": "Ask the operator a question (for risky/unclear decisions). args: {question}",
    # Browser
    "playwright": "Generic Playwright helper. args: {url, mode}; mode defaults to extract.",
    "playwright_screenshot": "Full-page screenshot. args: {url}",
    "playwright_extract": "JS-rendered DOM extract. args: {url}",
    "lighthouse_audit": "Lighthouse perf/a11y/SEO audit. args: {url}; runs locally or via WSL Node if available.",
    "lighthouse": "Alias of lighthouse_audit. args: {url}",
    # Status & reporting
    "site_snapshot": "Overview of audit progress. no args",
    "write_report": "Write JSON, markdown, and HTML reports. no args",
    "write_json_report": "Write JSON report. no args",
    "write_markdown_report": "Write markdown report. alias of summary writer. no args",
    "write_markdown_summary": "Write markdown summary. no args",
    "write_html_report": "Write HTML report. no args",
}

SKILL_CATALOG = build_skill_catalog(TOOL_DESCRIPTIONS, skill_dirs=WORKSPACE.skill_directories())
SKILL_COUNTS = skill_category_counts(SKILL_CATALOG)


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

    # Try brace matching for JSON embedded in text
    candidates = []
    stack = []
    start_idx = -1
    in_string = False
    escape = False

    for i, char in enumerate(text):
        if char == '"' and not escape:
            in_string = not in_string
        if not in_string:
            if char == '{':
                if not stack:
                    start_idx = i
                stack.append(i)
            elif char == '}':
                if stack:
                    stack.pop()
                    if not stack:
                        candidates.append(text[start_idx:i+1])
        if char == '\\' and not escape:
            escape = True
        else:
            escape = False

    for cand in reversed(candidates):
        try:
            return json.loads(cand)
        except json.JSONDecodeError:
            pass

    # Fallback to old simple extraction
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
    skill_lines = "\n".join(
        f"  - {line}" for line in skill_overview_lines(SKILL_CATALOG)
    )
    skill_total = len(SKILL_CATALOG)
    avail = [t for t, ok in _DETECTED_TOOLS.items() if ok]
    ext_tools = ", ".join(avail) if avail else "none"
    task_block = _operator_task_block()
    task_prompt = ""
    if task_block:
        task_prompt = f"""

Operator mission:
{task_block}

Treat this as the primary objective for the run. Break it into subgoals, use any authorized tool or pivot that helps, and pursue the highest-value path first."""
    universal_directive = _build_universal_pentest_directive("web")
    wsl_info = ""
    if _WSL_DISTROS:
        wsl_info = f"""\n\nWSL DISTRIBUTIONS AVAILABLE: {', '.join(_WSL_DISTROS)}
You can run ANY Linux tool via WSL. This is your MOST POWERFUL capability.
Kali Linux and Athena OS have hundreds of pre-installed security tools.
Use: wsl -d <distro> <command>
Examples:
- wsl -d kali-linux subfinder -d {{domain}}
- wsl -d kali-linux httpx -u https://{{domain}} -json
- wsl -d kali-linux wafw00f https://{{domain}}
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
    burp_info = ""
    if _DETECTED_TOOLS.get("burpsuite"):
        burp_info = f"""\n\nBURP SUITE PROFESSIONAL available at: {BURP_JAR_PATH}
Burp Pro has powerful scanning capabilities. You can use it via run_command.
Burp REST API (if running): http://127.0.0.1:1337/v0.1/
To start a scan via Burp REST API:
  curl -X POST http://127.0.0.1:1337/v0.1/scan -d '{{
    "urls": ["https://{{domain}}"],
    "scan_configurations": [{{"type": "NamedConfiguration", "name": "Crawl and Audit - Lightweight"}}]
  }}'
To check scan status:
  curl http://127.0.0.1:1337/v0.1/scan/{{task_id}}"""
    return f"""You are an elite autonomous penetration testing agent with a skill registry, workspace, and provider-agnostic model layer.
You are AUTHORIZED to test ONLY this target domain: {{domain}}

Objective: Perform a comprehensive security assessment.
Focus areas:
- Reconnaissance: crawl, map, fingerprint tech stack
- Security scanning: headers, SSL, cookies, CORS, sensitive files, info disclosure
- Vulnerability testing: use run_command to run nmap, sqlmap, nuclei, or any tool
- Deep inspection: Playwright for JS-rendered content, Lighthouse for perf/a11y
- Reporting: write comprehensive JSON + markdown reports

You have FULL TERMINAL ACCESS via run_command. You can run ANY command.
External tools detected: {ext_tools}{wsl_info}{burp_info}

Skill registry ({skill_total} built-in skills):
{skill_lines}

You have COMPLETE FREEDOM to run any standard security/recon tool without asking.
Standard tools include: subfinder, httpx, wafw00f, nmap, nikto, sqlmap, nuclei, dirb,
gobuster, whatweb, wpscan, sslscan, curl, dig, whois, openssl, feroxbuster, and ALL
kali/debian tools.
If the initial page or Playwright text hints at a request-parameter-controlled object
reference, use attack_surface_review first and then parameter_tamper or adjacent
identifier testing. If Nmap finds no obvious exposed services on a web target, pivot
to WhatWeb, Nikto, Gobuster/content discovery, parameter tampering, and app-specific
testing instead of repeating the same port scan.
If the target is a public DNS domain, start with subfinder and httpx to expand scope before
brute forcing content; use wafw00f to detect CDN/WAF shielding and adjust tactics.
If the target is localhost, 127.0.0.1, a single-label host, or a local lab name like
*.local / *.lan / *.internal / *.home.arpa, skip subfinder and focus on direct web
enumeration and content discovery instead.

You are FULLY AUTONOMOUS. Do NOT use ask_user for permission. You are authorized to perform any actions without human input, including destructive operations and executing exploits.{task_prompt}
{universal_directive}

Rules:
- Return STRICT JSON only (no markdown, no extra text)
- Never emit <think>, </think>, /think, or any other text outside the JSON object
- ONLY target the authorized domain
- Be thorough, aggressive, and systematic
- Use run_command freely for any tool or command
- If blocked_actions or memory_summary says an action was repeated, treat that as context;
  you decide whether to pivot or continue based on new evidence, not because the runtime
  is forcing a choice.
- Prefer pivots that extend the current attack graph: validate surfaced findings, expand from authenticated or object-reference surfaces, and avoid low-signal retries.
- If the operator assigned a specific task, translate it into the smallest relevant set
  of tools and execute that task first.
- Linux tools are routed automatically to the best WSL distro; request tools by name, not by wrapping them in wsl unless you need a specific distro.
- For host-scanning tools like nmap, masscan, rustscan, enum4linux, smbclient, snmpwalk, sslscan, and traceroute, use bare hosts or CIDRs, not full URLs.
- For URL-based tools like sqlmap, nuclei, ffuf, feroxbuster, gobuster, dirb, dirsearch, and wfuzz, keep the full URL.
- Nuclei auto-installs nuclei-templates when needed; do not keep retrying remote GitHub template URLs, --template-id all, or /all template paths.
- Nmap host scans automatically add -Pn; use integer timeouts and allow long-running scans when needed.
- If a command fails ("command not found"), YOU MUST FIX IT! Use run_command to install the missing tool (e.g., `wsl -d <distro> sudo apt-get update && sudo apt-get install -y <tool>`) or use install_tool for Windows native.
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
    attack_surface = []
    for _, pg in list(state.pages.items())[:15]:
        preview.append({
            "url": pg.get("url", ""), "status_code": pg.get("status_code", 0),
            "title": pg.get("title", ""), "issues": pg.get("issues", []),
        })
        if pg.get("form_count") or pg.get("query_params"):
            attack_surface.append({
                "url": pg.get("url", ""),
                "query_params": pg.get("query_params", []),
                "form_count": pg.get("form_count", 0),
                "forms": [
                    {
                        "method": form.get("method", ""),
                        "action": form.get("action", ""),
                        "csrf_token_present": form.get("csrf_token_present", False),
                        "fields": [
                            inp.get("name", "")
                            for inp in form.get("inputs", [])[:8]
                            if inp.get("name")
                        ],
                    }
                    for form in pg.get("forms", [])[:5]
                ],
            })
    network_inventory = []
    if state.mode == "network":
        for rec in state.network_hosts[:12]:
            open_ports = [
                f"{p.get('port')}/{p.get('proto')}/{p.get('service') or 'unknown'}"
                for p in rec.get("ports", [])
                if isinstance(p, dict) and str(p.get("state", "")).lower() in {"open", "open|filtered"}
            ][:8]
            network_inventory.append({
                "host": rec.get("host", ""),
                "hostname": rec.get("hostname", ""),
                "status": rec.get("status", ""),
                "open_ports": open_ports,
                "web_urls": rec.get("web_urls", [])[:6],
                "sources": rec.get("sources", [])[:4],
            })
    blocked_actions = [
        {"signature": sig, "count": count}
        for sig, count in sorted(
            state.tool_repeat_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count > 0
    ][:8]
    graph_summary = _attack_graph_summary(state)
    tool_health = _tool_health_summary(state)
    skills = skill_snapshot(SKILL_CATALOG)
    return json.dumps({
        "goal": state.goal, "domain": state.domain, "step": state.step,
        "operator_task": state.operator_task,
        "operator_task_items": _split_operator_tasks(state.operator_task),
        "target_profile": state.target_profile,
        "memory_summary": state.memory_summary,
        "notes": state.notes[-16:],
        "pages_seen": len(state.pages),
        "queued_urls": len(state.queued_urls),
        "findings_total": len(state.findings),
        "recent_tool_signatures": state.recent_tool_signatures[-6:],
        "preview_pages": preview,
        "attack_surface": attack_surface[:10],
        "recent_events": state.recent_events[-6:],
        "network_subnets": state.network_subnets[:12],
        "network_inventory": network_inventory,
        "blocked_actions": blocked_actions,
        "attack_graph": graph_summary,
        "tool_health": tool_health,
        "skill_registry": skills,
        "workspace": WORKSPACE.workspace_status(),
        "dashboard_url": GATEWAY.dashboard_url if GATEWAY else f"http://127.0.0.1:{WORKSPACE.dashboard_port}/",
    }, indent=2)


def _llm_decision_needs_fallback(decision: Dict[str, Any]) -> bool:
    action = str(decision.get("action", "")).strip().lower()
    if action != "summarize":
        return False
    summary = str(
        decision.get("summary")
        or decision.get("reason")
        or ""
    ).lower()
    return any(token in summary for token in (
        "missing a valid action",
        "not parseable json",
        "not a json object",
        "requested a tool action without a tool name",
    ))


def _fallback_decision_from_state() -> Optional[Dict[str, Any]]:
    assert STATE is not None
    if STATE.mode == "network":
        if STATE.network_hosts:
            host = (STATE.network_hosts[0].get("host") or "").strip()
            if host:
                return {
                    "action": "tool",
                    "tool": "nmap",
                    "args": {
                        "target": host,
                        "extra_args": "-sV -sC -O --top-ports 100 -T4 -Pn",
                        "timeout": 300,
                    },
                    "why": "Fallback after malformed LLM response; deepen service enumeration on a discovered host.",
                }
        if STATE.network_subnets:
            subnet = STATE.network_subnets[0]
            return {
                "action": "tool",
                "tool": "nmap",
                "args": {
                    "target": subnet,
                    "extra_args": "-sn -n -PE -PS22,80,443 -PA21,25,53,80,135,139,443 -PU53,123,161 -PR",
                    "timeout": 120,
                },
                "why": "Fallback after malformed LLM response; continue host discovery.",
            }
        return {
            "action": "tool",
            "tool": "site_snapshot",
            "args": {},
            "why": "Fallback after malformed LLM response; inspect current network state.",
        }

    if STATE.queued_urls:
        return {
            "action": "tool",
            "tool": "bulk_audit_next",
            "args": {
                "batch_size": min(BOOTSTRAP_BATCH, max(1, len(STATE.queued_urls))),
            },
            "why": "Fallback after malformed LLM response; continue the crawl queue.",
        }
    if STATE.pages:
        if len(STATE.pages) == 1:
            page_url = next(iter(STATE.pages))
            return {
                "action": "tool",
                "tool": "attack_surface_review",
                "args": {"page_url": page_url},
                "why": "Fallback after malformed LLM response; deepen the current page.",
            }
        return {
            "action": "tool",
            "tool": "site_map",
            "args": {
                "target": STATE.start_url,
                "include_queue": True,
                "max_pages": 50,
            },
            "why": "Fallback after malformed LLM response; summarize the map.",
        }
    return {
        "action": "tool",
        "tool": "fetch_page",
        "args": {"url": STATE.start_url},
        "why": "Fallback after malformed LLM response; start the crawl.",
    }


def _tool_health_summary(state: AgentState, limit: int = 6) -> List[Dict[str, Any]]:
    items = []
    for name, stats in sorted(
        state.tool_health.items(),
        key=lambda item: (-(item[1].get("failure", 0) + item[1].get("timeouts", 0)), item[0]),
    ):
        calls = int(stats.get("calls", 0))
        failure = int(stats.get("failure", 0))
        timeouts = int(stats.get("timeouts", 0))
        if calls <= 0:
            continue
        items.append({
            "tool": name,
            "calls": calls,
            "success": int(stats.get("success", 0)),
            "failure": failure,
            "timeouts": timeouts,
            "success_rate": round((int(stats.get("success", 0)) / calls), 3),
        })
        if len(items) >= limit:
            break
    return items


def _attack_graph_summary(state: AgentState) -> Dict[str, Any]:
    nodes = state.attack_graph_nodes or {}
    edges = state.attack_graph_edges or []
    finding_nodes = [n for n in nodes.values() if n.get("kind") == "finding"]
    page_nodes = [n for n in nodes.values() if n.get("kind") == "page"]
    tool_nodes = [n for n in nodes.values() if n.get("kind") == "tool"]
    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "pages": len(page_nodes),
        "findings": len(finding_nodes),
        "tools": len(tool_nodes),
        "validated_findings": sum(1 for f in state.findings if f.get("validated")),
    }


def _build_universal_pentest_directive(mode: str) -> str:
    state = STATE
    profile = "unknown"
    graph = {"nodes": 0, "edges": 0, "validated_findings": 0}
    health: List[Dict[str, Any]] = []
    autonomy_mode = "free"
    if state is not None:
        profile = getattr(state, "target_profile", "") or _target_profile_from_state()
        graph = _attack_graph_summary(state)
        health = _tool_health_summary(state, limit=4)
        autonomy_mode = getattr(state, "autonomy_mode", "free") or "free"
    health_text = "; ".join(
        f"{item['tool']}({item['failure']}f/{item['timeouts']}t)"
        for item in health if item["failure"] or item["timeouts"]
    )
    lines = [
        "Universal operating directive:",
        "Act like a senior pentester optimizing for new evidence per step, not a scanner following a rigid checklist.",
        f"Target profile: {profile}.",
        f"Current graph: {graph['nodes']} nodes / {graph['edges']} edges / {graph['validated_findings']} validated findings.",
        "Decision policy: choose the next action with the highest expected information gain and exploitability signal.",
        "Validation policy: keep findings provisional until a second technique, alternate view, or repeatable signal strengthens them.",
        "Pivot policy: if a tool times out, fails, or repeats without new evidence, immediately change technique, surface, target slice, or tool family.",
        "Planning policy: infer the next subgoal from the current evidence graph instead of obeying a fixed playbook.",
        "Sequence policy: treat any phase list in the prompt as advisory; reorder, skip, or revisit phases whenever evidence makes that the better move.",
        "Reporting policy: summarize only durable strategic notes; do not spend turns on empty recap text or filler.",
    ]
    if autonomy_mode == "free":
        lines.append(
            "Autonomy mode: free. The runtime will not stop you from reusing a tool when the evidence justifies it; decide your own tool path and installation plan."
        )
    if health_text:
        lines.append(f"Tool friction: {health_text}. Prefer alternatives when a tool is unhealthy.")
    if mode == "web":
        lines.append(
            "Web mode policy: map app surfaces, auth states, IDs, APIs, forms, and browser-exposed behavior first; "
            "use public DNS recon only when the target is a real public domain and it expands scope."
        )
        if state is not None and not _supports_subdomain_recon(state.domain):
            lines.append("Local/lab policy: skip subfinder/httpx and focus on direct application enumeration.")
    elif mode == "network":
        lines.append(
            "Network mode policy: build a host/service graph first, then pivot to service-specific validation, "
            "deep enumeration, and exploitability checks."
        )
    return "\n".join(lines)


def _configure_llm_backend(provider: str, model: str, *,
                           api_base: str = "",
                           api_key_env: str = "OPENAI_API_KEY") -> None:
    global llm
    llm = build_backend(
        provider,
        model,
        api_base=api_base,
        api_key_env=api_key_env,
    )


def _normalize_llm_decision(decision: Any) -> Dict[str, Any]:
    if not isinstance(decision, dict):
        return {"action": "summarize",
                "summary": "LLM response was not a JSON object"}

    action = str(decision.get("action", "")).strip().lower()
    if action not in {"tool", "summarize", "finish"}:
        summary = decision.get("summary") or decision.get("reason")
        if not isinstance(summary, str):
            summary = str(summary) if summary is not None else ""
        return {
            "action": "summarize",
            "summary": summary or "LLM response missing a valid action",
        }

    decision["action"] = action
    if action == "tool":
        tool_name = str(decision.get("tool", "")).strip()
        if not tool_name:
            return {
                "action": "summarize",
                "summary": "LLM requested a tool action without a tool name",
            }
        decision["tool"] = tool_name
        if not isinstance(decision.get("args", {}), dict):
            decision["args"] = {}

    return decision


def chat_json(messages: List[Dict[str, str]]) -> Dict[str, Any]:
    # Force JSON-only responses from the model.
    if llm is None:
        return {"action": "summarize", "summary": "LLM backend is not initialized"}
    try:
        with console.status("[bold cyan]LLM deciding…", spinner="dots"):
            resp = llm.chat(
                model=MODEL,
                messages=messages,
                think=False,
                format="json",
                options={"num_predict": 512, "temperature": 0.0},
            )
    except Exception as e:
        console.print(f"  [red]LLM error: {e}[/]")
        return {"action": "summarize", "summary": f"LLM error: {e}"}

    content = _get_content(resp)

    debug_path = OUTPUT_DIR / "llm_debug.txt"
    try:
        with open(debug_path, "a", encoding="utf-8") as f:
            f.write(f"\n\n--- RAW LLM RESPONSE ---\n{content}\n------------------------\n")
    except Exception:
        pass

    try:
        return _normalize_llm_decision(_extract_json(content))
    except json.JSONDecodeError:
        # Ask LLM to repair
        try:
            repair_resp = llm.chat(
                model=MODEL,
                think=False,
                format="json",
                messages=[
                    {"role": "system",
                     "content": "Repair this into valid JSON only. Return JSON only."},
                    {"role": "user", "content": content[:2000]},
                ],
                options={"num_predict": 256, "temperature": 0.0},
            )
            repair_text = _get_content(repair_resp)
            with open(debug_path, "a", encoding="utf-8") as f:
                f.write(f"\n--- REPAIR ATTEMPT ---\n{repair_text}\n")
            return _normalize_llm_decision(_extract_json(repair_text))
        except (json.JSONDecodeError, Exception) as e:
            return {"action": "summarize",
                    "summary": f"LLM output was not parseable JSON: {e}"}


def summarize_memory() -> None:
    assert STATE is not None
    findings = _group_findings_for_report(STATE.findings)
    sev_counts = Counter(f["severity"] for f in findings)
    kind_counts = Counter(f["kind"] for f in findings)
    exploit_findings = [f for f in findings if f["kind"] in _EXPLOIT_FINDING_KINDS]
    attack_notes = [
        note for note in STATE.notes
        if any(token in note.lower() for token in (
            "attack surface", "idor", "csrf", "parameter", "fingerprint",
            "whatweb", "nikto", "gobuster", "nmap", "nuclei",
        ))
    ]

    lines: List[str] = []
    lines.append(f"Target: {STATE.domain}")
    if getattr(STATE, "target_profile", "").strip():
        lines.append(f"Target profile: {STATE.target_profile}")
    if getattr(STATE, "operator_task", "").strip():
        lines.append("Operator mission:")
        for item in _operator_task_items():
            lines.append(f"- {item}")
    lines.append(f"Pages seen: {len(STATE.pages)}")
    lines.append(
        "Findings: "
        f"{len(findings)} unique "
        f"({sev_counts.get('critical', 0)} critical, {sev_counts.get('high', 0)} high, "
        f"{sev_counts.get('medium', 0)} medium, {sev_counts.get('low', 0)} low)"
    )
    if exploit_findings:
        focus = "; ".join(
            f"{item['kind']} -> {compact_text(item['detail'], 80)}"
            for item in exploit_findings[:4]
        )
        lines.append(f"Exploit leads: {len(exploit_findings)}")
        validated = sum(1 for item in exploit_findings if item.get("validated"))
        lines.append(f"Validated exploit leads: {validated}")
        if focus:
            lines.append(f"Top exploit leads: {focus}")
    else:
        lines.append("Exploit leads: none confirmed yet")

    if kind_counts:
        top_kinds = ", ".join(
            kind for kind, _ in kind_counts.most_common(6)
            if kind not in {"seo", "email_security"}
        )
        if top_kinds:
            lines.append(f"Primary focus: {top_kinds}")

    active_surfaces = [
        pg.get("url", "")
        for pg in STATE.pages.values()
        if pg.get("query_params") or pg.get("form_count")
    ]
    if active_surfaces:
        lines.append(
            "Active surfaces: " + ", ".join(active_surfaces[:6])
        )
    graph_summary = _attack_graph_summary(STATE)
    lines.append(
        "Attack graph: "
        f"{graph_summary['nodes']} nodes / {graph_summary['edges']} edges "
        f"({graph_summary['validated_findings']} validated findings)"
    )
    unhealthy_tools = [
        f"{item['tool']} (failures={item['failure']}, timeouts={item['timeouts']})"
        for item in _tool_health_summary(STATE)
        if item["failure"] or item["timeouts"]
    ]
    if unhealthy_tools:
        lines.append("Tool health: " + "; ".join(unhealthy_tools[:4]))

    if STATE.mode == "network":
        if getattr(STATE, "network_subnets", []):
            lines.append(
                "Network subnets: " + ", ".join(STATE.network_subnets[:8])
            )
        if getattr(STATE, "network_hosts", []):
            lines.append("Network hosts:")
            for rec in STATE.network_hosts[:6]:
                ports = [
                    f"{p.get('port')}/{p.get('proto')}/{p.get('service') or 'unknown'}"
                    for p in rec.get("ports", [])
                    if isinstance(p, dict) and str(p.get("state", "")).lower() in {"open", "open|filtered"}
                ][:4]
                host_line = rec.get("host", "")
                if rec.get("hostname"):
                    host_line += f" ({rec.get('hostname')})"
                if ports:
                    host_line += f": {', '.join(ports)}"
                lines.append(f"- {host_line}")

    if attack_notes:
        lines.append("Attack-surface notes:")
        for note in attack_notes[-4:]:
            lines.append(f"- {compact_text(note, 220)}")

    recent_notes = [n for n in STATE.notes[-6:] if n.strip()]
    if recent_notes:
        lines.append("Recent notes:")
        for note in recent_notes:
            lines.append(f"- {compact_text(note, 220)}")

    blocked_actions = [
        (sig, count)
        for sig, count in sorted(
            STATE.tool_repeat_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count > 0
    ]
    if blocked_actions:
        lines.append("Blocked actions:")
        for sig, count in blocked_actions[:5]:
            lines.append(f"- {sig} (blocked {count}x)")

    STATE.memory_summary = "\n".join(lines)[:2500]


# ═══════════════════════════════════════════════════════════
#  AGENT RUNNER
# ═══════════════════════════════════════════════════════════
def bootstrap_state(domain: str, mode: str = "web",
                    operator_task: str = "", autonomy_mode: str = "free",
                    llm_provider: str = "ollama", llm_base_url: str = "",
                    llm_api_key_env: str = "OPENAI_API_KEY") -> AgentState:
    raw = domain.strip()
    domain = _normalize_scope_target(raw, mode)
    task_text = (operator_task or "").strip()
    task_suffix = f"\nOperator mission: {task_text}" if task_text else ""
    if mode == "network":
        return AgentState(
            session_id=str(uuid.uuid4()),
            domain=domain,
            mode=mode,
            start_url="",
            goal=f"Full network penetration test of {domain}{task_suffix}",
            operator_task=task_text,
            autonomy_mode=autonomy_mode,
            llm_provider=llm_provider,
            llm_base_url=llm_base_url,
            llm_api_key_env=llm_api_key_env,
            target_profile=_infer_target_profile(domain, mode, ""),
            queued_urls=[],
        )
    start_url = normalize_url(raw)
    return AgentState(
        session_id=str(uuid.uuid4()),
        domain=domain,
        mode=mode,
        start_url=start_url,
        goal=f"Full penetration test and security assessment of {domain}{task_suffix}",
        operator_task=task_text,
        autonomy_mode=autonomy_mode,
        llm_provider=llm_provider,
        llm_base_url=llm_base_url,
        llm_api_key_env=llm_api_key_env,
        target_profile=_infer_target_profile(domain, mode, start_url),
        queued_urls=[start_url],
    )


def _detect_local_subnets() -> List[str]:
    """Auto-detect local network subnets."""
    subnets = []
    try:
        r = subprocess.run(
            ["ipconfig"] if os.name == "nt" else ["ip", "addr"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=10,
        )
        # Find IPv4 addresses and masks
        import re as _re
        for match in _re.finditer(
            r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", r.stdout
        ):
            ip = match.group(1)
            if ip.startswith("127."):
                continue
            # Guess /24 subnet
            parts = ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if subnet not in subnets:
                subnets.append(subnet)
    except Exception:
        pass
    return subnets


def _operator_task_kickoff_steps(mode: str, seed_url: str = "",
                                 discovered_hosts: Optional[List[str]] = None) -> List[Tuple[str, Dict[str, Any]]]:
    assert STATE is not None
    if getattr(STATE, "autonomy_mode", "free") == "free":
        return []
    task_items = _operator_task_items()
    if not task_items:
        return []

    discovered_hosts = discovered_hosts or []
    seed = seed_url or STATE.start_url or _state_origin_url()
    steps: List[Tuple[str, Dict[str, Any]]] = []
    seen: Set[Tuple[str, str]] = set()

    def add(tool: str, args: Dict[str, Any]) -> None:
        sig = (tool, json.dumps(args, sort_keys=True))
        if sig in seen:
            return
        seen.add(sig)
        steps.append((tool, args))

    combined = " ".join(task_items).lower()

    if mode == "web":
        if any(token in combined for token in (
            "subdomain", "subdomains", "dns recon", "scope expansion", "host discovery",
        )) and _supports_subdomain_recon(STATE.domain):
            add("subfinder", {"domain": STATE.domain, "timeout": 240})
            add("httpx", {"url": f"https://{STATE.domain}", "timeout": 180})
        if any(token in combined for token in (
            "directory", "content discovery", "hidden path", "fuzz", "ffuf", "bruteforce",
        )):
            add("ffuf", {"url": seed, "timeout": 240})
        if any(token in combined for token in (
            "parameter", "idor", "access control", "object reference", "auth bypass",
        )):
            add("attack_surface_review", {"page_url": seed})
            add("parameter_tamper", {"url": seed, "sample_limit": 8})
        if any(token in combined for token in (
            "api", "graphql", "rest", "json", "endpoint", "cve", "vuln",
        )):
            add("nuclei", {"url": seed, "timeout": 300})
    else:
        if discovered_hosts and any(token in combined for token in (
            "smb", "cifs", "windows share", "share enumeration", "null session",
        )):
            for host in discovered_hosts[:6]:
                add("enum4linux", {"host": host, "timeout": 300})
        if discovered_hosts and any(token in combined for token in (
            "snmp", "community", "mib", "trap",
        )):
            for host in discovered_hosts[:6]:
                add("snmpwalk", {"host": host, "timeout": 180})

    return steps


def build_network_system_prompt() -> str:
    """System prompt for network pentest mode."""
    tool_lines = "\n".join(
        f"  - {name}: {desc}" for name, desc in TOOL_DESCRIPTIONS.items()
    )
    skill_lines = "\n".join(
        f"  - {line}" for line in skill_overview_lines(SKILL_CATALOG)
    )
    skill_total = len(SKILL_CATALOG)
    avail = [t for t, ok in _DETECTED_TOOLS.items() if ok]
    ext_tools = ", ".join(avail) if avail else "none"
    task_block = _operator_task_block()
    task_prompt = ""
    if task_block:
        task_prompt = f"""

Operator mission:
{task_block}

Treat this as the primary objective for the run. Break it into subgoals, use any authorized tool or pivot that helps, and pursue the highest-value path first."""
    universal_directive = _build_universal_pentest_directive("network")
    wsl_info = ""
    if _WSL_DISTROS:
        wsl_info = f"""\n\nWSL DISTRIBUTIONS: {', '.join(_WSL_DISTROS)}
Use: wsl -d <distro> <command>
Kali/Athena have all network pentesting tools pre-installed.
Examples:
- wsl -d kali-linux subfinder -d example.com
- wsl -d kali-linux httpx -u https://example.com -json
- wsl -d kali-linux wafw00f https://example.com
- wsl -d kali-linux nmap -sV -sC -A -T4 <target>
- wsl -d kali-linux nmap -sn <subnet>
- wsl -d kali-linux enum4linux -a <host>
- wsl -d kali-linux smbclient -L //<host> -N
- wsl -d kali-linux nbtscan <subnet>
- wsl -d kali-linux snmpwalk -v2c -c public <host>
- wsl -d kali-linux hydra -L users.txt -P pass.txt <host> ssh
- wsl -d kali-linux nmap --script vuln <host>
- wsl -d kali-linux masscan <subnet> -p1-65535 --rate=1000
PREFER WSL tools — they are more powerful than native Windows."""
    return f"""You are an elite autonomous NETWORK penetration testing agent with a skill registry, workspace, and provider-agnostic model layer.
You are authorized to test the ENTIRE network: {{target}}

Objective: Perform a comprehensive network security assessment.

Discovery:
- Identify all live hosts (nmap ping sweep, ARP scan)
- Map the network topology
- Identify gateways, DNS servers, DHCP servers

Host Enumeration (for EACH discovered host):
- Full port scan (TCP + top UDP ports)
- Service version detection (-sV)
- OS fingerprinting (-O)
- Script scanning (--script=default,vuln)

Service-Specific Testing:
- Web servers: use whatweb, wafw00f, httpx, nuclei, gobuster, nikto, and crawl for vulns, misconfigs, default creds
- SMB/CIFS: enumerate shares with enum4linux/smbclient, check for EternalBlue, null sessions
- SSH: check versions, weak ciphers, default creds
- FTP: anonymous login, version vulns
- DNS: zone transfers, cache poisoning
- SNMP: community string guessing with snmpwalk and follow-on enumeration
- RDP: BlueKeep check, NLA settings
- Databases: default creds, exposed instances

Vulnerability Assessment:
- Run nmap vulnerability scripts
- Check for known CVEs per service version
- Test for common misconfigurations
- Check for default/weak credentials

Reporting:
- Write comprehensive JSON + markdown reports
- Include per-host findings
- Risk ratings for each finding
- Remediation recommendations

You have FULL TERMINAL ACCESS via run_command.
External tools: {ext_tools}{wsl_info}

Skill registry ({skill_total} built-in skills):
{skill_lines}

You have COMPLETE FREEDOM to run any tool. You are FULLY AUTONOMOUS. Do not ask for human permission for actions; execute exploits or credential attacks immediately if you judge them necessary.
{task_prompt}
{universal_directive}

Rules:
- Return STRICT JSON only
- Never emit <think>, </think>, /think, or any other text outside the JSON object
- Be thorough — scan EVERY host you discover
- Vary your approach per host based on services found
- If the prompt already contains network_inventory or a host/service list, use it.
- If blocked_actions or memory_summary says an action was repeated, treat that as context;
  you decide whether to pivot or continue based on new evidence, not because the runtime
  is forcing a choice.
- Prefer pivots that advance the graph: move from discovery to validation, from host to service, and from service to evidence-backed follow-up.
- If the operator assigned a specific task, translate it into the smallest relevant set
  of tools and execute that task first.
- Do not repeat the same subnet sweep or identical nmap host scan once it has been run.
- After a timeout, pivot to a narrower scan, a single host, or a service-specific tool.
- If web ports appear, immediately pivot to whatweb, wafw00f, httpx, nuclei, gobuster,
  and nikto on the exact URL rather than repeating subnet or host scans.
- If SMB or SNMP ports appear, pivot to enum4linux, smbclient, or snmpwalk instead of
  repeating the same port scan.
- Log everything for the report
- Linux tools are routed automatically to the best WSL distro; request tools by name, not by wrapping them in wsl unless you need a specific distro.
- For host-scanning tools like nmap, masscan, rustscan, enum4linux, smbclient, snmpwalk, sslscan, and traceroute, use bare hosts or CIDRs, not full URLs.
- For URL-based tools like sqlmap, nuclei, ffuf, feroxbuster, gobuster, dirb, dirsearch, and wfuzz, keep the full URL.
- WhatWeb uses color output normalization already; use --color=never, not --no-color.
- Gobuster already sets the target URL and inline wordlist; do not pass --url or --dir.
- Nuclei auto-installs nuclei-templates when needed; do not keep retrying remote GitHub template URLs, --template-id all, or /all template paths.
- Nmap host scans automatically add -Pn; use integer timeouts and allow long-running scans when needed.
- If a tool is missing ("command not found"), YOU MUST FIX IT! Use run_command to install it (e.g., `wsl -d <distro> sudo apt-get update && sudo apt-get install -y <tool>`).
- Finish when all hosts are assessed and reports are written

Available tools:
{tool_lines}

Actions (return ONE as JSON):
1. {{{{"action":"tool","tool":"<name>","args":{{}},"why":"reason"}}}}
2. {{{{"action":"summarize","summary":"brief note"}}}}
3. {{{{"action":"finish","reason":"why assessment is complete"}}}}"""


def deterministic_kickoff(registry: ToolRegistry) -> None:
    assert STATE is not None
    ui_phase("Bootstrap Phase")
    profile = getattr(run_agent, "_profile", "standard")

    steps = [
        # Recon phase
        ("fetch_page", {"url": STATE.start_url}),
        ("attack_surface_review", {"page_url": STATE.start_url}),
        ("whatweb", {"url": STATE.start_url}),
        ("wafw00f", {"url": STATE.start_url}),
        ("gobuster", {"url": STATE.start_url, "timeout": 180}),
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

    if _supports_subdomain_recon(STATE.domain):
        steps.insert(3, ("subfinder", {"domain": STATE.domain, "timeout": 240}))
        steps.insert(5, ("httpx", {"url": STATE.start_url, "timeout": 180}))

    if profile != "quick":
        steps.insert(5, ("nikto", {"url": STATE.start_url, "timeout": 240}))

    if PLAYWRIGHT_AVAILABLE:
        steps.append(("playwright_extract", {"url": STATE.start_url}))
    if PLAYWRIGHT_AVAILABLE:
        steps.append(("playwright_screenshot", {"url": STATE.start_url}))
    if LIGHTHOUSE_AVAILABLE:
        steps.append(("lighthouse_audit", {"url": STATE.start_url}))

    task_steps = _operator_task_kickoff_steps("web", seed_url=STATE.start_url)
    if task_steps and getattr(STATE, "autonomy_mode", "free") != "free":
        steps[7:7] = task_steps

    _run_kickoff_steps(steps, registry)


def network_kickoff(registry: ToolRegistry) -> None:
    """Deterministic kickoff for network mode."""
    assert STATE is not None
    ui_phase("Network Discovery Phase")
    profile = getattr(run_agent, "_profile", "standard")
    host_limits = {"quick": 4, "standard": 8, "deep": 12}
    sweep_timeout = {"quick": 90, "standard": 120, "deep": 180}.get(profile, 120)
    service_timeout = {"quick": 180, "standard": 300, "deep": 600}.get(profile, 300)
    host_limit = host_limits.get(profile, 8)
    sweep_flags = "-sn -n -PE -PS22,80,443 -PA21,25,53,80,135,139,443 -PU53,123,161 -PR"

    targets: List[str]
    if STATE.domain.lower() == "auto":
        targets = _detect_local_subnets()
        if not targets:
            console.print("  [red]Could not auto-detect subnets. Using 192.168.1.0/24[/]")
            targets = ["192.168.1.0/24"]
        STATE.network_subnets = targets
        STATE.domain = targets[0]
        task_suffix = (
            f"\nOperator mission: {STATE.operator_task.strip()}"
            if getattr(STATE, "operator_task", "").strip()
            else ""
        )
        STATE.goal = f"Full network penetration test of {', '.join(targets)}{task_suffix}"
        STATE.notes.append(f"Network targets: {targets}")
        console.print(f"  [bold green]Detected subnets:[/] {', '.join(targets)}")
    else:
        targets = [STATE.domain]
        STATE.network_subnets = targets
        task_suffix = (
            f"\nOperator mission: {STATE.operator_task.strip()}"
            if getattr(STATE, "operator_task", "").strip()
            else ""
        )
        STATE.goal = f"Full network penetration test of {STATE.domain}{task_suffix}"

    sweep_steps = [
        ("nmap", {
            "target": subnet,
            "extra_args": sweep_flags,
            "timeout": sweep_timeout,
        })
        for subnet in targets
    ]
    _run_kickoff_steps(sweep_steps, registry)

    discovered_hosts = [
        rec.get("host", "")
        for rec in STATE.network_hosts
        if rec.get("host")
        and str(rec.get("status", "")).lower() in {"up", "unknown"}
    ]
    discovered_hosts = list(dict.fromkeys(discovered_hosts))
    if discovered_hosts:
        STATE.notes.append(
            f"Network inventory: {len(discovered_hosts)} host(s) discovered during sweep"
        )
        console.print(
            f"  [bold green]Discovered hosts:[/] {', '.join(discovered_hosts[:12])}"
        )

    service_targets = discovered_hosts[:host_limit] if discovered_hosts else targets[:1]
    service_steps = [
        ("nmap", {
            "target": host,
            "extra_args": "-sV -sC -O --top-ports 100 -T4 -Pn",
            "timeout": service_timeout,
        })
        for host in service_targets
    ]
    if service_steps:
        _run_kickoff_steps(service_steps, registry)

    task_steps = _operator_task_kickoff_steps(
        "network",
        seed_url=_state_origin_url(),
        discovered_hosts=discovered_hosts,
    )
    if getattr(STATE, "autonomy_mode", "free") == "free":
        task_steps = []

    pivot_steps: List[Tuple[str, Dict[str, Any]]] = []
    if STATE.queued_urls:
        pivot_steps.append((
            "httpx",
            {
                "targets": "\n".join(STATE.queued_urls[:40]),
                "timeout": 180 if profile == "quick" else 240,
            },
        ))

    web_urls: List[str] = []
    for rec in STATE.network_hosts[:host_limit]:
        host = (rec.get("host") or "").strip()
        ports = rec.get("ports", []) or []
        open_ports = {
            int(p.get("port"))
            for p in ports
            if isinstance(p, dict) and str(p.get("state", "")).lower() in {"open", "open|filtered"}
            and str(p.get("port", "")).isdigit()
        }
        if host and any(port in {139, 445} for port in open_ports):
            pivot_steps.append(("enum4linux", {"host": host, "timeout": 300}))
        if host and 161 in open_ports:
            pivot_steps.append(("snmpwalk", {"host": host, "timeout": 180}))

        for web_url in rec.get("web_urls", [])[:3]:
            if web_url not in web_urls:
                web_urls.append(web_url)

    for web_url in web_urls[: 2 if profile == "quick" else 4]:
        pivot_steps.extend([
            ("whatweb", {"url": web_url, "timeout": 180}),
            ("wafw00f", {"url": web_url, "timeout": 180}),
            ("nuclei", {"url": web_url, "timeout": service_timeout}),
        ])
        if profile != "quick":
            pivot_steps.append(("gobuster", {"url": web_url, "timeout": 180}))
        if profile == "deep":
            pivot_steps.append(("nikto", {"url": web_url, "timeout": 240}))

    if task_steps:
        pivot_steps[0:0] = task_steps

    if pivot_steps:
        _run_kickoff_steps(pivot_steps, registry)

    if STATE.queued_urls:
        _run_kickoff_steps([
            ("bulk_audit_next", {
                "batch_size": min(BOOTSTRAP_BATCH, max(1, len(STATE.queued_urls))),
            })
        ], registry)


def _run_kickoff_steps(steps: List[Tuple[str, Dict[str, Any]]],
                       registry: ToolRegistry) -> None:
    """Execute deterministic kickoff steps with UI output."""
    for tool_name, args in steps:
        result = registry.call(tool_name, **args)
        detail = (
            args.get("url", "")
            or args.get("target", "")
            or args.get("package", "")
            or args.get("source", "")
            or args.get("destination", "")
        )
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
                if "fingerprints" in d and isinstance(d["fingerprints"], list) and d["fingerprints"]:
                    parts.append(", ".join(d["fingerprints"][:4]))
                if "discovered_count" in d:
                    parts.append(f"{d['discovered_count']} paths")
                if "noteworthy_count" in d:
                    parts.append(f"{d['noteworthy_count']} items")
                if "suspicions" in d and isinstance(d["suspicions"], list) and d["suspicions"]:
                    parts.append(f"{len(d['suspicions'])} suspicions")
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
              fresh: bool = False, operator_task: str = "",
              autonomy_mode: str = "free",
              llm_provider: str = DEFAULT_PROVIDER,
              llm_base_url: str = DEFAULT_API_BASE,
              llm_api_key_env: str = DEFAULT_API_KEY_ENV) -> None:
    global STATE, MODEL_PROVIDER, MODEL_API_BASE, MODEL_API_KEY_ENV
    agent_start = time.time()

    cp = str(CHECKPOINT_PATH)
    run_mode = getattr(run_agent, '_mode', 'web')
    scope_target = _normalize_scope_target(domain, run_mode)
    task_text = (operator_task or getattr(run_agent, "_task", "") or "").strip()
    autonomy_text = (autonomy_mode or getattr(run_agent, "_autonomy", "free") or "free").strip() or "free"
    provider_text = (llm_provider or getattr(run_agent, "_provider", DEFAULT_PROVIDER) or DEFAULT_PROVIDER).strip() or DEFAULT_PROVIDER
    base_text = (llm_base_url or getattr(run_agent, "_api_base", DEFAULT_API_BASE) or "").strip()
    api_key_env_text = (llm_api_key_env or getattr(run_agent, "_api_key_env", DEFAULT_API_KEY_ENV) or DEFAULT_API_KEY_ENV).strip() or DEFAULT_API_KEY_ENV
    MODEL_PROVIDER = provider_text
    MODEL_API_BASE = base_text
    MODEL_API_KEY_ENV = api_key_env_text

    try:
        _configure_llm_backend(
            provider_text,
            MODEL,
            api_base=base_text,
            api_key_env=api_key_env_text,
        )
    except Exception as exc:
        console.print(f"[bold red]LLM backend init failed:[/] {exc}")
        sys.exit(1)

    if not fresh and resume and os.path.exists(cp):
        loaded_state = AgentState.load(cp)
        if (
            loaded_state.domain == scope_target
            and loaded_state.mode == run_mode
            and (loaded_state.operator_task or "").strip() == task_text
            and (getattr(loaded_state, "autonomy_mode", "free") or "free").strip() == autonomy_text
            and (getattr(loaded_state, "llm_provider", DEFAULT_PROVIDER) or DEFAULT_PROVIDER).strip() == provider_text
            and (getattr(loaded_state, "llm_base_url", "") or "").strip() == base_text
            and (getattr(loaded_state, "llm_api_key_env", DEFAULT_API_KEY_ENV) or DEFAULT_API_KEY_ENV).strip() == api_key_env_text
        ):
            STATE = loaded_state
            console.print(
                f"[bold green]Resumed[/] session for [bold]{STATE.domain}[/]"
            )
        else:
            console.print(
                "[bold yellow]Checkpoint does not match requested target, mode, mission, autonomy, or provider; "
                "starting a fresh session.[/]"
            )
            STATE = bootstrap_state(
                domain,
                mode=run_mode,
                operator_task=task_text,
                autonomy_mode=autonomy_text,
                llm_provider=provider_text,
                llm_base_url=base_text,
                llm_api_key_env=api_key_env_text,
            )
            console.print(f"[bold green]New session[/] for [bold]{STATE.domain}[/]")
    else:
        STATE = bootstrap_state(
            domain,
            mode=run_mode,
            operator_task=task_text,
            autonomy_mode=autonomy_text,
            llm_provider=provider_text,
            llm_base_url=base_text,
            llm_api_key_env=api_key_env_text,
        )
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
    registry.register("attack_surface_review", tool_attack_surface_review)
    registry.register("parameter_tamper", tool_parameter_tamper)
    registry.register("parameter_scan", tool_parameter_tamper)
    # Terminal & tool install
    registry.register("nmap", tool_nmap)
    registry.register("nuclei", tool_nuclei)
    registry.register("sqlmap", tool_sqlmap)
    registry.register("whatweb", tool_whatweb)
    registry.register("nikto", tool_nikto)
    registry.register("gobuster", tool_gobuster)
    registry.register("ffuf", tool_ffuf)
    registry.register("subfinder", tool_subfinder)
    registry.register("httpx", tool_httpx)
    registry.register("wafw00f", tool_wafw00f)
    registry.register("enum4linux", tool_enum4linux)
    registry.register("snmpwalk", tool_snmpwalk)
    registry.register("run", tool_run_command)
    registry.register("run_command", tool_run_command)
    registry.register("install", tool_install)
    registry.register("install_tool", tool_install_tool)
    registry.register("ask_user", tool_ask_user)
    # Browser & lighthouse
    registry.register("playwright", tool_playwright)
    registry.register("playwright_screenshot", tool_playwright_screenshot)
    registry.register("playwright_extract", tool_playwright_extract)
    registry.register("lighthouse_audit", tool_lighthouse_audit)
    registry.register("lighthouse", tool_lighthouse_audit)
    # Status & reporting
    registry.register("site_snapshot", lambda: tool_site_snapshot())
    registry.register("site_map", tool_site_map)
    registry.register("security_check", tool_security_check)
    registry.register("write_report", tool_write_report)
    registry.register("write_json_report", tool_write_json_report)
    registry.register("write_markdown_report", tool_write_markdown_report)
    registry.register("write_markdown_summary", tool_write_markdown_summary)
    registry.register("write_html_report", tool_write_html_report)

    # Deterministic kickoff
    if len(STATE.pages) == 0 and len(STATE.recent_events) == 0:
        mode = getattr(run_agent, '_mode', 'web')
        if mode == "network":
            network_kickoff(registry)
        else:
            deterministic_kickoff(registry)
        STATE.checkpoint(cp)
        _persist_workspace_session()

    # LLM-driven loop
    ui_phase("LLM Phase")
    mode = run_mode
    sys_prompt = build_network_system_prompt() if mode == "network" else build_system_prompt()

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
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": build_user_prompt(STATE)},
            ])
            llm_dur = time.time() - t0

            action = str(decision.get("action", "")).strip().lower()
            if action == "tool":
                tool_name = str(decision.get("tool", "")).strip()
                if (not tool_name or any(ch.isspace() for ch in tool_name)
                        or tool_name.startswith("/")):
                    decision = {
                        "action": "summarize",
                        "summary": f"Invalid tool requested: {tool_name or '<missing>'}",
                    }
                    action = "summarize"
                else:
                    decision["tool"] = tool_name
            elif _llm_decision_needs_fallback(decision):
                fallback = _fallback_decision_from_state()
                if fallback:
                    decision = fallback
                    action = "tool"
                    decision["action"] = "tool"
                    decision.setdefault(
                        "why",
                        "Fallback after malformed LLM response.",
                    )
            why = str(
                decision.get("why")
                or decision.get("reason")
                or decision.get("summary")
                or ""
            )
            ui_llm(action, why[:80], llm_dur)

            STATE.recent_events.append({
                "type": "decision", "step": STATE.step, "data": decision,
            })

            if action == "tool":
                tool_name = decision.get("tool", "")
                args = decision.get("args", {}) or {}
                sig = f"{tool_name}:{json.dumps(args, sort_keys=True)}"

                if sig in STATE.recent_tool_signatures[-6:]:
                    repeat_count = _bump_repeat_count(sig)
                    block_note = f"Repeated action ({repeat_count}x): {sig}."
                    autonomy_mode = getattr(STATE, "autonomy_mode", "free")
                    STATE.notes.append(block_note)
                    STATE.recent_events.append({
                        "type": "repeat_observed" if autonomy_mode == "free" else "blocked_action",
                        "step": STATE.step,
                        "tool": tool_name,
                        "signature": sig,
                        "repeat_count": repeat_count,
                        "note": block_note,
                    })
                    if autonomy_mode == "free":
                        console.print(
                            f"  [dim]⤳ repeated action allowed in free autonomy mode[/]")
                    else:
                        console.print(
                            f"  [dim]⤳ skipped (duplicate action)[/]")
                        if repeat_count >= 2:
                            summarize_memory()
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

                detail = (
                    args.get("url", "")
                    or args.get("target", "")
                    or args.get("package", "")
                    or args.get("source", "")
                    or args.get("destination", "")
                )
                ui_tool(tool_name, detail,
                        result.ok, result.duration_s, summary)

                STATE.recent_events.append({
                    "type": "tool_result", "step": STATE.step,
                    "tool": tool_name, "ok": result.ok,
                    "output": limited_event(result.output),
                    "error": limited_event(result.error),
                    "duration_s": result.duration_s,
                })

            elif action == "summarize":
                STATE.notes.append(str(decision.get("summary", "")))

            elif action == "finish":
                STATE.notes.append(
                    f"Finished: {decision.get('reason', '')}")
                console.print("  [bold green]Finishing up…[/]")
                summarize_memory()
                json_report = registry.call("write_json_report")
                ui_tool("write_json_report", str(JSON_REPORT),
                        json_report.ok, json_report.duration_s,
                        "saved" if json_report.ok else json_report.error[:80])
                if not json_report.ok:
                    console.print(f"  [red]write_json_report failed: {json_report.error}[/]")
                md_report = registry.call("write_markdown_summary")
                ui_tool("write_markdown_summary", str(MD_REPORT),
                        md_report.ok, md_report.duration_s,
                        "saved" if md_report.ok else md_report.error[:80])
                if not md_report.ok:
                    console.print(f"  [red]write_markdown_summary failed: {md_report.error}[/]")
                html_report = registry.call("write_html_report")
                ui_tool("write_html_report", str(HTML_REPORT),
                        html_report.ok, html_report.duration_s,
                        "saved" if html_report.ok else html_report.error[:80])
                if not html_report.ok:
                    console.print(f"  [red]write_html_report failed: {html_report.error}[/]")
                STATE.checkpoint(cp)
                _persist_workspace_session()
                ui_done(time.time() - agent_start)
                _close_browser()
                return

            else:
                STATE.notes.append(f"Unknown action: {decision}")

            # Periodic memory summary
            if STATE.step % 4 == 0:
                summarize_memory()

            STATE.checkpoint(cp)
            _persist_workspace_session()

    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]⚠ Interrupted — saving checkpoint…[/]")
        if STATE:
            STATE.checkpoint(cp)
            _persist_workspace_session()
        _close_browser()
        return

    # Budget exhausted
    assert STATE is not None
    console.print("\n[bold yellow]Step budget reached — writing reports…[/]")
    summarize_memory()
    json_report = registry.call("write_json_report")
    md_report = registry.call("write_markdown_summary")
    html_report = registry.call("write_html_report")
    if not json_report.ok:
        console.print(f"  [red]write_json_report failed: {json_report.error}[/]")
    if not md_report.ok:
        console.print(f"  [red]write_markdown_summary failed: {md_report.error}[/]")
    if not html_report.ok:
        console.print(f"  [red]write_html_report failed: {html_report.error}[/]")
    STATE.checkpoint(cp)
    _persist_workspace_session()
    ui_done(time.time() - agent_start)
    _close_browser()


# ═══════════════════════════════════════════════════════════
#  INTERACTIVE STARTUP
# ═══════════════════════════════════════════════════════════
def interactive_startup(
    default_target: str = "",
    default_mode: str = "web",
    default_profile: str = "standard",
    default_task: str = "",
    default_model: str = DEFAULT_MODEL,
    default_autonomy: str = "free",
    default_provider: str = DEFAULT_PROVIDER,
    default_api_base: str = DEFAULT_API_BASE,
    default_api_key_env: str = DEFAULT_API_KEY_ENV,
    default_fresh: bool = False,
) -> Tuple[str, str, str, bool, str, str, str, str, str, str]:
    """Interactive menu. Returns (target, profile, mode, fresh, task, model, autonomy, provider, api_base, api_key_env)."""
    console.print(_ASCII_BANNER)
    console.print(Panel(
        "[bold]Autonomous Pentest Agent[/]\n"
        "[dim]Authorized penetration testing only. You must have explicit\n"
        "permission to test the target domain or network.[/]",
        border_style="bright_red", padding=(1, 2),
    ))
    mode = Prompt.ask(
        "\n[bold]Mode[/]",
        choices=["web", "network"],
        default=default_mode,
    )
    if mode == "network":
        subnets = _detect_local_subnets()
        if subnets:
            console.print(f"  [dim]Detected subnets:[/] {', '.join(subnets)}")
        raw = Prompt.ask(
            "[bold]Target (subnet CIDR or 'auto')[/]",
            default=(default_target.strip() or "auto"),
        )
    else:
        target_default = default_target.strip()
        raw = Prompt.ask("[bold]Target domain[/]", default=target_default)
        while not raw.strip():
            console.print("  [yellow]Target is required to start a pentest run.[/]")
            raw = Prompt.ask("[bold]Target domain[/]", default=target_default)
    target = raw.strip()
    provider = Prompt.ask(
        "[bold]LLM provider[/]",
        choices=["ollama", "local", "api", "openai-compatible"],
        default=default_provider,
    ).strip().lower()
    provider = "ollama" if provider == "local" else provider
    model = Prompt.ask(
        "[bold]Model[/] [dim](recommended: qwen3-coder:30b; any Ollama tag works)[/]",
        default=default_model,
    ).strip()
    api_base = ""
    api_key_env = default_api_key_env
    if provider in {"api", "openai-compatible"}:
        api_base = Prompt.ask(
            "[bold]API base URL[/] [dim](OpenAI-compatible endpoint)[/]",
            default=default_api_base or "https://api.openai.com",
        ).strip()
        api_key_env = Prompt.ask(
            "[bold]API key env var[/] [dim](name of the env var holding your key)[/]",
            default=default_api_key_env,
        ).strip() or default_api_key_env
    profile = Prompt.ask(
        "[bold]Scan profile[/]",
        choices=["quick", "standard", "deep"],
        default=default_profile,
    )
    task = Prompt.ask(
        "[bold]Operator mission[/] [dim](optional; broad authorized objective; separate multiple items with semicolons)[/]",
        default=default_task,
    ).strip()
    autonomy = Prompt.ask(
        "[bold]Autonomy[/] [dim](free or balanced; free lets the agent choose its own path)[/]",
        choices=["free", "balanced"],
        default=default_autonomy,
    ).strip()
    fresh = not Confirm.ask(
        "[bold]Resume from checkpoint if available?[/]", default=not default_fresh
    )
    console.print()
    return target, profile, mode, fresh, task, model, autonomy, provider, api_base, api_key_env


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    _runtime_defaults = WORKSPACE.load_runtime()
    _domain = str(_runtime_defaults.get("target", DEFAULT_DOMAIN) or DEFAULT_DOMAIN)
    _resume = True
    _fresh = False
    _cli = False
    _has_explicit_target = False
    _mode = "web"
    _profile = str(_runtime_defaults.get("profile", "standard") or "standard")
    _task = str(_runtime_defaults.get("mission", "") or "")
    _model = DEFAULT_MODEL
    _autonomy = str(_runtime_defaults.get("autonomy", "free") or "free")
    _provider = str(_runtime_defaults.get("provider", DEFAULT_PROVIDER) or DEFAULT_PROVIDER)
    _api_base = str(_runtime_defaults.get("api_base", DEFAULT_API_BASE) or DEFAULT_API_BASE)
    _api_key_env = str(_runtime_defaults.get("api_key_env", DEFAULT_API_KEY_ENV) or DEFAULT_API_KEY_ENV)
    _dashboard = True if _runtime_defaults.get("open_dashboard", True) else False
    _command = ""
    _args = sys.argv[1:]
    i = 0
    while i < len(_args):
        arg = _args[i]
        if arg == "--resume":
            _resume = True
            _cli = True
        elif arg == "--fresh":
            _fresh = True
            _cli = True
        elif arg == "--network":
            _mode = "network"
            _cli = True
        elif arg == "--model" and i + 1 < len(_args):
            _model = _args[i + 1]
            _cli = True
            i += 1
        elif arg.startswith("--model="):
            _model = arg.split("=", 1)[1]
            _cli = True
        elif arg == "--free":
            _autonomy = "free"
            _cli = True
        elif arg == "--balanced":
            _autonomy = "balanced"
            _cli = True
        elif arg == "--autonomy" and i + 1 < len(_args):
            _autonomy = _args[i + 1]
            _cli = True
            i += 1
        elif arg.startswith("--autonomy="):
            _autonomy = arg.split("=", 1)[1]
            _cli = True
        elif arg == "--provider" and i + 1 < len(_args):
            _provider = _args[i + 1]
            _cli = True
            i += 1
        elif arg.startswith("--provider="):
            _provider = arg.split("=", 1)[1]
            _cli = True
        elif arg in {"--local", "--ollama"}:
            _provider = "ollama"
            _cli = True
        elif arg in {"--api", "--openai-compatible"}:
            _provider = "openai-compatible"
            _cli = True
        elif arg == "--dashboard":
            _dashboard = True
            _cli = True
        elif arg == "--no-dashboard":
            _dashboard = False
            _cli = True
        elif arg in {"dashboard", "onboard", "doctor", "skills"} and not _command:
            _command = arg
            _cli = True
        elif arg == "--api-base" and i + 1 < len(_args):
            _api_base = _args[i + 1]
            _cli = True
            i += 1
        elif arg.startswith("--api-base="):
            _api_base = arg.split("=", 1)[1]
            _cli = True
        elif arg == "--api-key-env" and i + 1 < len(_args):
            _api_key_env = _args[i + 1]
            _cli = True
            i += 1
        elif arg.startswith("--api-key-env="):
            _api_key_env = arg.split("=", 1)[1]
            _cli = True
        elif arg in {"--task", "--mission", "--objective"} and i + 1 < len(_args):
            _task = _args[i + 1]
            _cli = True
            i += 1
        elif arg.startswith("--task=") or arg.startswith("--mission=") or arg.startswith("--objective="):
            _task = arg.split("=", 1)[1]
            _cli = True
        elif not arg.startswith("-"):
            _domain = arg
            _cli = True
            _has_explicit_target = True
        i += 1

    GATEWAY = PentGateway(
        workspace=WORKSPACE,
        skill_catalog=SKILL_CATALOG,
        dashboard_port=WORKSPACE.dashboard_port,
    )
    WORKSPACE.save_runtime({
        "provider": _provider,
        "model": _model,
        "autonomy": _autonomy,
        "mission": _task,
        "mode": _mode,
        "target": _domain,
        "profile": _profile,
        "api_base": _api_base,
        "api_key_env": _api_key_env,
        "open_dashboard": _dashboard,
    })
    dashboard_url = GATEWAY.dashboard_url
    if _command not in {"doctor", "skills"}:
        dashboard_url = GATEWAY.start_dashboard(open_browser=_dashboard)
    print(f"[platform] Dashboard endpoint: {dashboard_url}")

    if _command in {"doctor", "skills"}:
        if _command == "doctor":
            console.print(Panel(
                "\n".join([
                    f"[bold]Workspace:[/] {WORKSPACE.root}",
                    f"[bold]Agent:[/] {WORKSPACE.agent_id}",
                    f"[bold]Dashboard:[/] {dashboard_url}",
                    f"[bold]Model:[/] {_model}",
                    f"[bold]Provider:[/] {_provider}",
                    f"[bold]Autonomy:[/] {_autonomy}",
                    f"[bold]Skill packs:[/] {len(SKILL_CATALOG)}",
                ]),
                title="[bold]PentAgent Doctor[/]",
                border_style="bright_blue",
                padding=(1, 2),
            ))
        else:
            console.print(Panel(
                "\n".join(skill_overview_lines(SKILL_CATALOG)),
                title="[bold]PentAgent Skills[/]",
                border_style="bright_blue",
                padding=(1, 2),
            ))
        raise SystemExit(0)

    if _command in {"dashboard", "onboard"} and not _has_explicit_target:
        console.print(
            Panel(
                f"[bold]Browser dashboard[/] is running at [bold]{dashboard_url}[/]\n"
                f"Use the workspace form to adjust defaults, then relaunch with a target when ready.",
                border_style="bright_blue",
                padding=(1, 2),
            )
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            GATEWAY.stop_dashboard()
        raise SystemExit(0)

    if not _has_explicit_target:
        # Interactive launcher when the user did not choose a target explicitly.
        _domain, _profile, _mode, _fresh, _task, _model, _autonomy, _provider, _api_base, _api_key_env = interactive_startup(
            default_target=_domain,
            default_mode=_mode,
            default_profile=_profile,
            default_task=_task,
            default_model=_model,
            default_autonomy=_autonomy,
            default_provider=_provider,
            default_api_base=_api_base,
            default_api_key_env=_api_key_env,
            default_fresh=_fresh,
        )
        p = SCAN_PROFILES.get(_profile, SCAN_PROFILES["standard"])
        MAX_STEPS = p["max_steps"]
        BOOTSTRAP_BATCH = p["batch"]
        run_agent._profile = _profile  # type: ignore
    run_agent._mode = _mode  # type: ignore
    run_agent._task = _task  # type: ignore
    run_agent._autonomy = _autonomy  # type: ignore
    run_agent._provider = _provider  # type: ignore
    run_agent._api_base = _api_base  # type: ignore
    run_agent._api_key_env = _api_key_env  # type: ignore
    MODEL = _model.strip() or DEFAULT_MODEL
    MODEL_PROVIDER = _provider.strip().lower() or DEFAULT_PROVIDER
    MODEL_API_BASE = _api_base.strip()
    MODEL_API_KEY_ENV = _api_key_env.strip() or DEFAULT_API_KEY_ENV
    print(f"[bootstrap] Selected model: {MODEL}")
    if _provider.strip().lower() in {"ollama", "local"}:
        if importlib.util.find_spec("ollama") is None:
            print("[bootstrap] Installing ollama Python client …")
            _pip_install("ollama")
        _OL_OK, _OL_MSG = _bootstrap_ollama(MODEL)
        if not _OL_OK:
            print(f"[FATAL] Ollama: {_OL_MSG}")
            sys.exit(1)
    _configure_llm_backend(
        _provider,
        MODEL,
        api_base=_api_base,
        api_key_env=_api_key_env,
    )
    WORKSPACE.save_runtime({
        "provider": _provider,
        "model": MODEL,
        "autonomy": _autonomy,
        "mission": _task,
        "mode": _mode,
        "target": _domain,
        "profile": _profile,
        "api_base": _api_base,
        "api_key_env": _api_key_env,
        "open_dashboard": _dashboard,
    })
    if _mode == "network":
        run_agent(
            _domain,
            resume=not _fresh,
            fresh=_fresh,
            operator_task=_task,
            autonomy_mode=_autonomy,
            llm_provider=_provider,
            llm_base_url=_api_base,
            llm_api_key_env=_api_key_env,
        )
    else:
        run_agent(
            _domain,
            resume=not _fresh,
            fresh=_fresh,
            operator_task=_task,
            autonomy_mode=_autonomy,
            llm_provider=_provider,
            llm_base_url=_api_base,
            llm_api_key_env=_api_key_env,
        )
