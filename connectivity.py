from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error, request
from urllib.parse import urlsplit


def _preview(text: str, limit: int = 260) -> str:
    stripped = (text or "").strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[: max(0, limit - 3)].rstrip() + "..."


_URL_RE = re.compile(
    r"(?P<url>(?:https?|ssh)://[^\s'\"<>]+)",
    re.IGNORECASE,
)
_HOST_RE = re.compile(
    r"\b(?P<host>(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}))(?:\:(?P<port>\d{1,5}))?\b",
    re.IGNORECASE,
)
_BRACKETED_IPV6_RE = re.compile(
    r"\[(?P<host>[0-9A-Fa-f:]+)\](?:\:(?P<port>\d{1,5}))?",
)


@dataclass
class SSHTarget:
    name: str
    host: str
    user: str = ""
    port: int = 22
    identity_file: str = ""


@dataclass
class APITarget:
    name: str
    base_url: str
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class ConnectivityManager:
    workspace_root: Path | str
    config_filename: str = "connectivity.json"
    ssh_targets: Dict[str, SSHTarget] = field(default_factory=dict, init=False)
    api_targets: Dict[str, APITarget] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root).expanduser().resolve()
        self.config_path = self.workspace_root / self.config_filename
        self._load_config()

    def _load_config(self) -> None:
        if not self.config_path.exists():
            return
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        for item in data.get("ssh", []) or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            host = str(item.get("host") or "").strip()
            if not name or not host:
                continue
            self.ssh_targets[name] = SSHTarget(
                name=name,
                host=host,
                user=str(item.get("user") or "").strip(),
                port=int(item.get("port") or 22),
                identity_file=str(item.get("identity_file") or "").strip(),
            )
        for item in data.get("api", []) or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            base_url = str(item.get("base_url") or "").strip()
            if not name or not base_url:
                continue
            self.api_targets[name] = APITarget(
                name=name,
                base_url=base_url.rstrip("/"),
                headers={str(k): str(v) for k, v in (item.get("headers") or {}).items()},
            )

    def discover_targets_from_text(self, text: str) -> List[str]:
        discovered: List[str] = []
        seen: set[str] = set()
        raw = text or ""
        if not raw.strip():
            return []

        def add(candidate: str) -> None:
            cleaned = (candidate or "").strip().rstrip(".,;:)]}>'\"")
            if not cleaned:
                return
            if cleaned.startswith(("http://", "https://", "ssh://")):
                try:
                    parsed = urlsplit(cleaned)
                except Exception:
                    return
                if not parsed.netloc:
                    return
                normalized = f"{parsed.scheme}://{parsed.netloc}"
            elif cleaned.startswith("[") and "]" in cleaned:
                host = cleaned[1:cleaned.index("]")]
                port = ""
                if ":" in cleaned[cleaned.index("]") + 1:]:
                    port = cleaned.split("]", 1)[1].lstrip(":")
                normalized = f"[{host}]"
                if port:
                    normalized = f"{normalized}:{port}"
            else:
                normalized = cleaned

            if normalized in seen:
                return
            if normalized.startswith("http://") or normalized.startswith("https://"):
                try:
                    parsed = urlsplit(normalized)
                    if parsed.hostname:
                        ip = ipaddress.ip_address(parsed.hostname)
                        _ = ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
                except ValueError:
                    pass
                except Exception:
                    pass
            seen.add(normalized)
            discovered.append(normalized)

        for match in _URL_RE.finditer(raw):
            add(match.group("url") or "")
        for match in _HOST_RE.finditer(raw):
            host = match.group("host") or ""
            port = match.group("port") or ""
            candidate = f"{host}:{port}" if port else host
            add(candidate)
        for match in _BRACKETED_IPV6_RE.finditer(raw):
            host = match.group("host") or ""
            port = match.group("port") or ""
            candidate = f"[{host}]"
            if port:
                candidate = f"{candidate}:{port}"
            add(candidate)

        return discovered[:24]

    def summary_text(self, terminal_text: str = "") -> str:
        discovered = self.discover_targets_from_text(terminal_text)
        lines = [
            "Dynamic Network Discovery (live stdout):",
            f"- discovered candidates: {len(discovered)}",
        ]
        if discovered:
            lines.append("- candidates: " + ", ".join(discovered))
            lines.append("- note: discovered hosts are surfaced from terminal output for the recursive loop to consider.")
        else:
            lines.append("- candidates: none")
        lines.append(f"Approved connectivity config: {self.config_path}")
        lines.append(f"Approved SSH targets: {len(self.ssh_targets)}")
        lines.append(f"Approved API targets: {len(self.api_targets)}")
        if self.ssh_targets:
            lines.append("SSH names: " + ", ".join(sorted(self.ssh_targets)))
        if self.api_targets:
            lines.append("API names: " + ", ".join(sorted(self.api_targets)))
        return "\n".join(lines)

    def run_ssh_command(
        self,
        target_name: str,
        command: str,
        *,
        timeout: float | None = None,
    ) -> Dict[str, Any]:
        target = self.ssh_targets[target_name]
        if not shutil.which("ssh"):
            return {
                "target": target_name,
                "returncode": 127,
                "stdout": "",
                "stderr": "ssh command not available",
            }
        destination = target.host
        if target.user:
            destination = f"{target.user}@{destination}"
        args = ["ssh", "-p", str(target.port)]
        if target.identity_file:
            args.extend(["-i", target.identity_file])
        args.append(destination)
        args.append(command)
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "target": target_name,
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
        }

    def call_api(
        self,
        target_name: str,
        path: str = "",
        *,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        target = self.api_targets[target_name]
        url = target.base_url.rstrip("/") + "/" + str(path or "").lstrip("/")
        req_headers = dict(target.headers)
        if headers:
            req_headers.update({str(k): str(v) for k, v in headers.items()})
        data = None
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                data = body.encode("utf-8")
            else:
                data = bytes(body)
        req = request.Request(url, data=data, method=method.upper(), headers=req_headers)
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read()
                return {
                    "target": target_name,
                    "url": url,
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                    "body": payload.decode("utf-8", errors="replace"),
                }
        except error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
            return {
                "target": target_name,
                "url": url,
                "status": exc.code,
                "headers": dict(exc.headers.items()) if exc.headers else {},
                "body": body_text,
                "error": str(exc),
            }
        except Exception as exc:
            return {
                "target": target_name,
                "url": url,
                "status": 0,
                "headers": {},
                "body": "",
                "error": str(exc),
            }


ConnectivityHandler = ConnectivityManager
