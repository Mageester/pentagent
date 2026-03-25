from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _preview(text: str, limit: int = 240) -> str:
    stripped = (text or "").strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[: max(0, limit - 3)].rstrip() + "..."


def _guess_language(code: str, declared: str) -> str:
    language = (declared or "").strip().lower()
    if language in {"python", "py"}:
        return "python"
    if language in {"bash", "sh"}:
        return "bash"
    first_line = (code or "").lstrip().splitlines()[:1]
    head = first_line[0].strip().lower() if first_line else ""
    if head.startswith("#!/") and "python" in head:
        return "python"
    if head.startswith(("#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/sh")):
        return "bash"
    python_markers = ("import ", "from ", "def ", "class ", "print(", "async def ", "if __name__ ==")
    if head.startswith(python_markers) or any(marker in (code or "") for marker in python_markers):
        return "python"
    return "bash"


def _to_wsl_path(path: Path) -> str:
    resolved = path.expanduser().resolve()
    drive = resolved.drive.rstrip(":").lower()
    tail = resolved.as_posix().split(":", 1)[-1]
    tail = tail.lstrip("/").replace("\\", "/")
    return f"/mnt/{drive}/{tail}"


def _build_command(language: str, script_path: Path) -> Tuple[list[str], str]:
    if language == "python":
        return [sys.executable, "-u", str(script_path)], "python"
    if shutil.which("bash"):
        return ["bash", str(script_path)], "bash"
    if shutil.which("wsl"):
        return ["wsl", "bash", _to_wsl_path(script_path)], "bash"
    if shutil.which("sh"):
        return ["sh", str(script_path)], "bash"
    return [sys.executable, "-u", str(script_path)], "python"


@dataclass
class ScriptRun:
    command: str
    script_path: str
    language: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "script_path": self.script_path,
            "language": self.language,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_s": self.duration_s,
            "timed_out": self.timed_out,
        }


@dataclass
class AdaptiveScriptEngine:
    workspace_root: Path | str
    scripts_dir_name: str = "scripts"
    max_retained_scripts: int = 64

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root).expanduser().resolve()
        self.scripts_root = self.workspace_root / self.scripts_dir_name
        self.scripts_root.mkdir(parents=True, exist_ok=True)

    def _script_suffix(self, language: str) -> str:
        return ".py" if language == "python" else ".sh"

    def _render_script(self, language: str, code: str) -> str:
        body = (code or "").rstrip() + "\n"
        if language == "python":
            if not body.lstrip().startswith("#!/"):
                return "#!/usr/bin/env python3\n" + body
            return body
        if not body.lstrip().startswith("#!/"):
            return "#!/usr/bin/env bash\nset -euo pipefail\n" + body
        return body

    def _make_script_path(self, language: str, code: str) -> Path:
        stamp = _now_stamp()
        digest = hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()[:12]
        return self.scripts_root / f"{stamp}_{digest}{self._script_suffix(language)}"

    def materialize(self, declared_language: str, code: str) -> Tuple[str, Path]:
        language = _guess_language(code, declared_language)
        path = self._make_script_path(language, code)
        path.write_text(self._render_script(language, code), encoding="utf-8")
        if os.name != "nt":
            try:
                path.chmod(0o700)
            except Exception:
                pass
        command, normalized = _build_command(language, path)
        return normalized, path

    def execute(
        self,
        declared_language: str,
        code: str,
        *,
        cwd: str | Path | None = None,
        env: Optional[Dict[str, str]] = None,
        timeout: float | None = None,
    ) -> ScriptRun:
        language = _guess_language(code, declared_language)
        normalized, script_path = self.materialize(language, code)
        command, normalized_language = _build_command(normalized, script_path)
        started = time.time()
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=timeout,
            check=False,
        )
        return ScriptRun(
            command=" ".join(command),
            script_path=str(script_path),
            language=normalized_language,
            returncode=result.returncode,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            duration_s=round(time.time() - started, 3),
            timed_out=False,
        )
