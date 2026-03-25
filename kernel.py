from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _preview(text: str, limit: int = 220) -> str:
    stripped = (text or "").strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[: max(0, limit - 3)].rstrip() + "..."


_CODE_BLOCK_RE = re.compile(
    r"```(?P<language>[A-Za-z0-9_+\-]*)[ \t]*\r?\n(?P<code>.*?)```",
    re.S,
)


def extract_code_blocks(text: str) -> List[Tuple[str, str]]:
    blocks: List[Tuple[str, str]] = []
    for match in _CODE_BLOCK_RE.finditer(text or ""):
        language = (match.group("language") or "").strip().lower()
        code = (match.group("code") or "").rstrip()
        if not language:
            language = _guess_code_language(code)
        blocks.append((language, code))
    return blocks


def _guess_code_language(code: str) -> str:
    stripped = (code or "").lstrip()
    if not stripped:
        return "bash"
    first_line = stripped.splitlines()[0].strip().lower()
    if first_line.startswith("#!/"):
        if "python" in first_line:
            return "python"
        return "bash"
    python_markers = (
        "import ",
        "from ",
        "def ",
        "class ",
        "print(",
        "async def ",
        "if __name__ ==",
    )
    if first_line.startswith(python_markers) or any(
        marker in stripped for marker in python_markers
    ):
        return "python"
    return "bash"


def _build_exec_command(language: str, code: str) -> Tuple[List[str], str]:
    lang = (language or "").strip().lower()
    if lang in {"python", "py"}:
        return [sys.executable, "-u", "-c", code], "python"
    if shutil.which("bash"):
        return ["bash", "-lc", code], "bash"
    if shutil.which("wsl"):
        return ["wsl", "bash", "-lc", code], "bash"
    if shutil.which("sh"):
        return ["sh", "-lc", code], "bash"
    return [sys.executable, "-u", "-c", code], "python"


@dataclass
class Kernel:
    history_path: Path
    session_id: str | None = None
    history: List[Dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.history_path = Path(self.history_path).expanduser().resolve()
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        self.session_id = (self.session_id or uuid.uuid4().hex)
        self._load()

    def _load(self) -> None:
        if not self.history_path.exists():
            return
        try:
            with self.history_path.open("r", encoding="utf-8") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict):
                            event_session_id = str(data.get("session_id") or "").strip()
                            if self.session_id and event_session_id and event_session_id != self.session_id:
                                continue
                            if self.session_id and not event_session_id:
                                continue
                            self.history.append(data)
                    except Exception:
                        self.history.append({
                            "ts": _now_iso(),
                            "kind": "load_error",
                            "raw": line,
                        })
        except Exception:
            return

    def clear(self) -> None:
        with self._lock:
            self.history.clear()
            try:
                self.history_path.write_text("", encoding="utf-8")
            except Exception:
                pass

    def _append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        data = dict(event)
        data.setdefault("ts", _now_iso())
        data.setdefault("session_id", self.session_id)
        with self._lock:
            self.history.append(data)
            with self.history_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(data, ensure_ascii=False) + "\n")
        return data

    def record_message(self, role: str, content: str, *, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._append({
            "kind": "message",
            "role": (role or "").strip().lower() or "assistant",
            "content": content,
            "metadata": metadata or {},
        })

    def record_command(
        self,
        command: str,
        *,
        language: str = "shell",
        cwd: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._append({
            "kind": "command",
            "command": command,
            "language": language,
            "cwd": cwd,
            "metadata": metadata or {},
        })

    def record_stream_line(
        self,
        command: str,
        stream: str,
        line: str,
        *,
        cwd: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._append({
            "kind": f"{stream}_line",
            "command": command,
            "cwd": cwd,
            "line": line,
            "metadata": metadata or {},
        })

    def record_result(
        self,
        command: str,
        returncode: int | None,
        *,
        cwd: str = "",
        stdout: str = "",
        stderr: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._append({
            "kind": "result",
            "command": command,
            "cwd": cwd,
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "metadata": metadata or {},
        })

    def tail(self, count: int = 40) -> List[Dict[str, Any]]:
        if count <= 0:
            return []
        return self.history[-count:]

    def context_text(self, *, max_events: int = 120, max_chars: int = 12000) -> str:
        items = self.tail(max_events)
        lines: List[str] = []
        total = 0
        for event in items:
            kind = str(event.get("kind", "event"))
            ts = _stringify(event.get("ts"))
            if kind == "message":
                role = _stringify(event.get("role") or "assistant")
                content = _stringify(event.get("content"))
                rendered = f"[{ts}] {role}: {content}"
            elif kind == "command":
                lang = _stringify(event.get("language") or "shell")
                cwd = _stringify(event.get("cwd"))
                command = _stringify(event.get("command"))
                rendered = f"[{ts}] command({lang}) cwd={cwd}: {command}"
            elif kind in {"stdout_line", "stderr_line"}:
                rendered = f"[{ts}] {kind[:-5]}: {_stringify(event.get('line'))}"
            elif kind == "result":
                parts = []
                stdout_preview = _preview(_stringify(event.get("stdout")))
                stderr_preview = _preview(_stringify(event.get("stderr")))
                if stdout_preview:
                    parts.append(stdout_preview)
                if stderr_preview:
                    parts.append(stderr_preview)
                rendered = f"[{ts}] result rc={event.get('returncode')}: " + " | ".join(parts)
            else:
                rendered = f"[{ts}] {kind}: {_preview(json.dumps(event, ensure_ascii=False))}"
            rendered = rendered.strip()
            if not rendered:
                continue
            lines.append(rendered)
            total += len(rendered) + 1
            if total >= max_chars:
                break
        return "\n".join(lines)

    def execute_code_block(
        self,
        language: str,
        code: str,
        *,
        cwd: str | Path | None = None,
        timeout: int | float | None = None,
        env: Optional[Dict[str, str]] = None,
        on_stream: Optional[Callable[[str, str], None]] = None,
    ) -> Dict[str, Any]:
        command, normalized_language = _build_exec_command(language, code)
        cwd_text = str(cwd) if cwd is not None else ""
        self.record_command(
            " ".join(command),
            language=normalized_language,
            cwd=cwd_text,
            metadata={"source_language": language, "code": code},
        )

        start = time.time()
        proc = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        stdout_closed = threading.Event()
        stderr_closed = threading.Event()

        def pump(stream_name: str, pipe: Any, sink: List[str], closed: threading.Event) -> None:
            try:
                for raw_line in iter(pipe.readline, ""):
                    if raw_line == "":
                        break
                    line = raw_line.rstrip("\r\n")
                    sink.append(line)
                    self.record_stream_line(
                        " ".join(command),
                        stream_name,
                        line,
                        cwd=cwd_text,
                        metadata={"source_language": language},
                    )
                    if on_stream is not None:
                        on_stream(stream_name, line)
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass
                closed.set()

        threads = [
            threading.Thread(target=pump, args=("stdout", proc.stdout, stdout_lines, stdout_closed), daemon=True),
            threading.Thread(target=pump, args=("stderr", proc.stderr, stderr_lines, stderr_closed), daemon=True),
        ]
        for thread in threads:
            thread.start()

        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass

        for thread in threads:
            thread.join(timeout=5)

        duration_s = round(time.time() - start, 3)
        returncode = proc.returncode
        stdout_text = "\n".join(stdout_lines)
        stderr_text = "\n".join(stderr_lines)
        self.record_result(
            " ".join(command),
            returncode,
            cwd=cwd_text,
            stdout=stdout_text,
            stderr=stderr_text,
            metadata={
                "source_language": language,
                "normalized_language": normalized_language,
                "timed_out": timed_out,
                "duration_s": duration_s,
                "code": code,
            },
        )
        return {
            "command": " ".join(command),
            "language": normalized_language,
            "code": code,
            "returncode": returncode,
            "timed_out": timed_out,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "duration_s": duration_s,
            "cwd": cwd_text,
        }


def run_code_blocks(
    kernel: Kernel,
    text: str,
    *,
    cwd: str | Path | None = None,
    timeout: int | float | None = None,
    env: Optional[Dict[str, str]] = None,
    on_command: Optional[Callable[[str, str, str], None]] = None,
    on_stream: Optional[Callable[[str, str], None]] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for language, code in extract_code_blocks(text or ""):
        if on_command is not None:
            on_command(language, code, " ".join(_build_exec_command(language, code)[0]))
        results.append(
            kernel.execute_code_block(
                language,
                code,
                cwd=cwd,
                timeout=timeout,
                env=env,
                on_stream=on_stream,
            )
        )
    return results
