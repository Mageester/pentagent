from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _preview(text: str, limit: int = 260) -> str:
    stripped = (text or "").strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[: max(0, limit - 3)].rstrip() + "..."


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _kind(event: Dict[str, Any]) -> str:
    return str(event.get("kind", "")).lower()


def _compact_event(event: Dict[str, Any]) -> Dict[str, Any]:
    kind = _kind(event)
    if kind == "command":
        return {
            "kind": kind,
            "ts": event.get("ts"),
            "command": event.get("command", ""),
            "language": event.get("language", ""),
            "cwd": event.get("cwd", ""),
            "metadata": event.get("metadata", {}),
        }
    if kind == "result":
        return {
            "kind": kind,
            "ts": event.get("ts"),
            "command": event.get("command", ""),
            "returncode": event.get("returncode"),
            "cwd": event.get("cwd", ""),
            "stdout": event.get("stdout", ""),
            "stderr": event.get("stderr", ""),
            "metadata": event.get("metadata", {}),
        }
    if kind in {"stdout_line", "stderr_line"}:
        return {
            "kind": kind,
            "ts": event.get("ts"),
            "command": event.get("command", ""),
            "cwd": event.get("cwd", ""),
            "line": event.get("line", ""),
            "metadata": event.get("metadata", {}),
        }
    if kind == "message":
        return {
            "kind": kind,
            "ts": event.get("ts"),
            "role": event.get("role", ""),
            "content": event.get("content", ""),
            "metadata": event.get("metadata", {}),
        }
    return {
        "kind": kind or "event",
        "ts": event.get("ts"),
        "data": event,
    }


def _render_tail(events: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for event in events:
        kind = _kind(event)
        if kind == "command":
            language = _stringify(event.get("language") or "shell")
            cwd = _stringify(event.get("cwd"))
            command = _stringify(event.get("command"))
            lines.append(f"[command] {language} cwd={cwd}")
            lines.append(command)
        elif kind == "result":
            rc = event.get("returncode")
            stdout = _stringify(event.get("stdout")).rstrip()
            stderr = _stringify(event.get("stderr")).rstrip()
            lines.append(f"[returncode] {rc}")
            if stdout:
                lines.append(stdout)
            if stderr:
                lines.append(stderr)
        elif kind in {"stdout_line", "stderr_line"}:
            lines.append(f"[{kind}] {_stringify(event.get('line'))}")
        elif kind == "message":
            role = _stringify(event.get("role") or "assistant")
            content = _preview(_stringify(event.get("content")), 360)
            lines.append(f"[message] {role}: {content}")
    return _preview("\n".join(lines).strip(), 8000)


def _last_result(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for event in reversed(events):
        if _kind(event) == "result":
            return event
    return None


@dataclass
class JournalingEngine:
    project_root: Path | str
    filename: str = ".vanguard_journal.json"
    max_history_events: int = 160
    _snapshot: Dict[str, Any] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.project_root = Path(self.project_root).expanduser().resolve()
        self.journal_path = self.project_root / self.filename
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)

    def exists(self) -> bool:
        return self.journal_path.exists()

    def load(self) -> Dict[str, Any] | None:
        if not self.journal_path.exists():
            return None
        try:
            data = json.loads(self.journal_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        self._snapshot = data
        return data

    def save(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        data = dict(snapshot)
        data.setdefault("journal_version", 1)
        data.setdefault("updated_at", _now_iso())
        data.setdefault("project_root", str(self.project_root))
        temp_path = self.journal_path.with_suffix(self.journal_path.suffix + ".tmp")
        temp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.journal_path)
        self._mark_hidden()
        self._snapshot = data
        return data

    def clear(self) -> None:
        try:
            if self.journal_path.exists():
                self.journal_path.unlink()
        except Exception:
            pass
        self._snapshot = None

    def _mark_hidden(self) -> None:
        if os.name != "nt":
            return
        try:
            subprocess.run(
                ["attrib", "+h", str(self.journal_path)],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception:
            pass

    def build_snapshot(
        self,
        *,
        objective: str,
        session_id: str,
        iteration: int,
        kernel_history: List[Dict[str, Any]],
        current_terminal_state: str,
        progress: Optional[Dict[str, Any]] = None,
        provider: str = "",
        model: str = "",
        cwd: str = "",
        status: str = "active",
    ) -> Dict[str, Any]:
        history_tail = list(kernel_history[-self.max_history_events :])
        commands = [_compact_event(event) for event in history_tail if _kind(event) == "command"]
        outputs = [
            _compact_event(event)
            for event in history_tail
            if _kind(event) in {"result", "stdout_line", "stderr_line"}
        ]
        last_result = _last_result(history_tail)
        last_error = ""
        last_returncode = None
        if last_result is not None:
            last_returncode = last_result.get("returncode")
            stderr = _stringify(last_result.get("stderr")).strip()
            stdout = _stringify(last_result.get("stdout")).strip()
            if last_returncode not in (0, None) or stderr:
                last_error = stderr or stdout

        progress_data = dict(progress or {})
        progress_data.setdefault("iteration", iteration)
        progress_data.setdefault("status", status)
        progress_data.setdefault("command_count", len(commands))
        progress_data.setdefault("output_count", len(outputs))
        progress_data.setdefault("last_command", commands[-1]["command"] if commands else "")
        progress_data.setdefault("last_returncode", last_returncode)
        progress_data.setdefault("last_error", _preview(last_error, 1200))
        progress_data.setdefault("current_heuristic", "")
        progress_data.setdefault("last_command_failed", bool(last_result and (last_returncode not in (0, None) or bool(last_error))))

        unified_context = {
            "commands": commands,
            "outputs": outputs,
            "history_tail": [_compact_event(event) for event in history_tail],
            "current_terminal_state": current_terminal_state,
        }

        snapshot = {
            "session_id": session_id,
            "objective": objective,
            "provider": provider,
            "model": model,
            "cwd": cwd,
            "iteration": iteration,
            "status": status,
            "current_goal_progress": progress_data,
            "unified_context": unified_context,
        }
        snapshot["resume_context"] = self.resume_context(snapshot)
        return snapshot

    def resume_context(self, snapshot: Optional[Dict[str, Any]] = None) -> str:
        data = snapshot or self._snapshot or self.load()
        if not data:
            return ""

        progress = data.get("current_goal_progress") or {}
        context = data.get("unified_context") or {}
        history_tail = context.get("history_tail") or []
        lines = [
            "Resuming from hidden Vanguard journal.",
            f"Session ID: {_stringify(data.get('session_id'))}",
            f"Objective: {_stringify(data.get('objective'))}",
            f"Iteration: {_stringify(progress.get('iteration', data.get('iteration')))}",
            f"Status: {_stringify(progress.get('status', data.get('status', 'active')))}",
        ]

        last_command = _stringify(progress.get("last_command"))
        if last_command:
            lines.append(f"Last command: {last_command}")
        last_error = _stringify(progress.get("last_error"))
        if last_error:
            lines.append(f"Last error: {last_error}")
        last_response = _stringify(progress.get("last_response"))
        if last_response:
            lines.append(f"Last model response: {_preview(last_response, 500)}")
        current_heuristic = _stringify(progress.get("current_heuristic"))
        if current_heuristic:
            lines.append(f"Last heuristic: {_preview(current_heuristic, 300)}")

        if history_tail:
            lines.append("Previous history tail:")
            lines.append(_render_tail(history_tail))

        return "\n".join(lines).strip()
