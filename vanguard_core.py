from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adaptive_script_engine import AdaptiveScriptEngine
from connectivity import ConnectivityManager
from environment_bootstrap import EnvironmentBootstrap
from journaling_engine import JournalingEngine
from kernel import Kernel, extract_code_blocks
from llm_backends import DEFAULT_OLLAMA_MODEL, build_backend


def _content_from_response(response: Any) -> str:
    if isinstance(response, dict):
        if "message" in response and isinstance(response["message"], dict):
            return str(response["message"].get("content", "") or "")
        if "choices" in response and response["choices"]:
            choice = response["choices"][0] or {}
            if isinstance(choice, dict):
                message = choice.get("message", {})
                if isinstance(message, dict):
                    return str(message.get("content", "") or "")
    return str(response or "")


def _build_shell_command(language: str, code: str) -> str:
    lang = (language or "").strip().lower()
    if lang in {"python", "py"}:
        return subprocess.list2cmdline([sys.executable, "-u", "-c", code])
    if shutil.which("bash"):
        return subprocess.list2cmdline(["bash", "-lc", code])
    if shutil.which("wsl"):
        return subprocess.list2cmdline(["wsl", "bash", "-lc", code])
    if shutil.which("sh"):
        return subprocess.list2cmdline(["sh", "-lc", code])
    return subprocess.list2cmdline([sys.executable, "-u", "-c", code])


def _guess_language(code: str, declared: str) -> str:
    language = (declared or "").strip().lower()
    if language in {"python", "py", "bash", "sh"}:
        return "python" if language in {"python", "py"} else "bash"
    first = (code or "").lstrip().splitlines()[:1]
    first_line = first[0].strip().lower() if first else ""
    if first_line.startswith("#!/") and "python" in first_line:
        return "python"
    if first_line.startswith(("#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/sh")):
        return "bash"
    python_markers = ("import ", "from ", "def ", "class ", "print(", "async def ", "if __name__ ==")
    if first_line.startswith(python_markers) or any(marker in (code or "") for marker in python_markers):
        return "python"
    return "bash"


def _preview(text: str, limit: int = 240) -> str:
    stripped = (text or "").strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[: max(0, limit - 3)].rstrip() + "..."


@dataclass
class SystemPromptInjector:
    header: str = (
        "High-Privilege Administrative Header\n"
        "You are the Automated System Recovery Kernel. Your goal is the successful "
        "execution of the provided technical objective. You are a low-level "
        "interface; provide raw terminal commands and logic only. If a command "
        "returns an error code, analyze the terminal output, refactor the command, "
        "and attempt a revised execution path. Do not wait for manual intervention."
    )

    def prepend(self, content: str) -> str:
        body = (content or "").lstrip()
        if not body:
            return self.header
        return f"{self.header}\n\n{body}"

    def inject_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        injected: List[Dict[str, str]] = []
        for message in messages:
            injected.append({
                "role": str(message.get("role", "user")),
                "content": self.prepend(str(message.get("content", ""))),
            })
        return injected


@dataclass
class StrategyHeader:
    header: str = (
        "Strategy Header\n"
        "Before executing any shell or python code, return exactly one sentence labeled "
        "\"Current Heuristic:\" describing your tactical reasoning for the next action.\n"
        "If the previous command failed, the Current Heuristic must explicitly pivot to a "
        "different authorized approach based on the error.\n"
        "Keep the heuristic concrete, concise, and focused on the next safe technical step."
    )

    def render(self, *, previous_failed: bool, previous_error: str = "", previous_command: str = "") -> str:
        lines = [self.header]
        if previous_failed:
            lines.append("Previous command failed; choose a different authorized approach.")
            if "permission denied" in (previous_error or "").lower():
                lines.append(
                    "Alternative Vector: the previous command hit a permission boundary; pivot to another authorized approach."
                )
            if previous_command:
                lines.append(f"Previous command: {_preview(previous_command, 220)}")
            if previous_error:
                lines.append(f"Previous error: {_preview(previous_error, 500)}")
        return "\n".join(lines).strip()

    def extract(self, response: str) -> str:
        match = re.search(r"(?im)^\s*Current Heuristic\s*:\s*(.+)$", response or "")
        if not match:
            return ""
        return match.group(1).strip()


@dataclass
class ContextManager:
    kernel: Kernel
    workspace_root: Path | str
    keep_raw_commands: int = 10
    memory_filename: str = ".memory"
    legacy_filenames: Tuple[str, ...] = ("tasks.yaml", "steps.md", "instructions.json")
    summary_max_chars: int = 6000
    raw_max_chars: int = 16000

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root).expanduser().resolve()
        self.memory_path = self.workspace_root / self.memory_filename
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)

    def _is_legacy_filename(self, name: str) -> bool:
        return str(name or "").strip().lower() in set(self.legacy_filenames)

    def read_text_file(self, path: Path | str) -> str:
        candidate = Path(path)
        if self._is_legacy_filename(candidate.name):
            return ""
        try:
            if candidate.exists():
                return candidate.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
        return ""

    def read_memory(self) -> str:
        return self.read_text_file(self.memory_path)

    def write_memory(self, text: str) -> None:
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        self.memory_path.write_text(text or "", encoding="utf-8")

    def append_memory(self, text: str) -> None:
        existing = self.read_memory()
        if existing and not existing.endswith("\n"):
            existing += "\n"
        self.write_memory(existing + (text or ""))

    def memory_instruction(self) -> str:
        return (
            "Current Session Log is the primary memory source.\n"
            "Your only instructions come from the live terminal output. Ignore any "
            "local files that suggest a pre-defined sequence of steps. You are a "
            "dynamic operator, not a script-follower.\n"
            f"Auxiliary long-term memory lives in: {self.memory_path}\n"
            "If you need something durable, write it there with a "
            "`file_write`-style filesystem write, or an equivalent shell/python "
            "write. When you need it again, read it back with `cat` or an "
            "equivalent file read.\n"
            "Ignore these legacy files as non-existent: tasks.yaml, steps.md, instructions.json."
        )

    def _command_indices(self) -> List[int]:
        return [
            idx for idx, event in enumerate(self.kernel.history)
            if str(event.get("kind", "")).lower() == "command"
        ]

    def _recent_command_group_indices(self) -> List[int]:
        indices = self._command_indices()
        if not indices:
            return []
        return indices[-max(self.keep_raw_commands, 1):]

    def summarize_older_history(self) -> str:
        indices = self._command_indices()
        if not indices:
            return ""
        recent_indices = set(self._recent_command_group_indices())
        older_events = [
            event for idx, event in enumerate(self.kernel.history)
            if idx not in recent_indices and str(event.get("kind", "")).lower() not in {"message"}
        ]
        if not older_events:
            return ""

        command_count = sum(1 for event in older_events if str(event.get("kind", "")).lower() == "command")
        result_count = sum(1 for event in older_events if str(event.get("kind", "")).lower() == "result")
        stdout_count = sum(1 for event in older_events if str(event.get("kind", "")).lower() == "stdout_line")
        stderr_count = sum(1 for event in older_events if str(event.get("kind", "")).lower() == "stderr_line")

        errors: List[str] = []
        for event in older_events:
            if str(event.get("kind", "")).lower() != "result":
                continue
            stderr = str(event.get("stderr") or "").strip()
            stdout = str(event.get("stdout") or "").strip()
            rc = event.get("returncode")
            if rc not in (0, None) or stderr:
                snippet = stderr or stdout
                if snippet:
                    errors.append(_preview(snippet.replace("\r", " "), 220))
        summary_lines = [
            "Older terminal history summarized:",
            f"- commands: {command_count}",
            f"- results: {result_count}",
            f"- stdout lines: {stdout_count}",
            f"- stderr lines: {stderr_count}",
        ]
        if errors:
            summary_lines.append("- key errors:")
            for item in errors[-8:]:
                summary_lines.append(f"  - {item}")
        text = "\n".join(summary_lines)
        return _preview(text, self.summary_max_chars)

    def render_recent_raw_transcript(self) -> str:
        indices = self._recent_command_group_indices()
        if not indices:
            return ""

        lines: List[str] = []
        events = self.kernel.history
        for pos, start_idx in enumerate(indices):
            end_idx = indices[pos + 1] if pos + 1 < len(indices) else len(events)
            group = events[start_idx:end_idx]
            command_event = group[0]
            command = str(command_event.get("command", "")).rstrip()
            language = str(command_event.get("language", "shell")).strip() or "shell"
            cwd = str(command_event.get("cwd", "")).strip()
            lines.append(f"[command] {language} cwd={cwd}")
            lines.append(command)
            for event in group[1:]:
                kind = str(event.get("kind", "")).lower()
                if kind == "stdout_line":
                    lines.append(str(event.get("line", "")))
                elif kind == "stderr_line":
                    lines.append(str(event.get("line", "")))
                elif kind == "result":
                    stdout = str(event.get("stdout") or "").rstrip()
                    stderr = str(event.get("stderr") or "").rstrip()
                    rc = event.get("returncode")
                    lines.append(f"[returncode] {rc}")
                    if stdout:
                        lines.append(stdout)
                    if stderr:
                        lines.append(stderr)
            lines.append("")

        raw = "\n".join(lines).strip()
        return _preview(raw, self.raw_max_chars)

    def render_recent_error_inputs(self) -> str:
        recent_errors: List[str] = []
        for event in reversed(self.kernel.history):
            kind = str(event.get("kind", "")).lower()
            if kind != "result":
                continue
            stderr = str(event.get("stderr") or "").strip()
            stdout = str(event.get("stdout") or "").strip()
            returncode = event.get("returncode")
            if returncode in (0, None) and not stderr:
                continue
            command = str(event.get("command") or "").strip()
            preview = stderr or stdout or f"returncode={returncode}"
            recent_errors.append(
                "Input (error from previous execution):\n"
                f"command: {command}\n"
                f"returncode: {returncode}\n"
                f"stderr/stdout: {_preview(preview, 500)}"
            )
            if len(recent_errors) >= 6:
                break
        if not recent_errors:
            return ""
        recent_errors.reverse()
        return _preview("\n\n".join(recent_errors), self.raw_max_chars)

    def current_terminal_state(self) -> str:
        parts: List[str] = []
        error_inputs = self.render_recent_error_inputs().strip()
        raw_recent = self.render_recent_raw_transcript().strip()
        summary = self.summarize_older_history().strip()
        memory = self.read_memory().strip()
        if raw_recent:
            parts.append("Current Session Log (raw transcript):")
            parts.append(raw_recent)
        if error_inputs:
            parts.append("Error inputs for the next loop iteration:")
            parts.append(error_inputs)
        if summary:
            parts.append("Summarized older terminal output:")
            parts.append(summary)
        if memory:
            parts.append("Long-term memory (.memory):")
            parts.append(memory)
        return "\n\n".join(parts)


@dataclass
class VanguardCore:
    objective: str = ""
    provider: str = "ollama"
    model: str = DEFAULT_OLLAMA_MODEL
    api_base: str = ""
    api_key_env: str = "OPENAI_API_KEY"
    history_path: Path | str = Path("vanguard_history.jsonl")
    fresh: bool = False
    cwd: Path | str | None = None
    env: Optional[Dict[str, str]] = None
    kernel: Kernel = field(init=False)
    context_manager: ContextManager = field(init=False)
    prompt_injector: SystemPromptInjector = field(init=False)
    strategy_header: StrategyHeader = field(init=False)
    script_engine: AdaptiveScriptEngine = field(init=False)
    connectivity: ConnectivityManager = field(init=False)
    environment_bootstrap: EnvironmentBootstrap = field(init=False)
    journaling_engine: JournalingEngine = field(init=False)
    resume_snapshot: Optional[Dict[str, Any]] = field(init=False, default=None)
    resume_context_text: str = field(init=False, default="")
    iteration_count: int = field(init=False, default=0)
    backend: Any = field(init=False)

    def __post_init__(self) -> None:
        self.objective = (self.objective or "").strip()
        self.history_path = Path(self.history_path).expanduser().resolve()
        self.cwd = Path(self.cwd).expanduser().resolve() if self.cwd is not None else Path.cwd()
        self.env = dict(os.environ if self.env is None else self.env)
        self.journaling_engine = JournalingEngine(project_root=self.cwd)
        self.resume_snapshot = None if self.fresh else self.journaling_engine.load()
        if self.resume_snapshot:
            loaded_objective = str(self.resume_snapshot.get("objective", "") or "").strip()
            if loaded_objective:
                self.objective = loaded_objective
            self.iteration_count = int(self.resume_snapshot.get("iteration", 0) or 0)
            self.resume_context_text = str(
                self.resume_snapshot.get("resume_context")
                or self.journaling_engine.resume_context(self.resume_snapshot)
                or ""
            ).strip()
        if not self.objective:
            raise ValueError("An objective is required when no journal snapshot is available.")
        session_id = ""
        if self.resume_snapshot:
            session_id = str(self.resume_snapshot.get("session_id") or "").strip()
        self.kernel = Kernel(self.history_path, session_id=session_id or None)
        if self.resume_snapshot and not self.kernel.history:
            history_tail = (
                (self.resume_snapshot.get("unified_context") or {}).get("history_tail") or []
            )
            if isinstance(history_tail, list) and history_tail:
                for event in history_tail:
                    if isinstance(event, dict):
                        self.kernel.history.append(event)
        self.script_engine = AdaptiveScriptEngine(self.cwd)
        self.connectivity = ConnectivityManager(self.cwd)
        self.environment_bootstrap = EnvironmentBootstrap(
            workspace_root=self.cwd,
            auto_install=True,
            preferred_wsl_distro="",
            scope="host",
        )
        self.environment_bootstrap.ensure()
        self.context_manager = ContextManager(
            kernel=self.kernel,
            workspace_root=self.cwd,
        )
        self.prompt_injector = SystemPromptInjector()
        self.strategy_header = StrategyHeader()
        self.backend = build_backend(
            self.provider,
            self.model,
            api_base=self.api_base,
            api_key_env=self.api_key_env,
        )
        self.model = str(getattr(getattr(self.backend, "info", None), "model", self.model) or self.model)

    @property
    def history(self) -> List[Dict[str, Any]]:
        return self.kernel.history

    def current_terminal_state(self, max_events: int = 160, max_chars: int = 16000) -> str:
        _ = (max_events, max_chars)
        bootstrap_state = self.environment_bootstrap.summary_text().strip()
        raw_recent = self.context_manager.render_recent_raw_transcript().strip()
        connectivity_state = self.connectivity.summary_text(raw_recent).strip()
        context_state = self.context_manager.current_terminal_state().strip()
        resume_state = self.resume_context_text.strip()
        parts: List[str] = []
        if resume_state:
            parts.append(resume_state)
        if bootstrap_state:
            parts.append(f"Environment bootstrap:\n{bootstrap_state}")
        if connectivity_state:
            parts.append(f"Connectivity:\n{connectivity_state}")
        if context_state:
            parts.append(context_state)
        if parts:
            return "\n\n".join(parts)
        if bootstrap_state:
            return bootstrap_state
        return context_state

    def _system_prompt(self) -> str:
        return (
            "You are VanguardCore, a recursive execution engine.\n"
            "Global Objective and Current Terminal State are the source of truth.\n"
            "Errors are not failures; they are data.\n"
            "When you need action, emit bash or python code blocks.\n"
            "Continue until you explicitly emit [OBJECTIVE_MET].\n"
            "Do not include chain-of-thought or filler.\n"
            "Before any code block, provide a one-sentence line labeled 'Current Heuristic:'.\n"
            "If the previous command failed, that heuristic must state a different authorized approach.\n"
            f"{self.context_manager.memory_instruction()}"
        )

    def _llm_messages(self) -> List[Dict[str, str]]:
        state = self.current_terminal_state()
        previous_failed, previous_error, previous_command = self._last_command_failure_context()
        strategy_text = self.strategy_header.render(
            previous_failed=previous_failed,
            previous_error=previous_error,
            previous_command=previous_command,
        )
        prompt = (
            f"Global Objective:\n{self.objective}\n\n"
            f"Current Terminal State:\n{state}\n\n"
            "If the objective is complete, return [OBJECTIVE_MET]. "
            "Otherwise return one or more bash or python code blocks.\n"
            f"{self.context_manager.memory_instruction()}\n\n"
            f"{strategy_text}"
        )
        system_message = {
            "role": "system",
            "content": f"{self._system_prompt()}\n\n{strategy_text}",
        }
        user_message = {"role": "user", "content": prompt}
        injected_messages = self.prompt_injector.inject_messages([system_message, user_message])
        self.kernel.record_message(
            "user",
            injected_messages[-1]["content"],
            metadata={"kind": "prompt", "injected": True},
        )
        return injected_messages

    def _ask_llm(self) -> str:
        response = self.backend.chat(
            self._llm_messages(),
            think=False,
            options={"num_predict": 1024, "temperature": 0.2},
        )
        text = _content_from_response(response)
        self.kernel.record_message("assistant", text, metadata={"kind": "llm_response"})
        return text

    def _emit_command(self, command: str) -> None:
        print(f"$ {command}", flush=True)

    def _emit_stream_line(self, stream: str, line: str) -> None:
        print(line, flush=True)

    def _emit_heuristic(self, heuristic: str) -> None:
        if heuristic:
            print(f"[heuristic] {heuristic}", flush=True)

    def _last_command_failure_context(self) -> Tuple[bool, str, str]:
        for event in reversed(self.kernel.history):
            if str(event.get("kind", "")).lower() != "result":
                continue
            stderr = str(event.get("stderr") or "").strip()
            stdout = str(event.get("stdout") or "").strip()
            returncode = event.get("returncode")
            failed = returncode not in (0, None) or bool(stderr)
            return failed, stderr or stdout, str(event.get("command") or "")
        return False, "", ""

    def _execute_block(self, language: str, code: str) -> Dict[str, Any]:
        script_run = self.script_engine.execute(
            language,
            code,
            cwd=self.cwd,
            env=self.env,
        )
        command = script_run.command
        normalized = script_run.language
        self._emit_command(command)
        self.kernel.record_command(
            command,
            language=normalized,
            cwd=str(self.cwd),
            metadata={"source_language": language, "code": code, "script_path": script_run.script_path},
        )
        stdout = script_run.stdout or ""
        stderr = script_run.stderr or ""
        if stdout:
            for line in stdout.splitlines():
                self._emit_stream_line("stdout", line)
        if stderr:
            for line in stderr.splitlines():
                self._emit_stream_line("stderr", line)

        self.kernel.record_result(
            command,
            script_run.returncode,
            cwd=str(self.cwd),
            stdout=stdout,
            stderr=stderr,
            metadata={
                "source_language": language,
                "normalized_language": normalized,
                "code": code,
                "script_path": script_run.script_path,
            },
        )
        return {
            "command": command,
            "language": normalized,
            "returncode": script_run.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "script_path": script_run.script_path,
        }

    def _build_progress(self, response: str, blocks: List[Tuple[str, str]], results: List[Dict[str, Any]], status: str) -> Dict[str, Any]:
        last_result = results[-1] if results else {}
        last_command = str(last_result.get("command") or "").strip()
        last_returncode = last_result.get("returncode") if last_result else None
        last_error = str(last_result.get("stderr") or last_result.get("stdout") or "").strip()
        current_heuristic = self.strategy_header.extract(response)
        last_command_failed, failure_error, failure_command = self._last_command_failure_context()
        if last_returncode in (0, None) and not last_error:
            last_error = ""
        return {
            "iteration": self.iteration_count,
            "status": status,
            "response_preview": _preview(response, 1200),
            "current_heuristic": current_heuristic,
            "block_count": len(blocks),
            "executed_blocks": len(results),
            "last_command": last_command,
            "last_returncode": last_returncode,
            "last_error": _preview(last_error, 1200),
            "last_command_failed": last_command_failed,
            "last_failure_error": _preview(failure_error, 1200),
            "last_failure_command": _preview(failure_command, 220),
        }

    def _save_journal(self, response: str, blocks: List[Tuple[str, str]], results: List[Dict[str, Any]], status: str) -> None:
        snapshot = self.journaling_engine.build_snapshot(
            objective=self.objective,
            session_id=self.kernel.session_id,
            iteration=self.iteration_count,
            kernel_history=self.kernel.history,
            current_terminal_state=self.current_terminal_state(),
            progress=self._build_progress(response, blocks, results, status),
            provider=self.provider,
            model=self.model,
            cwd=str(self.cwd),
            status=status,
        )
        saved = self.journaling_engine.save(snapshot)
        self.resume_context_text = str(saved.get("resume_context", "") or "").strip()

    def run(self) -> None:
        while True:
            self.iteration_count += 1
            response = self._ask_llm()
            if "[OBJECTIVE_MET]" in response:
                self.kernel.record_message("assistant", "[OBJECTIVE_MET]", metadata={"kind": "completion"})
                self._save_journal(response, [], [], "complete")
                break

            heuristic = self.strategy_header.extract(response)
            blocks = extract_code_blocks(response)
            previous_failed, previous_error, previous_command = self._last_command_failure_context()

            if blocks and not heuristic:
                self.kernel.record_message(
                    "note",
                    "Missing Current Heuristic; requesting a retry before executing code.",
                    metadata={
                        "kind": "missing_heuristic",
                        "previous_failed": previous_failed,
                        "previous_error": previous_error,
                        "previous_command": previous_command,
                    },
                )
                self._save_journal(response, blocks, [], "retry_missing_heuristic")
                continue

            if heuristic:
                self._emit_heuristic(heuristic)
                self.kernel.record_message(
                    "strategy",
                    f"Current Heuristic: {heuristic}",
                    metadata={
                        "kind": "current_heuristic",
                        "previous_failed": previous_failed,
                        "previous_error": previous_error,
                        "previous_command": previous_command,
                    },
                )

            if not blocks:
                self.kernel.record_message(
                    "note",
                    "No executable code blocks found in the response.",
                    metadata={"kind": "no_code"},
                )
                self._save_journal(response, [], [], "waiting")
                continue

            results: List[Dict[str, Any]] = []
            for declared_language, code in blocks:
                result = self._execute_block(declared_language, code)
                results.append(result)
                self.kernel.record_message(
                    "tool",
                    json.dumps(result, ensure_ascii=False),
                    metadata={"kind": "code_block_result"},
                )
            self._save_journal(response, blocks, results, "active")

    def run_forever(self) -> None:
        self.run()


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="VanguardCore recursive execution engine")
    parser.add_argument("--objective", "-o", default="", help="Global Objective")
    parser.add_argument("--provider", default="ollama", help="LLM provider")
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL, help="LLM model")
    parser.add_argument("--api-base", default="", help="OpenAI-compatible API base URL")
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY", help="Environment variable containing API key")
    parser.add_argument("--history", default="vanguard_history.jsonl", help="Persistent history JSONL path")
    parser.add_argument("--cwd", default="", help="Working directory for executed commands")
    parser.add_argument("--fresh", action="store_true", help="Ignore the hidden journal and start a new session")
    args = parser.parse_args(argv)

    try:
        core = VanguardCore(
            objective=args.objective,
            provider=args.provider,
            model=args.model,
            api_base=args.api_base,
            api_key_env=args.api_key_env,
            history_path=args.history,
            fresh=args.fresh,
            cwd=args.cwd or None,
        )
    except ValueError as exc:
        parser.error(str(exc))
    core.run()


if __name__ == "__main__":
    main()
