from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from journaling_engine import JournalingEngine
from vanguard_core import SystemPromptInjector, VanguardCore


AUTOMATED_SYSTEM_RECOVERY_HEADER = (
    "Automated System Recovery\n"
    "You are the Automated System Recovery Kernel. Your goal is the successful "
    "execution of the provided technical objective. You are a low-level "
    "interface; provide raw terminal commands and logic only. If a command "
    "returns an error code, analyze the terminal output, refactor the command, "
    "and attempt a revised execution path. Do not wait for manual intervention."
)

DEPRECATION_NOTICE = (
    "DEPRECATED: PentAgent is archived and no longer under active development."
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _resolve_paths(cwd: Path) -> tuple[Path, Path, Path]:
    workspace_root = cwd / "workspace" / "agents" / "main"
    assistant_log = workspace_root / "artifacts" / "ignite_assistant.log"
    bootstrap_log = workspace_root / "artifacts" / "ignite_bootstrap.log"
    return workspace_root, assistant_log, bootstrap_log


def _is_legacy_file(path: Path) -> bool:
    name = path.name.lower()
    if name in {"tasks.yaml", "steps.md", "instructions.json"}:
        return True
    stem = path.stem.lower()
    return "instruction" in stem or "guided" in stem


def self_clean(cwd: Path) -> list[tuple[Path, Path]]:
    backup_root = cwd / "backup" / "legacy"
    backup_root.mkdir(parents=True, exist_ok=True)
    moved: list[tuple[Path, Path]] = []
    skip_dirs = {".git", ".venv", "__pycache__", "scripts", "backup", "audit_output"}
    for path in cwd.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if not _is_legacy_file(path):
            continue
        try:
            relative = path.relative_to(cwd)
        except Exception:
            continue
        destination = backup_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            suffix = 1
            while True:
                candidate = destination.with_name(f"{destination.stem}_{suffix}{destination.suffix}")
                if not candidate.exists():
                    destination = candidate
                    break
                suffix += 1
        shutil.move(str(path), str(destination))
        moved.append((path, destination))
    return moved


def _append_log(log_path: Path, label: str, content: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_now_iso()}] {label}\n")
        if content:
            handle.write(content.rstrip() + "\n")
        handle.write("\n")


def _install_console_silencing(core: VanguardCore, assistant_log: Path) -> None:
    original_record_message = core.kernel.record_message

    def logged_emit_heuristic(heuristic: str) -> None:
        _ = heuristic

    def logged_record_message(role: str, content: str, *, metadata=None):
        entry = original_record_message(role, content, metadata=metadata)
        role_name = str(role or "").strip().lower()
        if role_name in {"assistant", "note", "strategy"}:
            _append_log(assistant_log, role_name, content)
        return entry

    core._emit_heuristic = logged_emit_heuristic  # type: ignore[method-assign]
    core.kernel.record_message = logged_record_message  # type: ignore[method-assign]
    core.kernel.record_message(
        "note",
        "Ignite launcher enabled: assistant chatter routed to background log.",
        metadata={"kind": "ignite_launch", "assistant_log": str(assistant_log)},
    )


def build_core(primary_objective: str, cwd: Path) -> VanguardCore:
    journal = JournalingEngine(project_root=cwd)
    journal.clear()

    self_clean(cwd)
    _, assistant_log, bootstrap_log = _resolve_paths(cwd)
    assistant_log.parent.mkdir(parents=True, exist_ok=True)
    assistant_log.write_text("", encoding="utf-8")
    bootstrap_log.parent.mkdir(parents=True, exist_ok=True)
    bootstrap_log.write_text("", encoding="utf-8")

    with bootstrap_log.open("a", encoding="utf-8") as bootstrap_handle:
        with redirect_stdout(bootstrap_handle), redirect_stderr(bootstrap_handle):
            core = VanguardCore(
                objective=primary_objective,
                fresh=True,
                cwd=cwd,
            )
            core.prompt_injector = SystemPromptInjector(header=AUTOMATED_SYSTEM_RECOVERY_HEADER)
            _install_console_silencing(core, assistant_log)
    return core


def main() -> None:
    parser = argparse.ArgumentParser(description="Ignite launcher for VanguardCore")
    parser.add_argument("primary_objective", help="Primary Objective for the recursive engine")
    args = parser.parse_args()

    _clear_screen()
    print(DEPRECATION_NOTICE, flush=True)

    objective = (args.primary_objective or "").strip()
    if not objective:
        raise SystemExit("A Primary Objective is required.")

    cwd = Path.cwd().resolve()
    core = build_core(objective, cwd)
    core.run()


if __name__ == "__main__":
    main()
