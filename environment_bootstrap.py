from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _preview(text: str, limit: int = 240) -> str:
    stripped = (text or "").strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[: max(0, limit - 3)].rstrip() + "..."


def _run_command(args: Sequence[str], *, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
    )


@dataclass(frozen=True)
class ToolSpec:
    name: str
    executables: Tuple[str, ...]
    apt_packages: Tuple[str, ...] = ()
    brew_packages: Tuple[str, ...] = ()
    pip_packages: Tuple[str, ...] = ()


@dataclass
class ToolStatus:
    name: str
    present: bool
    executable: str = ""
    install_attempted: bool = False
    installed_now: bool = False
    manager: str = ""
    notes: List[str] = field(default_factory=list)
    attempts: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "present": self.present,
            "executable": self.executable,
            "install_attempted": self.install_attempted,
            "installed_now": self.installed_now,
            "manager": self.manager,
            "notes": list(self.notes),
            "attempts": list(self.attempts),
        }


@dataclass
class BootstrapReport:
    scope: str
    workspace_root: str
    package_manager: str
    preferred_wsl_distro: str
    tools: List[ToolStatus] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scope": self.scope,
            "workspace_root": self.workspace_root,
            "package_manager": self.package_manager,
            "preferred_wsl_distro": self.preferred_wsl_distro,
            "tools": [tool.as_dict() for tool in self.tools],
        }

    def summary_text(self) -> str:
        lines = [
            f"Bootstrap scope: {self.scope}",
            f"Workspace root: {self.workspace_root}",
            f"Package manager: {self.package_manager or 'none'}",
            f"Preferred WSL distro: {self.preferred_wsl_distro or 'none'}",
        ]
        for tool in self.tools:
            state = "present" if tool.present else "missing"
            if tool.installed_now:
                state = "installed"
            line = f"- {tool.name}: {state}"
            if tool.executable:
                line += f" ({tool.executable})"
            if tool.manager:
                line += f" via {tool.manager}"
            if tool.notes:
                line += f" | {'; '.join(tool.notes[:2])}"
            lines.append(line)
        return "\n".join(lines)


class EnvironmentBootstrap:
    """
    Host-environment bootstrapper for VanguardCore.

    It checks for approved recovery tools, attempts non-interactive installation
    via available package managers, and writes a JSON summary into the workspace.
    """

    def __init__(
        self,
        *,
        workspace_root: str | Path,
        required_tools: Sequence[str] = ("python", "nmap", "openssl", "netcat"),
        auto_install: bool = True,
        preferred_wsl_distro: str = "",
        allow_pip: bool = True,
        allow_host_package_managers: bool = True,
        state_filename: str = "environment_bootstrap.json",
        scope: str = "host",
    ) -> None:
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.required_tools = tuple(required_tools)
        self.auto_install = bool(auto_install)
        self.preferred_wsl_distro = (preferred_wsl_distro or "").strip()
        self.allow_pip = bool(allow_pip)
        self.allow_host_package_managers = bool(allow_host_package_managers)
        self.scope = scope
        self.state_path = self.workspace_root / "state" / state_filename
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.tool_specs = self._tool_specs()
        self._report: Optional[BootstrapReport] = None

    def _tool_specs(self) -> Dict[str, ToolSpec]:
        return {
            "python": ToolSpec(
                name="python",
                executables=(sys.executable, "python", "python3"),
                pip_packages=(),
            ),
            "nmap": ToolSpec(
                name="nmap",
                executables=("nmap",),
                apt_packages=("nmap",),
                brew_packages=("nmap",),
                pip_packages=("python-nmap",),
            ),
            "openssl": ToolSpec(
                name="openssl",
                executables=("openssl",),
                apt_packages=("openssl",),
                brew_packages=("openssl@3",),
                pip_packages=("pyOpenSSL",),
            ),
            "netcat": ToolSpec(
                name="netcat",
                executables=("nc", "netcat", "ncat"),
                apt_packages=("netcat-openbsd",),
                brew_packages=("netcat",),
                pip_packages=("netcat",),
            ),
        }

    def _normalize_tool_name(self, name: str) -> str:
        token = (name or "").strip().lower()
        aliases = {
            "py": "python",
            "python3": "python",
            "nc": "netcat",
            "ncat": "netcat",
        }
        return aliases.get(token, token)

    def _tool_present(self, spec: ToolSpec) -> Tuple[bool, str]:
        for candidate in spec.executables:
            if candidate == sys.executable:
                return True, candidate
            resolved = shutil.which(candidate)
            if resolved:
                return True, resolved
        return False, ""

    def _available_wsl_distros(self) -> List[str]:
        if not shutil.which("wsl"):
            return []
        result = _run_command(["wsl", "-l", "-q"])
        if result.returncode != 0:
            return []
        distros = []
        for line in result.stdout.splitlines():
            distro = line.strip().replace("\x00", "")
            if not distro:
                continue
            lower = distro.lower()
            if lower.startswith("docker-desktop"):
                continue
            distros.append(distro)
        return distros

    def _choose_wsl_distro(self) -> str:
        distros = self._available_wsl_distros()
        if not distros:
            return ""
        if self.preferred_wsl_distro and self.preferred_wsl_distro in distros:
            return self.preferred_wsl_distro
        for candidate in ("kali-linux", "Ubuntu", "Debian"):
            if candidate in distros:
                return candidate
        return distros[0]

    def _package_manager(self) -> str:
        if shutil.which("brew"):
            return "brew"
        if shutil.which("apt-get") or shutil.which("apt"):
            return "apt"
        if shutil.which("wsl") and self._choose_wsl_distro():
            return "wsl-apt"
        if shutil.which("pip") or shutil.which("python"):
            return "pip"
        return ""

    def _install_with_apt(self, packages: Sequence[str]) -> subprocess.CompletedProcess[str]:
        cmd = ["apt-get", "update"]
        if os.name != "nt" and os.geteuid() != 0:  # type: ignore[attr-defined]
            cmd = ["sudo", "-n", "apt-get", "update"]
        result = _run_command(cmd)
        if result.returncode != 0:
            return result
        install_cmd = ["apt-get", "install", "-y", *packages]
        if os.name != "nt" and os.geteuid() != 0:  # type: ignore[attr-defined]
            install_cmd = ["sudo", "-n", "apt-get", "install", "-y", *packages]
        return _run_command(install_cmd)

    def _install_with_wsl_apt(self, packages: Sequence[str]) -> subprocess.CompletedProcess[str]:
        distro = self._choose_wsl_distro()
        if not distro:
            return subprocess.CompletedProcess(args=["wsl"], returncode=1, stdout="", stderr="No WSL distro available")
        joined = " ".join(packages)
        command = f"sudo -n apt-get update && sudo -n apt-get install -y {joined}"
        return _run_command(["wsl", "-d", distro, "--", "bash", "-lc", command])

    def _install_with_brew(self, packages: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return _run_command(["brew", "install", *packages])

    def _install_with_pip(self, packages: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if not self.allow_pip:
            return subprocess.CompletedProcess(args=["pip"], returncode=1, stdout="", stderr="pip installs disabled")
        return _run_command([sys.executable, "-m", "pip", "install", *packages])

    def _attempt_install(self, tool_name: str, spec: ToolSpec, manager: str) -> Tuple[bool, List[str], str]:
        notes: List[str] = []
        if not self.auto_install:
            notes.append("auto-install disabled")
            return False, notes, ""

        if manager == "brew" and spec.brew_packages:
            result = self._install_with_brew(spec.brew_packages)
            notes.append(_preview(result.stdout or result.stderr, 280))
            return result.returncode == 0, notes, "brew"

        if manager == "apt" and spec.apt_packages:
            result = self._install_with_apt(spec.apt_packages)
            notes.append(_preview(result.stdout or result.stderr, 280))
            return result.returncode == 0, notes, "apt"

        if manager == "wsl-apt" and spec.apt_packages:
            result = self._install_with_wsl_apt(spec.apt_packages)
            notes.append(_preview(result.stdout or result.stderr, 280))
            return result.returncode == 0, notes, "wsl-apt"

        if manager == "pip" and spec.pip_packages:
            result = self._install_with_pip(spec.pip_packages)
            notes.append(_preview(result.stdout or result.stderr, 280))
            return result.returncode == 0, notes, "pip"

        notes.append(f"no install mapping for {tool_name} with {manager}")
        return False, notes, manager

    def ensure(self) -> BootstrapReport:
        manager = self._package_manager()
        report = BootstrapReport(
            scope=self.scope,
            workspace_root=str(self.workspace_root),
            package_manager=manager,
            preferred_wsl_distro=self._choose_wsl_distro(),
        )

        for tool_name in self.required_tools:
            normalized = self._normalize_tool_name(tool_name)
            spec = self.tool_specs.get(normalized)
            if spec is None:
                report.tools.append(ToolStatus(
                    name=tool_name,
                    present=False,
                    notes=["unknown tool"],
                ))
                continue

            present, executable = self._tool_present(spec)
            status = ToolStatus(
                name=normalized,
                present=present,
                executable=executable,
            )

            if present:
                status.notes.append("available")
                report.tools.append(status)
                continue

            status.notes.append("missing")
            status.install_attempted = True
            if self.allow_host_package_managers and manager:
                installed, notes, used_manager = self._attempt_install(normalized, spec, manager)
                status.installed_now = installed
                status.manager = used_manager
                status.notes.extend(notes)
                present_after, executable_after = self._tool_present(spec)
                status.present = present_after
                if executable_after:
                    status.executable = executable_after
                if present_after and not status.installed_now:
                    status.notes.append("found after installation attempt")
            else:
                status.notes.append("no supported package manager available")

            report.tools.append(status)

        self._report = report
        self._write_report(report)
        return report

    def _write_report(self, report: BootstrapReport) -> None:
        try:
            self.state_path.write_text(
                json.dumps(report.as_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    @property
    def report(self) -> Optional[BootstrapReport]:
        return self._report

    def summary_text(self) -> str:
        if self._report is None:
            self.ensure()
        assert self._report is not None
        return self._report.summary_text()
