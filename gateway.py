from __future__ import annotations

from dataclasses import asdict, dataclass, field
import webbrowser
from typing import Any, Callable, Dict, Optional

from dashboard import PentDashboardServer
from skill_registry import SkillSpec, skill_snapshot
from workspace import PentWorkspace


@dataclass
class PentGateway:
    workspace: PentWorkspace
    skill_catalog: Dict[str, SkillSpec]
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8765
    _dashboard: Optional[PentDashboardServer] = field(default=None, init=False, repr=False)

    @property
    def dashboard_url(self) -> str:
        port = self._dashboard._server.server_port if self._dashboard else self.dashboard_port
        return f"http://{self.dashboard_host}:{port}/"

    def snapshot(self) -> Dict[str, Any]:
        data = self.workspace.describe()
        runtime = data.get("runtime", {})
        runtime.setdefault("backend", f"{runtime.get('provider', 'ollama')}:{runtime.get('model', 'unset')}")
        data["runtime"] = runtime
        data["workspace"] = data.get("workspace", {})
        data["skills"] = skill_snapshot(self.skill_catalog)
        data["skill_details"] = [asdict(skill) for skill in self.skill_catalog.values()]
        data["launch"] = {
            "dashboard_url": self.dashboard_url,
            "workspace_root": str(self.workspace.root),
        }
        return data

    def save_runtime(self, payload: Dict[str, Any]) -> None:
        self.workspace.save_runtime(payload)

    def start_dashboard(self, *, open_browser: bool = True) -> str:
        if self._dashboard and self._dashboard._thread and self._dashboard._thread.is_alive():
            return self._dashboard.url
        self._dashboard = PentDashboardServer(
            host=self.dashboard_host,
            port=self.dashboard_port,
            snapshot_provider=self.snapshot,
            save_config=self.save_runtime,
        )
        return self._dashboard.start(open_browser=open_browser)

    def stop_dashboard(self) -> None:
        if self._dashboard:
            self._dashboard.stop()
            self._dashboard = None
