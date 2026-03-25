from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List

from llm_backends import DEFAULT_OLLAMA_MODEL


DEFAULT_AGENT_ID = "main"
DEFAULT_DASHBOARD_PORT = 8765


def _slugify(value: str) -> str:
    text = (value or "").strip().lower()
    text = text.replace("\\", "/")
    text = text.replace(" ", "-")
    cleaned = []
    for char in text:
        if char.isalnum() or char in {"-", "_", "."}:
            cleaned.append(char)
    slug = "".join(cleaned).strip("._-")
    return slug or DEFAULT_AGENT_ID


def _workspace_root() -> Path:
    env_root = os.getenv("PENTAGENT_WORKSPACE", "").strip()
    if env_root:
        return Path(env_root).expanduser()
    return Path(__file__).resolve().parent / "workspace"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent


def _json_read(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def _json_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


_DEFAULT_DOCS: Dict[str, str] = {
    "AGENTS.md": """# PentAgent Workspace (Deprecated)

This workspace template is archived and no longer actively developed.

This workspace is the local control plane for the agent runtime.

## What lives here
- `state/` holds checkpoints, runtime config, and session manifests.
- `artifacts/` holds reports, screenshots, and generated evidence.
- `sessions/` holds per-run JSON and JSONL records.
- `skills/` holds workspace overrides for skill packs.
- `docs/` holds the workspace bootstrap documents.

## Operating model
- Local models are the default.
- API-backed models are optional and can be configured later.
- The dashboard reads from the workspace and checkpoint files.
- The pentest engine is one skill pack inside the platform.

## Working rules
- Keep operator missions broad and explicit.
- Prefer evidence-backed pivots over repeated dead ends.
- Use the dashboard to review current state, skills, and sessions.
""",
    "SOUL.md": """# SOUL

Deprecated: this platform template is preserved for reference only.

Local-first. Evidence-driven. Operator-directed.

The platform should behave like a serious authorized assessment console:
- remember state
- expose capabilities clearly
- keep tool routing flexible
- make the current mission obvious
- preserve artifacts for later review

The pentest engine remains a dedicated capability pack, not the whole product.
""",
    "TOOLS.md": """# Tools

Deprecated: the bundled tooling guidance is archival only.

The runtime is skill-driven.

## Skill sources
- Bundled skill packs under `skills/`
- Workspace overrides under `workspace/agents/<agent_id>/skills/`

## Runtime integrations
- Local Ollama models
- OpenAI-compatible API backends
- WSL-native security tools
- Browser tools and report generation

## Operator guidance
- Choose the model at launch or in the dashboard.
- Use the mission field to describe the objective, not a fixed checklist.
- Let the agent pivot from evidence rather than repeating the same probe.
""",
    "BOOTSTRAP.md": """# Bootstrap

Deprecated: this bootstrap guide is preserved for reference.

1. Select a provider and model.
2. Choose a workspace agent profile.
3. Set a mission or leave it blank for general platform use.
4. Open the dashboard to review status.
5. Launch a session explicitly against an authorized target.

The dashboard and workspace state are stored locally.
""",
}


@dataclass
class PentWorkspace:
    root: Path
    agent_id: str = DEFAULT_AGENT_ID
    dashboard_port: int = DEFAULT_DASHBOARD_PORT

    def __post_init__(self) -> None:
        self.root = Path(self.root).expanduser().resolve()
        self.agent_id = _slugify(self.agent_id)
        self.agent_root = self.root / "agents" / self.agent_id
        self.state_dir = self.agent_root / "state"
        self.artifacts_dir = self.agent_root / "artifacts"
        self.sessions_dir = self.agent_root / "sessions"
        self.skills_dir = self.agent_root / "skills"
        self.docs_dir = self.agent_root / "docs"
        self.config_path = self.agent_root / "config.json"
        self.runtime_path = self.agent_root / "runtime.json"
        self.session_index_path = self.sessions_dir / "index.json"

    @classmethod
    def from_env(cls) -> "PentWorkspace":
        raw_port = os.getenv("PENTAGENT_DASHBOARD_PORT", "").strip()
        try:
            port = int(raw_port) if raw_port else DEFAULT_DASHBOARD_PORT
        except ValueError:
            port = DEFAULT_DASHBOARD_PORT
        agent_id = os.getenv("PENTAGENT_AGENT_ID", DEFAULT_AGENT_ID).strip() or DEFAULT_AGENT_ID
        return cls(root=_workspace_root(), agent_id=agent_id, dashboard_port=port)

    def ensure(self) -> "PentWorkspace":
        for path in (
            self.root,
            self.agent_root,
            self.state_dir,
            self.artifacts_dir,
            self.sessions_dir,
            self.skills_dir,
            self.docs_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
        self._ensure_default_docs()
        if not self.config_path.exists():
            self.save_runtime(self.default_runtime())
        if not self.runtime_path.exists():
            self.save_runtime(self.default_runtime())
        return self

    def _ensure_default_docs(self) -> None:
        for name, content in _DEFAULT_DOCS.items():
            path = self.docs_dir / name
            if not path.exists():
                path.write_text(content.strip() + "\n", encoding="utf-8")

    def default_runtime(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "provider": "ollama",
            "model": DEFAULT_OLLAMA_MODEL,
            "backend_provider": "ollama",
            "backend_model": DEFAULT_OLLAMA_MODEL,
            "backend_base_url": "",
            "backend_api_key_env": "OPENAI_API_KEY",
            "model_verified": True,
            "autonomy": "free",
            "mission": "",
            "mode": "launcher",
            "target": "",
            "dashboard_port": self.dashboard_port,
            "api_base": "",
            "api_key_env": "OPENAI_API_KEY",
            "open_dashboard": True,
            "updated_at": _now_iso(),
        }

    def load_runtime(self) -> Dict[str, Any]:
        runtime = self.default_runtime()
        runtime.update(_json_read(self.runtime_path, {}))
        runtime.update(_json_read(self.config_path, {}))
        runtime["agent_id"] = self.agent_id
        runtime["dashboard_port"] = self.dashboard_port
        provider = str(runtime.get("provider", "")).strip() or "ollama"
        model = str(runtime.get("model", "")).strip()
        backend_provider = str(runtime.get("backend_provider", "")).strip() or provider
        backend_model = str(runtime.get("backend_model", "")).strip()
        if not model or model.lower() == "unset":
            model = self.default_runtime()["model"]
        if not backend_model or backend_model.lower() == "unset":
            backend_model = model
        runtime["provider"] = provider
        runtime["model"] = model
        runtime["backend_provider"] = backend_provider
        runtime["backend_model"] = backend_model
        runtime["model_verified"] = bool(model) and backend_model == model
        return runtime

    def save_runtime(self, data: Dict[str, Any]) -> None:
        payload = dict(self.default_runtime())
        payload.update({k: v for k, v in data.items() if v is not None})
        payload["agent_id"] = self.agent_id
        payload["dashboard_port"] = self.dashboard_port
        payload["updated_at"] = _now_iso()
        _json_write(self.config_path, payload)
        _json_write(self.runtime_path, payload)

    def skill_directories(self) -> List[Path]:
        bundled = _repo_root() / "skills"
        return [self.skills_dir, bundled]

    def checkpoint_path(self) -> Path:
        return self.state_dir / "checkpoint.json"

    def kernel_history_path(self) -> Path:
        return self.state_dir / "kernel_history.jsonl"

    def report_paths(self) -> Dict[str, str]:
        return {
            "json": str(self.artifacts_dir / "audit_report.json"),
            "markdown": str(self.artifacts_dir / "audit_summary.md"),
            "html": str(self.artifacts_dir / "audit_summary.html"),
            "screenshots": str(self.artifacts_dir / "screenshots"),
            "lighthouse": str(self.artifacts_dir / "lighthouse"),
            "scan_logs": str(self.artifacts_dir / "scan_logs"),
        }

    def workspace_status(self) -> Dict[str, Any]:
        docs = {
            name: (self.docs_dir / name).exists()
            for name in sorted(_DEFAULT_DOCS)
        }
        return {
            "root": str(self.root),
            "agent_id": self.agent_id,
            "agent_root": str(self.agent_root),
            "state_dir": str(self.state_dir),
            "artifacts_dir": str(self.artifacts_dir),
            "sessions_dir": str(self.sessions_dir),
            "skills_dir": str(self.skills_dir),
            "docs_dir": str(self.docs_dir),
            "config_path": str(self.config_path),
            "runtime_path": str(self.runtime_path),
            "checkpoint_path": str(self.checkpoint_path()),
            "kernel_history_path": str(self.kernel_history_path()),
            "dashboard_port": self.dashboard_port,
            "docs": docs,
            "skill_dirs": [str(p) for p in self.skill_directories()],
        }

    def write_session_manifest(self, data: Dict[str, Any]) -> Path:
        session_id = str(data.get("session_id") or data.get("id") or _now_iso())
        manifest = self.sessions_dir / f"{_slugify(session_id)}.json"
        payload = dict(data)
        payload.setdefault("session_id", session_id)
        payload["updated_at"] = _now_iso()
        _json_write(manifest, payload)
        self._refresh_session_index()
        return manifest

    def append_session_event(self, session_id: str, event: Dict[str, Any]) -> Path:
        log_path = self.sessions_dir / f"{_slugify(session_id)}.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(event)
        payload.setdefault("timestamp", _now_iso())
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return log_path

    def load_checkpoint(self) -> Dict[str, Any]:
        return _json_read(self.checkpoint_path(), {})

    def list_sessions(self, limit: int = 12) -> List[Dict[str, Any]]:
        manifests = sorted(
            self.sessions_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )
        sessions: List[Dict[str, Any]] = []
        for path in manifests[:limit]:
            if path.name == self.session_index_path.name:
                continue
            data = _json_read(path, {})
            if isinstance(data, dict) and data:
                data.setdefault("path", str(path))
                sessions.append(data)
        return sessions

    def _refresh_session_index(self) -> None:
        index = self.list_sessions(limit=200)
        _json_write(self.session_index_path, index)

    def describe(self) -> Dict[str, Any]:
        runtime = self.load_runtime()
        checkpoint = self.load_checkpoint()
        return {
            "workspace": self.workspace_status(),
            "runtime": runtime,
            "checkpoint": checkpoint,
            "reports": self.report_paths(),
            "sessions": self.list_sessions(limit=8),
        }
