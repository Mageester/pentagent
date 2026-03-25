from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import threading
import webbrowser
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlparse


SnapshotProvider = Callable[[], Dict[str, Any]]
SaveConfigCallback = Callable[[Dict[str, Any]], None]


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _pill(label: str, value: Any) -> str:
    return f'<span class="pill"><span>{_esc(label)}</span><strong>{_esc(value)}</strong></span>'


def _kv(items: Dict[str, Any]) -> str:
    rows = "".join(f"<li><span>{_esc(k)}</span><strong>{_esc(v)}</strong></li>" for k, v in items.items())
    return f'<ul class="kv">{rows}</ul>'


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>"
        for row in rows
    ) or '<tr><td class="empty" colspan="99">No entries yet</td></tr>'
    return f'<div class="table"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _short(value: Any, limit: int = 160) -> str:
    text = "" if value is None else str(value).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def render_dashboard(snapshot: Dict[str, Any]) -> str:
    runtime = snapshot.get("runtime", {})
    workspace = snapshot.get("workspace", {})
    checkpoint = snapshot.get("checkpoint", {})
    skills = snapshot.get("skills", {})
    skill_details = snapshot.get("skill_details", [])
    sessions = snapshot.get("sessions", [])
    reports = snapshot.get("reports", {})

    mission = runtime.get("mission") or checkpoint.get("operator_task") or "platform launcher"
    target = runtime.get("target") or checkpoint.get("domain") or "none"
    mode = runtime.get("mode") or checkpoint.get("mode") or "launcher"
    provider = runtime.get("provider") or "ollama"
    model = runtime.get("model") or "unset"
    backend_model = runtime.get("backend_model") or model
    has_model = bool(str(model).strip()) and str(model).strip().lower() != "unset"
    model_verified = bool(runtime.get("model_verified", backend_model == model)) if has_model else False
    autonomy = runtime.get("autonomy") or checkpoint.get("autonomy_mode") or "free"
    backend = runtime.get("backend") or provider
    verification = "verified" if model_verified else ("unconfigured" if not has_model else "mismatch")

    findings = checkpoint.get("findings", []) or []
    notes = checkpoint.get("notes", []) or []
    top_findings = [
        [f.get("severity", "info"), f.get("kind", "finding"), f.get("url", ""), f.get("detail", "")]
        for f in findings[-6:]
    ]
    recent_notes = [[note] for note in notes[-6:] if str(note).strip()]
    skill_rows = [
        [s.get("name", ""), s.get("category", ""), s.get("kind", ""), s.get("source", ""), ", ".join(s.get("tools", []) or []), s.get("description", "")]
        for s in skill_details[:12]
    ]
    session_rows = [
        [s.get("session_id", ""), s.get("mode", ""), s.get("domain", ""), s.get("goal", ""), s.get("updated_at", "")]
        for s in sessions[:8]
    ]
    recent_events = checkpoint.get("recent_events", []) or []
    trace_rows = []
    for event in recent_events[-12:]:
        if not isinstance(event, dict):
            continue
        etype = str(event.get("type", "event")).strip() or "event"
        step = event.get("step", "")
        data = event.get("data", {})
        if not isinstance(data, dict):
            data = {}
        if etype == "decision":
            action = str(data.get("action", "")).strip()
            tool = str(data.get("tool", "")).strip()
            why = str(data.get("why") or data.get("reason") or data.get("summary") or "").strip()
            source = "decision"
            detail = " | ".join([part for part in (action, tool, why) if part]) or "(no details)"
        elif etype == "tool_result":
            tool = str(event.get("tool", "")).strip()
            source = tool or "tool_result"
            status = "ok" if event.get("ok") else "fail"
            preview = str(event.get("output") or event.get("error") or "").strip()
            detail = f"{status} | {_short(preview, 140)}"
        elif etype in {"repeat_observed", "blocked_action"}:
            source = str(event.get("tool", "")).strip() or etype
            detail = _short(event.get("note") or event.get("signature") or "", 160)
        else:
            source = str(event.get("tool", "")).strip() or etype
            detail = _short(json.dumps(event, ensure_ascii=False), 140)
        trace_rows.append([step, etype, source, detail])

    docs = workspace.get("docs", {})
    doc_rows = [[name, "present" if present else "missing"] for name, present in docs.items()]
    state_signature = (
        f"{checkpoint.get('step', 0)}:"
        f"{len(checkpoint.get('recent_events', []) or [])}:"
        f"{len(findings)}:"
        f"{len(notes)}:"
        f"{runtime.get('updated_at', '')}:"
        f"{runtime.get('model', '')}:"
        f"{runtime.get('backend_model', '')}"
    )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>PentAgent Control Plane</title>
<style>
:root{{color-scheme:dark;--bg:#07111f;--bg2:#0d1730;--panel:rgba(11,21,40,.86);--border:rgba(132,164,255,.18);--text:#e7efff;--muted:#8fa4cc;--accent:#68f0c4;--accent2:#6da8ff;--radius:22px;--radius-sm:16px;--mono:"Cascadia Mono","SFMono-Regular",Consolas,monospace;--sans:"Segoe UI Variable","Segoe UI","Aptos",system-ui,sans-serif;}}
*{{box-sizing:border-box}} body{{margin:0;font-family:var(--sans);color:var(--text);background:radial-gradient(circle at top left,rgba(104,240,196,.17),transparent 32%),radial-gradient(circle at top right,rgba(109,168,255,.16),transparent 28%),linear-gradient(180deg,var(--bg),var(--bg2));min-height:100vh}}
body::before{{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px);background-size:48px 48px;pointer-events:none;mask-image:linear-gradient(180deg,rgba(0,0,0,.7),transparent 96%)}}
.shell{{width:min(1440px,calc(100vw - 32px));margin:0 auto;padding:20px 0 40px;position:relative}}
.top{{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}}
.brand{{display:flex;align-items:center;gap:14px}} .logo{{width:54px;height:54px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(135deg,rgba(104,240,196,.18),rgba(109,168,255,.18));border:1px solid rgba(255,255,255,.12);font-family:var(--mono);font-weight:700;letter-spacing:.08em}}
h1{{margin:0;font-size:clamp(2rem,4vw,3.25rem);line-height:1.02;letter-spacing:-.04em}} .sub{{margin:8px 0 0;color:var(--muted);max-width:72ch;line-height:1.55}}
.stack{{display:flex;flex-wrap:wrap;gap:8px}} .pill{{display:inline-flex;gap:10px;align-items:center;padding:10px 14px;border-radius:999px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.03)}} .pill span{{color:var(--muted);text-transform:uppercase;font-size:.72rem;letter-spacing:.08em}} .pill strong{{font-family:var(--mono);font-size:.9rem}}
.hero{{display:grid;grid-template-columns:1.6fr 1fr;gap:18px;margin-top:12px}}
.panel,.card{{background:linear-gradient(180deg,rgba(19,33,61,.92),rgba(10,17,32,.92));border:1px solid var(--border);border-radius:var(--radius);box-shadow:0 24px 80px rgba(0,0,0,.35);backdrop-filter:blur(20px)}}
.hero-main{{padding:28px;display:grid;gap:18px}} .form{{display:grid;gap:12px}} .grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}} .stats{{padding:18px;min-height:124px}}
.eyebrow{{color:var(--muted);text-transform:uppercase;letter-spacing:.12em;font-size:.72rem;margin-bottom:10px}} .value{{font-size:1.55rem;font-weight:700;letter-spacing:-.03em;margin-bottom:8px}} .note{{color:var(--muted);line-height:1.45;font-size:.94rem}}
.panel{{margin-top:18px;padding:20px}} .head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:14px}} .head h2{{margin:0;font-size:1.15rem;letter-spacing:-.02em}} .head p{{margin:6px 0 0;color:var(--muted)}}
.split{{display:grid;grid-template-columns:1fr 1fr;gap:14px}} .inset{{padding:16px;border-radius:var(--radius-sm);background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08)}}
.kv,.list{{list-style:none;padding:0;margin:0;display:grid;gap:10px}} .kv li,.list li{{padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}}
.kv li{{display:flex;justify-content:space-between;gap:14px;font-family:var(--mono);font-size:.86rem}} .kv li span{{color:var(--muted)}} .kv li strong{{text-align:right;word-break:break-word}}
.list li{{display:grid;gap:6px}} .list li span{{font-weight:650}} .list li small{{color:var(--muted);line-height:1.4}} .empty{{color:var(--muted);text-align:center;padding:22px !important}}
.table{{overflow:auto;border-radius:18px;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.02)}} table{{width:100%;border-collapse:collapse;min-width:820px}} th,td{{padding:12px 14px;text-align:left;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top;font-size:.92rem}} th{{color:#cfe0ff;font-size:.74rem;text-transform:uppercase;letter-spacing:.1em;background:rgba(255,255,255,.03)}} td{{color:#e7efff}}
input,select,textarea,button{{font:inherit}} input,select,textarea{{width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,.08);background:rgba(2,8,18,.72);color:var(--text);outline:none}} textarea{{min-height:90px;resize:vertical}} button,.btn{{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 16px;border-radius:14px;border:1px solid rgba(255,255,255,.1);background:linear-gradient(135deg,rgba(104,240,196,.16),rgba(109,168,255,.14));color:var(--text);text-decoration:none;cursor:pointer;font-weight:650}}
.actions{{display:flex;gap:12px;flex-wrap:wrap}} .footer{{margin-top:18px;color:var(--muted);font-size:.9rem;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}} pre{{margin:0;overflow:auto;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);font-size:.82rem;line-height:1.5;color:#d6e3ff}}
@media(max-width:1100px){{.hero,.split,.grid{{grid-template-columns:1fr}}}}
</style></head><body><div class="shell">
<div class="top"><div class="brand"><div class="logo">PA</div><div><div class="eyebrow">Deprecated control plane</div><h1>PentAgent Dashboard</h1><p class="sub">This project is archived and no longer actively developed. Workspace, skills, sessions, and artifacts remain local for reference only.</p></div></div><div class="stack">{_pill("provider", provider)}{_pill("model", model)}{_pill("backend", backend)}{_pill("model check", verification)}</div></div>
<div class="hero"><section class="panel hero-main"><div><div class="eyebrow">Current mission</div><h1>{_esc(mission)}</h1><p class="sub">The pentest engine runs as one skill pack inside a broader local platform. The dashboard reads the workspace and checkpoint files and refreshes automatically.</p></div><div class="stack">{_pill("target", target)}{_pill("mode", mode)}{_pill("autonomy", autonomy)}{_pill("workspace", workspace.get("agent_id", "main"))}{_pill("verified", verification)}</div></section>
    <aside class="card stats"><div class="eyebrow">Launch Defaults</div><form class="form" method="post" action="/api/config"><div class="grid"><label>Provider<select name="provider"><option value="ollama" {"selected" if provider == "ollama" else ""}>ollama</option><option value="openai-compatible" {"selected" if provider in {"openai-compatible", "api"} else ""}>openai-compatible</option></select></label><label>Model<input name="model" value="{_esc(model)}" placeholder="Exact Ollama model tag"></label><label>Autonomy<select name="autonomy"><option value="free" {"selected" if autonomy == "free" else ""}>free</option><option value="balanced" {"selected" if autonomy == "balanced" else ""}>balanced</option></select></label><label>Mode<select name="mode"><option value="launcher" {"selected" if mode == "launcher" else ""}>launcher</option><option value="web" {"selected" if mode == "web" else ""}>web</option><option value="network" {"selected" if mode == "network" else ""}>network</option></select></label></div><label>Mission<textarea name="mission" placeholder="Describe the broad authorized objective">{_esc(runtime.get("mission", ""))}</textarea></label><label>Target / subnet<input name="target" value="{_esc(runtime.get("target", ""))}" placeholder="http://localhost:3000 or 10.0.0.0/24"></label><div class="actions"><button type="submit">Save workspace defaults</button><a class="btn" href="/api/state">JSON state</a></div></form></aside></div>
<section class="panel"><div class="head"><div><h2>Runtime</h2><p>Current session and workspace state from the checkpoint.</p></div></div><div class="grid"><article class="card stats"><div class="eyebrow">Progress</div><div class="value">Step {checkpoint.get("step", 0)}</div><div class="note">{len(checkpoint.get("pages", {}) or [])} pages | {len(checkpoint.get("network_hosts", []) or [])} hosts | {len(checkpoint.get("queued_urls", []) or [])} queued URLs</div></article><article class="card stats"><div class="eyebrow">Findings</div><div class="value">{len(findings)}</div><div class="note">{len(skills.get("categories", {}) or {})} skill categories | {skills.get("total", 0)} loaded skills</div></article><article class="card stats"><div class="eyebrow">Workspace</div><div class="value">{workspace.get("agent_id", "main")}</div><div class="note">{workspace.get("artifacts_dir", "")}</div></article><article class="card stats"><div class="eyebrow">Model</div><div class="value">{_esc(runtime.get("model", "unset"))}</div><div class="note">{_esc(runtime.get("backend_model", runtime.get("model", "unset")))} | {("verified" if model_verified else "mismatch")}</div></article></div></section>
<section class="panel"><div class="head"><div><h2>Workspace</h2><p>Bootstrap docs and local storage paths.</p></div></div><div class="split"><div class="inset">{_kv({"root": workspace.get("root", ""), "state_dir": workspace.get("state_dir", ""), "artifacts_dir": workspace.get("artifacts_dir", ""), "sessions_dir": workspace.get("sessions_dir", ""), "skills_dir": workspace.get("skills_dir", ""), "config_path": workspace.get("config_path", ""), "checkpoint": workspace.get("checkpoint_path", ""), "dashboard": f"http://127.0.0.1:{workspace.get('dashboard_port', 8765)}"})}</div><div class="inset"><div class="eyebrow">Docs</div>{_kv(docs)}<div class="eyebrow" style="margin-top:1rem;">Skill Roots</div><div class="stack">{''.join(f'<span class="btn">{_esc(p)}</span>' for p in workspace.get("skill_dirs", []))}</div></div></div></section>
<section class="panel"><div class="head"><div><h2>Skills</h2><p>File-based packs plus built-in tool descriptors.</p></div></div><div class="split"><div class="inset"><div class="eyebrow">Catalog</div><div class="stack">{_pill("total", skills.get("total", 0))}{_pill("sources", len(skills.get("sources", {}) or {}))}{_pill("categories", len(skills.get("categories", {}) or {}))}</div><div class="eyebrow" style="margin-top:1rem;">Samples</div>{_kv({k: ', '.join(v[:5]) for k, v in (skills.get("samples", {}) or {}).items()})}</div><div class="inset"><ul class="list">{''.join(f'<li><span>{_esc(s.get("name", ""))}</span><small>{_esc(s.get("category", ""))} | { _esc(s.get("kind", "")) } | {_esc(s.get("source", ""))}</small><small>{_esc(s.get("description", ""))}</small></li>' for s in skill_details[:12]) or '<li class="empty">No file-based skill packs discovered yet</li>'}</ul></div></div></section>
<section class="panel"><div class="head"><div><h2>Sessions</h2><p>Persisted workspace sessions.</p></div></div>{_table(["Session","Mode","Target","Goal","Updated"], session_rows)}</section>
<section class="panel"><div class="head"><div><h2>Evidence</h2><p>Recent findings, notes, and report destinations.</p></div></div><div class="split"><div class="inset"><div class="eyebrow">Recent findings</div>{_table(["Severity","Kind","URL","Detail"], top_findings)}</div><div class="inset"><div class="eyebrow">Recent notes</div>{_table(["Note"], recent_notes)}</div></div><div class="inset" style="margin-top:14px"><div class="eyebrow">Report artifacts</div>{_kv(reports)}</div></section>
<section class="panel"><div class="head"><div><h2>Live Trace</h2><p>Recent decisions, tool calls, and repeat handling from the current run.</p></div></div>{_table(["Step","Type","Source","Detail"], trace_rows)}</section>
<section class="panel"><div class="head"><div><h2>Raw State</h2><p>Checkpoint JSON for deeper inspection.</p></div></div><details><summary>Open checkpoint JSON</summary><pre>{_esc(json.dumps(checkpoint, indent=2, ensure_ascii=False)[:12000])}</pre></details></section>
<div class="footer"><span>Auto-refreshes when the checkpoint changes.</span><span>Workspace root: <code>{_esc(workspace.get("root", ""))}</code></span></div>
<script>
const __PENTAGENT_SIG__ = "{state_signature}";
async function __pollPentAgent() {{
  try {{
    const response = await fetch("/api/state", {{ cache: "no-store" }});
    if (!response.ok) return;
    const state = await response.json();
    const nextSig = `${{state?.checkpoint?.step || 0}}:${{(state?.checkpoint?.recent_events || []).length}}:${{(state?.checkpoint?.findings || []).length}}:${{(state?.checkpoint?.notes || []).length}}:${{state?.runtime?.updated_at || ""}}:${{state?.runtime?.model || ""}}:${{state?.runtime?.backend_model || ""}}`;
    if (nextSig !== __PENTAGENT_SIG__) {{
      window.location.reload();
    }}
  }} catch (error) {{
    // Keep the existing page visible if polling fails.
  }}
}}
setInterval(__pollPentAgent, 2000);
</script>
</div></body></html>"""


def _page(title: str, subtitle: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_esc(title)} - PentAgent</title><meta http-equiv="refresh" content="8"><style>{_css()}</style></head>
<body><div class="shell"><div class="top"><div class="brand"><div class="logo">PA</div><div><div class="eyebrow">PentAgent</div><h1>{_esc(title)}</h1><p class="sub">{_esc(subtitle)}</p></div></div><div class="stack"><a class="btn" href="/">Dashboard</a></div></div>{body}</div></body></html>"""


def _css() -> str:
    return render_dashboard({"runtime": {}, "workspace": {}, "checkpoint": {}, "skills": {}, "skill_details": [], "sessions": [], "reports": {}}).split("</style>")[0].split("<style>")[1]


def _page_from_table(title: str, subtitle: str, headers: list[str], rows: list[list[Any]]) -> str:
    return _page(title, subtitle, _table(headers, rows))


class DashboardHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, *, snapshot_provider: SnapshotProvider, save_config: SaveConfigCallback):
        super().__init__(server_address, RequestHandlerClass)
        self.snapshot_provider = snapshot_provider
        self.save_config = save_config


class PentDashboardServer:
    def __init__(self, *, host: str, port: int, snapshot_provider: SnapshotProvider, save_config: SaveConfigCallback) -> None:
        self.host = host
        self.port = port
        self._server = DashboardHTTPServer((host, port), _DashboardHandler, snapshot_provider=snapshot_provider, save_config=save_config)
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self._server.server_port}/"

    def start(self, *, open_browser: bool = True) -> str:
        if self._thread and self._thread.is_alive():
            return self.url
        self._thread = threading.Thread(target=self._server.serve_forever, name="PentAgentDashboard", daemon=True)
        self._thread.start()
        if open_browser:
            try:
                webbrowser.open(self.url, new=1, autoraise=False)
            except Exception:
                pass
        return self.url

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass


class _DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _snapshot(self) -> Dict[str, Any]:
        try:
            return self.server.snapshot_provider()
        except Exception as exc:
            return {"error": str(exc)}

    def _send_json(self, payload: Dict[str, Any], status: int = HTTPStatus.OK) -> None:
        data = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html_doc: str, status: int = HTTPStatus.OK) -> None:
        data = html_doc.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        snapshot = self._snapshot()
        path = urlparse(self.path).path
        if path in {"", "/"}:
            self._send_html(render_dashboard(snapshot))
            return
        if path == "/skills":
            skills = snapshot.get("skill_details", [])
            rows = [[s.get("name", ""), s.get("category", ""), s.get("kind", ""), s.get("source", ""), ", ".join(s.get("tools", []) or []), s.get("description", "")] for s in skills]
            self._send_html(_page_from_table("Skills", "File-based skill packs and built-in capability registry.", ["Name", "Category", "Kind", "Source", "Tools", "Description"], rows))
            return
        if path == "/sessions":
            rows = [[s.get("session_id", ""), s.get("mode", ""), s.get("domain", ""), s.get("goal", ""), s.get("updated_at", "")] for s in snapshot.get("sessions", [])]
            self._send_html(_page_from_table("Sessions", "Persisted workspace sessions.", ["Session", "Mode", "Target", "Goal", "Updated"], rows))
            return
        if path == "/workspace":
            workspace = snapshot.get("workspace", {})
            self._send_html(_page_from_table("Workspace", "Workspace bootstrap docs and local storage paths.", ["Key", "Value"], [[k, v] for k, v in workspace.items()]))
            return
        if path == "/api/state":
            self._send_json(snapshot)
            return
        if path == "/api/config":
            self._send_json(snapshot.get("runtime", {}))
            return
        if path == "/api/workspace":
            self._send_json(snapshot.get("workspace", {}))
            return
        if path == "/api/skills":
            self._send_json({"skills": snapshot.get("skill_details", []), "summary": snapshot.get("skills", {})})
            return
        if path == "/api/sessions":
            self._send_json({"sessions": snapshot.get("sessions", [])})
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/config":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype == "application/json":
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        else:
            parsed = parse_qs(raw.decode("utf-8")) if raw else {}
            payload = {k: (v[-1] if isinstance(v, list) and v else "") for k, v in parsed.items()}
        allowed = {"provider", "model", "autonomy", "mission", "mode", "target", "api_base", "api_key_env", "open_dashboard"}
        config = {k: v for k, v in payload.items() if k in allowed}
        if "open_dashboard" in config:
            config["open_dashboard"] = str(config["open_dashboard"]).strip().lower() in {"1", "true", "yes", "on"}
        try:
            self.server.save_config(config)
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.end_headers()
