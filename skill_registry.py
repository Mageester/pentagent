from __future__ import annotations

from dataclasses import dataclass
from collections import Counter, defaultdict
from pathlib import Path
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class SkillSpec:
    name: str
    category: str
    description: str
    inputs: str = ""
    outputs: str = ""
    source: str = "built-in"
    path: str = ""
    kind: str = "tool"
    tools: Tuple[str, ...] = ()


def _categorize(name: str, description: str) -> str:
    n = (name or "").lower()
    d = (description or "").lower()
    if n.startswith(("fetch_", "check_", "bulk_", "site_")):
        if "site_map" in n or "site_snapshot" in n:
            return "orchestration"
        if "security" in n or "parameter" in n:
            return "security"
        return "recon"
    if n.startswith(("security_", "attack_surface", "parameter_")):
        return "security"
    if n.startswith(("playwright", "lighthouse")):
        return "browser"
    if n in {"run", "run_command", "install", "install_tool", "ask_user"}:
        return "orchestration"
    if n in {"nmap", "nuclei", "sqlmap", "whatweb", "nikto", "gobuster", "ffuf",
             "subfinder", "httpx", "wafw00f", "enum4linux", "snmpwalk"}:
        return "terminal"
    if n.startswith("write_"):
        return "reporting"
    if "dns" in d or "ssl" in d or "httpx" in d:
        return "network"
    return "misc"


def _split_csv(value: str) -> Tuple[str, ...]:
    items = []
    for part in value.split(","):
        text = part.strip()
        if text:
            items.append(text)
    return tuple(items)


def _parse_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    stripped = text.lstrip()
    if not stripped.startswith("---"):
        return {}, text
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    meta_lines: List[str] = []
    body_start = None
    for idx, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            body_start = idx + 1
            break
        meta_lines.append(line)
    if body_start is None:
        return {}, text

    metadata: Dict[str, Any] = {}
    for raw in meta_lines:
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip().lower()] = value.strip()
    body = "\n".join(lines[body_start:]).strip()
    return metadata, body


def _maybe_json_list(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    text = str(value).strip()
    if not text:
        return ()
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return tuple(str(item).strip() for item in parsed if str(item).strip())
        except Exception:
            pass
    return _split_csv(text)


def _skill_from_file(path: Path, *, source: str) -> Optional[SkillSpec]:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return None
    metadata, body = _parse_frontmatter(raw)
    name = str(metadata.get("name") or path.parent.name or path.stem).strip()
    description = str(metadata.get("description") or "").strip()
    if not description:
        first_heading = ""
        for line in body.splitlines():
            text = line.strip().lstrip("#").strip()
            if text:
                first_heading = text
                break
        description = first_heading or f"Skill pack loaded from {path.parent.name}"
    category = str(metadata.get("category") or "").strip().lower()
    if not category:
        category = _categorize(name, description)
    inputs = str(metadata.get("inputs") or "").strip()
    outputs = str(metadata.get("outputs") or "").strip()
    kind = str(metadata.get("kind") or "pack").strip().lower() or "pack"
    tools = _maybe_json_list(metadata.get("tools"))
    return SkillSpec(
        name=name,
        category=category,
        description=description,
        inputs=inputs,
        outputs=outputs,
        source=source,
        path=str(path),
        kind=kind,
        tools=tools,
    )


def discover_skill_packs(skill_dirs: Iterable[Path | str]) -> List[SkillSpec]:
    packs: List[SkillSpec] = []
    seen: set[str] = set()
    for raw_dir in skill_dirs:
        base = Path(raw_dir)
        if not base.exists():
            continue
        candidates = []
        if base.is_file() and base.name.lower() == "skill.md":
            candidates.append(base)
        else:
            candidates.extend(base.rglob("SKILL.md"))
        for path in sorted(candidates):
            skill = _skill_from_file(path, source=str(base))
            if not skill:
                continue
            key = skill.name.lower()
            if key in seen:
                continue
            seen.add(key)
            packs.append(skill)
    return packs


def build_skill_catalog(
    tool_descriptions: Dict[str, str],
    skill_dirs: Optional[Iterable[Path | str]] = None,
) -> Dict[str, SkillSpec]:
    catalog: Dict[str, SkillSpec] = {}
    for name, desc in tool_descriptions.items():
        catalog[name] = SkillSpec(
            name=name,
            category=_categorize(name, desc),
            description=desc,
            inputs=_extract_inputs(desc),
            source="built-in",
            kind="tool",
        )
    for skill in discover_skill_packs(skill_dirs or []):
        catalog[skill.name] = skill
    return catalog


def _extract_inputs(description: str) -> str:
    if "args:" not in description:
        return ""
    return description.split("args:", 1)[1].strip().rstrip(";")


def skill_category_counts(catalog: Dict[str, SkillSpec]) -> Dict[str, int]:
    counter = Counter(skill.category for skill in catalog.values())
    return dict(sorted(counter.items(), key=lambda item: item[0]))


def skill_overview_lines(catalog: Dict[str, SkillSpec], limit_per_category: int = 4) -> List[str]:
    grouped: Dict[str, List[SkillSpec]] = defaultdict(list)
    for skill in catalog.values():
        grouped[skill.category].append(skill)

    lines: List[str] = []
    for category in sorted(grouped):
        skills = sorted(grouped[category], key=lambda skill: skill.name)
        sample = ", ".join(skill.name for skill in skills[:limit_per_category])
        lines.append(f"{category}: {len(skills)} skills [{sample}]")
    return lines


def skill_snapshot(catalog: Dict[str, SkillSpec], limit: int = 12) -> Dict[str, object]:
    grouped: Dict[str, List[str]] = defaultdict(list)
    source_counts = Counter(skill.source for skill in catalog.values())
    for skill in catalog.values():
        grouped[skill.category].append(skill.name)
    category_counts = skill_category_counts(catalog)
    return {
        "total": len(catalog),
        "categories": category_counts,
        "sources": dict(sorted(source_counts.items(), key=lambda item: item[0])),
        "samples": {
            category: sorted(names)[:limit]
            for category, names in grouped.items()
        },
    }
