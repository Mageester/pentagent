from __future__ import annotations

from dataclasses import dataclass
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Tuple


@dataclass(frozen=True)
class SkillSpec:
    name: str
    category: str
    description: str
    inputs: str = ""
    outputs: str = ""
    source: str = "built-in"


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


def build_skill_catalog(tool_descriptions: Dict[str, str]) -> Dict[str, SkillSpec]:
    catalog: Dict[str, SkillSpec] = {}
    for name, desc in tool_descriptions.items():
        catalog[name] = SkillSpec(
            name=name,
            category=_categorize(name, desc),
            description=desc,
            inputs=_extract_inputs(desc),
        )
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
    for skill in catalog.values():
        grouped[skill.category].append(skill.name)
    category_counts = skill_category_counts(catalog)
    return {
        "total": len(catalog),
        "categories": category_counts,
        "samples": {
            category: sorted(names)[:limit]
            for category, names in grouped.items()
        },
    }
