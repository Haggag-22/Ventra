"""Profile loading. Profiles are YAML preset bundles of collector names."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml


@dataclass
class Profile:
    name: str
    description: str
    collectors: list[str]
    auto_detect_tier3: bool = False
    overrides: list[str] = field(default_factory=list)


def list_profiles() -> list[str]:
    names = []
    for entry in resources.files(__package__).iterdir():
        if entry.name.endswith(".yml"):
            names.append(entry.name[:-4])
    return sorted(names)


def load_profile(name: str) -> Profile:
    """Load a built-in profile by name, or a path to a custom YAML."""
    candidate = Path(name)
    if candidate.suffix in (".yml", ".yaml") and candidate.exists():
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    else:
        try:
            text = resources.files(__package__).joinpath(f"{name}.yml").read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ValueError(
                f"Unknown profile {name!r}. Available: {', '.join(list_profiles())}"
            ) from exc
        data = yaml.safe_load(text)
    return Profile(
        name=data["name"],
        description=data.get("description", ""),
        collectors=list(data.get("collectors", [])),
        auto_detect_tier3=bool(data.get("auto_detect_tier3", False)),
    )


def resolve_collectors(profile: Profile, add: list[str], remove: list[str]) -> tuple[list[str], list[str]]:
    """Apply --add/--remove overrides. Returns (final_list, override_descriptions)."""
    selected = list(dict.fromkeys(profile.collectors))  # dedupe, keep order
    overrides: list[str] = []
    for name in add:
        if name not in selected:
            selected.append(name)
            overrides.append(f"+{name}")
    for name in remove:
        if name in selected:
            selected.remove(name)
            overrides.append(f"-{name}")
    return selected, overrides
