#!/usr/bin/env python3
"""Regenerate the logs-coverage CATALOG section in console/frontend/lib/catalog.ts from artifact YAML."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_ROOT = ROOT / "artifacts"
CATALOG_TS = ROOT / "console" / "frontend" / "lib" / "catalog.ts"
OVERRIDES = ROOT / "scripts" / "catalog-label-overrides.json"
PLANNED = ROOT / "scripts" / "catalog-planned.json"

_SKIP_COLLECTORS = frozenset({
    "account", "iam", "kms", "secrets", "ec2", "s3", "lambda", "log_posture",
    "rbac", "subscription", "entra_directory", "resource_graph", "diag_posture",
    "project", "iam_policy",
})
_SINGLE_GROUP_CLOUDS = frozenset({"aws", "azure"})


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _label(collector: str, description: str, overrides: dict[str, str]) -> str:
    return overrides.get(collector) or description.strip() or collector


def _load_artifacts() -> list[dict]:
    sys.path.insert(0, str(ROOT))
    from collector.engine.loader import load_artifacts_dir
    return load_artifacts_dir(ARTIFACTS_ROOT)


def _build_catalog(artifacts: list[dict], overrides: dict[str, str], planned: dict) -> dict[str, list[dict]]:
    by_cloud: dict[str, dict[str, list[dict]]] = {c: {} for c in ("aws", "azure", "gcp")}
    for art in artifacts:
        cloud = str(art.get("cloud", "")).lower()
        collector = str(art.get("collector", "")).strip()
        if cloud not in by_cloud or not collector or collector in _SKIP_COLLECTORS:
            continue
        category = "Logs Checked" if cloud in _SINGLE_GROUP_CLOUDS else str(art.get("category") or "Other")
        by_cloud[cloud].setdefault(category, []).append({
            "id": collector,
            "label": _label(collector, str(art.get("description", "")), overrides),
            "description": "",
        })
    for cloud, entries in planned.items():
        for entry in entries:
            cat = entry.get("category") or "Logs Checked"
            by_cloud.setdefault(cloud, {}).setdefault(cat, []).append({
                "id": entry["id"],
                "label": entry.get("label") or overrides.get(entry["id"], entry["id"]),
                "description": "",
            })
    out: dict[str, list[dict]] = {}
    for cloud, groups in by_cloud.items():
        catalog_groups = []
        for category in sorted(groups):
            items = sorted(groups[category], key=lambda x: x["id"])
            catalog_groups.append({"category": category, "items": items})
        out[cloud] = catalog_groups
    return out


def _ts_item(item: dict) -> str:
    label = item["label"].replace("\\", "\\\\").replace('"', '\\"')
    return f'      {{ id: "{item["id"]}", label: "{label}", description: "" }},'


def _ts_group(group: dict) -> str:
    lines = ["  {", f'    category: "{group["category"]}",', "    items: ["]
    for item in group["items"]:
        lines.append(_ts_item(item))
    lines.extend(["    ],", "  },"])
    return "\n".join(lines)


def _render_catalog_block(catalog: dict[str, list[dict]]) -> str:
    parts = []
    for cloud, const in (("aws", "AWS_LOGS"), ("azure", "AZURE"), ("gcp", "GCP")):
        groups = catalog.get(cloud, [])
        comment = ""
        if cloud == "aws":
            comment = (
                "// AWS — Erblind / IR logs cheat sheet. Ids match collector source names / posture gap names\n"
                "// so the Logs Coverage panel can resolve each row straight from the manifest.\n"
            )
        elif cloud == "gcp":
            comment = "/** GCP IR cheat sheet — categories mirror the Google Cloud incident response reference. */\n"
        body = "\n".join(_ts_group(g) for g in groups)
        parts.append(f"{comment}const {const}: CatalogGroup[] = [\n{body}\n];")
    return "\n\n".join(parts)


def _replace_generated(text: str, block: str) -> str:
    start = "// BEGIN GENERATED CATALOG"
    end = "// END GENERATED CATALOG"
    if start not in text or end not in text:
        raise SystemExit(f"{CATALOG_TS}: missing GENERATED CATALOG markers")
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    return pattern.sub(f"{start} — run: python scripts/generate-catalog-ts.py\n{block}\n{end}", text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    overrides = _load_json(OVERRIDES)
    planned = _load_json(PLANNED)
    block = _render_catalog_block(_build_catalog(_load_artifacts(), overrides, planned))
    current = CATALOG_TS.read_text(encoding="utf-8")
    updated = _replace_generated(current, block)
    if args.check:
        if updated != current:
            print("catalog.ts is out of date — run: python scripts/generate-catalog-ts.py", file=sys.stderr)
            return 1
        print("catalog.ts is up to date")
        return 0
    CATALOG_TS.write_text(updated, encoding="utf-8")
    print(f"Updated {CATALOG_TS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
