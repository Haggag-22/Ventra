"""Shared helpers for per-artifact collector parameters from acquisition.yaml."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .models import CollectionContext, TimeWindow

DEFAULT_WINDOW_DAYS = 90


def artifact_param_dict(ctx: CollectionContext, collector_name: str) -> dict[str, Any]:
    return dict(getattr(ctx, "artifact_parameters", {}).get(collector_name, {}) or {})


def param_raw(params: dict[str, Any], key: str) -> Any:
    if key not in params:
        return None
    return params[key]


def param_strings(params: dict[str, Any], key: str) -> list[str]:
    """Return a normalized list of non-empty strings from a scalar or list param."""
    val = param_raw(params, key)
    if val is None:
        return []
    if isinstance(val, bool):
        return []
    if isinstance(val, (int, float)):
        return [str(val)]
    if isinstance(val, list):
        out: list[str] = []
        for item in val:
            if item is None:
                continue
            s = str(item).strip()
            if s:
                out.append(s)
        return out
    if isinstance(val, str):
        return [part.strip() for part in val.split(",") if part.strip()]
    return []


def param_bool(params: dict[str, Any], key: str, *, default: bool = False) -> bool:
    val = param_raw(params, key)
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        lowered = val.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def param_int(params: dict[str, Any], key: str, *, default: int | None = None) -> int | None:
    val = param_raw(params, key)
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def parse_relative_since(value: str, end: datetime) -> datetime | None:
    val = value.strip().lower()
    if val.endswith("d") and val[:-1].isdigit():
        return end - timedelta(days=int(val[:-1]))
    return None


def effective_window(
    ctx: CollectionContext,
    collector_name: str,
    *,
    default_days: int = DEFAULT_WINDOW_DAYS,
) -> tuple[datetime, datetime]:
    """Merge global acquisition window with per-artifact since/until/window_days."""
    params = artifact_param_dict(ctx, collector_name)
    window_days = param_int(params, "window_days", default=default_days) or default_days
    start, end = window_bounds(ctx.time_window, window_days)

    rel = param_raw(params, "since")
    if isinstance(rel, str) and rel.strip():
        parsed = parse_relative_since(rel, end)
        if parsed is not None:
            start = parsed

    until = param_raw(params, "until")
    if isinstance(until, str) and until.strip():
        try:
            end = datetime.fromisoformat(until.replace("Z", "+00:00"))
        except ValueError:
            pass

    return start, end


def has_explicit_time_scope(
    ctx: CollectionContext,
    collector_name: str,
    *,
    default_days: int = DEFAULT_WINDOW_DAYS,
) -> bool:
    """True when CLI or artifact params narrow the collection window."""
    params = artifact_param_dict(ctx, collector_name)
    tw = ctx.time_window
    if param_raw(params, "since") or param_raw(params, "until"):
        return True
    if param_int(params, "window_days") is not None:
        return True
    if tw.since is not None or tw.until is not None:
        return True
    return False


def scoped_window(
    ctx: CollectionContext,
    collector_name: str,
    *,
    default_days: int = DEFAULT_WINDOW_DAYS,
) -> tuple[datetime | None, datetime | None]:
    """Return (start, end) for blob/API filtering, or (None, None) when unset."""
    if not has_explicit_time_scope(ctx, collector_name, default_days=default_days):
        return None, None
    return effective_window(ctx, collector_name, default_days=default_days)


def window_bounds(tw: TimeWindow, default_days: int = DEFAULT_WINDOW_DAYS) -> tuple[datetime, datetime]:
    end = tw.until or datetime.now(UTC)
    start = tw.since or (end - timedelta(days=default_days))
    return start, end


def matches_any(value: str | None, allowed: list[str], *, case_insensitive: bool = True) -> bool:
    """If allowed is empty, match everything; otherwise value must match one token."""
    if not allowed:
        return True
    if value is None:
        return False
    hay = value if not case_insensitive else value.lower()
    for token in allowed:
        t = token if not case_insensitive else token.lower()
        if hay == t or hay.endswith(t) or t in hay:
            return True
    return False


def matches_prefix(value: str | None, prefixes: list[str]) -> bool:
    if not prefixes:
        return True
    if not value:
        return False
    lower = value.lower()
    return any(lower.startswith(p.lower()) for p in prefixes)


def filter_dicts_by_fields(
    items: list[dict[str, Any]],
    params: dict[str, Any],
    *,
    id_param_keys: tuple[str, ...] = ("resource_ids",),
    name_param_keys: tuple[str, ...] = ("resource_names", "names"),
    arn_param_keys: tuple[str, ...] = ("resource_arns", "arns"),
    id_fields: tuple[str, ...] = ("ResourceId", "Id", "id"),
    name_fields: tuple[str, ...] = ("Name", "name"),
    arn_fields: tuple[str, ...] = ("Arn", "ARN", "TrailARN", "arn"),
) -> list[dict[str, Any]]:
    """Generic allow-list filter for inventory-style collector results."""
    ids: list[str] = []
    names: list[str] = []
    arns: list[str] = []
    for key in id_param_keys:
        ids.extend(param_strings(params, key))
    for key in name_param_keys:
        names.extend(param_strings(params, key))
    for key in arn_param_keys:
        arns.extend(param_strings(params, key))
    prefixes = param_strings(params, "name_prefix")

    if not (ids or names or arns or prefixes):
        return items

    kept: list[dict[str, Any]] = []
    for item in items:
        item_ids = [str(item.get(f) or "") for f in id_fields if item.get(f)]
        item_names = [str(item.get(f) or "") for f in name_fields if item.get(f)]
        item_arns = [str(item.get(f) or "") for f in arn_fields if item.get(f)]

        if ids and not any(matches_any(i, ids) for i in item_ids):
            continue
        if names and not any(matches_any(n, names) for n in item_names):
            continue
        if arns and not any(matches_any(a, arns) for a in item_arns):
            continue
        if prefixes and not any(matches_prefix(n, prefixes) for n in item_names + item_ids):
            continue
        kept.append(item)
    return kept
