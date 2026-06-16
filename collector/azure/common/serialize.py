"""Serialize Azure SDK objects to JSON-safe dicts."""

from __future__ import annotations

from typing import Any


def to_dict(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_dict(x) for x in obj]
    if hasattr(obj, "as_dict"):
        return to_dict(obj.as_dict())
    if hasattr(obj, "__dict__"):
        return {k: to_dict(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)
