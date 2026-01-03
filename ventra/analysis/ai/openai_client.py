"""
Minimal OpenAI client for findings enrichment.

No third-party SDK dependency; uses `requests` (already in Ventra deps).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import requests


class OpenAIError(RuntimeError):
    pass


def chat_json(
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
    api_key: Optional[str] = None,
    timeout_seconds: int = 60,
) -> Dict[str, Any]:
    """
    Call OpenAI Chat Completions and parse a JSON object response.

    Requires OPENAI_API_KEY (or explicit api_key).
    """
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise OpenAIError("Missing OPENAI_API_KEY (required for --ai-provider openai)")

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        # Ask for JSON-ish output; we still defensively parse below.
        "response_format": {"type": "json_object"},
    }

    try:
        resp = requests.post(url, headers=headers, json=body, timeout=timeout_seconds)
    except Exception as e:
        raise OpenAIError(f"OpenAI request failed: {e}") from e

    if resp.status_code >= 400:
        raise OpenAIError(f"OpenAI HTTP {resp.status_code}: {resp.text}")

    data = resp.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except Exception:
        raise OpenAIError(f"Unexpected OpenAI response shape: {data}")

    try:
        return json.loads(content)
    except Exception as e:
        raise OpenAIError(f"Failed to parse JSON from model output: {e}; content={content!r}") from e

