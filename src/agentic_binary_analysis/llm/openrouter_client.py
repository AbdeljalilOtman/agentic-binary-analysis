from __future__ import annotations

import json
from typing import Any, Dict, List

import requests

from agentic_binary_analysis.config import OpenRouterConfig


def chat_completion(config: OpenRouterConfig, messages: List[Dict[str, str]]) -> Dict[str, Any]:
    if not config.api_key:
        raise ValueError("OPENROUTER_API_KEY is required")

    url = f"{config.base_url}/chat/completions"
    payload = {
        "model": config.model,
        "messages": messages,
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
    }
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
    response.raise_for_status()
    return response.json()


def simple_chat(config: OpenRouterConfig, prompt: str) -> str:
    result = chat_completion(config, [{"role": "user", "content": prompt}])
    choices = result.get("choices", [])
    if not choices:
        return ""
    return choices[0].get("message", {}).get("content", "")
