import os
from dataclasses import dataclass


@dataclass(frozen=True)
class OpenRouterConfig:
    api_key: str
    model: str
    base_url: str
    max_tokens: int
    temperature: float


def load_openrouter_config() -> OpenRouterConfig:
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    model = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free").strip()
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").strip()
    max_tokens = int(os.getenv("OPENROUTER_MAX_TOKENS", "512"))
    temperature = float(os.getenv("OPENROUTER_TEMPERATURE", "0.2"))
    return OpenRouterConfig(
        api_key=api_key,
        model=model,
        base_url=base_url,
        max_tokens=max_tokens,
        temperature=temperature,
    )
