from __future__ import annotations

from typing import Any, Callable, Dict, List

from agentic_binary_analysis.config import OpenRouterConfig
from agentic_binary_analysis.llm.openrouter_client import simple_chat


def run_agent(
    prompt: str,
    tools: List[Callable[..., Dict[str, Any]]],
    config: OpenRouterConfig,
) -> tuple[str, bool]:
    try:
        from agno.agent import Agent
        from agno.models.openai import OpenAIChat
    except Exception:
        return simple_chat(config, prompt), False

    model = OpenAIChat(
        id=config.model,
        api_key=config.api_key,
        base_url=config.base_url,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )
    agent = Agent(
        model=model,
        tools=tools,
        instructions="You are a malware analysis assistant. Use tools when helpful.",
    )
    return agent.run(prompt), True
