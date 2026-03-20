# Agentic Workflow for Automated Binary/APK Analysis

This project implements an agentic analysis workflow for binary executables and Android APKs.
It uses FastMCP to expose high-level analysis tools and an Agno-based agent to orchestrate them.
LLM calls are routed through OpenRouter free tier (no paid usage required).

## Features
- Binary static analysis tools (crypto constants, strings with context, imports/exports)
- Binary dynamic heuristics (suspicious syscalls, anti-analysis indicators)
- Pattern detection (control-flow anomalies, packing/encryption, YARA signatures)
- APK analysis tools (permissions risk, hardcoded secrets, network behavior, obfuscation)

## Requirements
- Python 3.11+
- Optional: Radare2, YARA, LIEF, Capstone, Androguard

## Quick Start
1. Create a virtual environment and install dependencies:
   - `python -m venv .venv`
   - `./.venv/Scripts/activate` (Windows)
   - `pip install -r requirements.txt`
2. Set environment variables (OpenRouter free tier):
   - Copy `.env.example` to `.env`
   - Set `OPENROUTER_API_KEY` and confirm `OPENROUTER_MODEL` is a free-tier model
3. Run a basic analysis:
   - `python -m agentic_binary_analysis.cli analyze --file samples/sample.bin --kind binary`
4. Optional agent summary:
   - `python -m agentic_binary_analysis.cli analyze --file samples/sample.bin --kind binary --agent`
5. Optional agent tool orchestration (requires Agno installed):
   - `python -m agentic_binary_analysis.cli analyze --file samples/sample.bin --kind binary --agent --agent-orchestrate`

## Docker
- Build: `docker build -t agentic-analysis .`
- Run: `docker run --rm -e OPENROUTER_API_KEY=... agentic-analysis`

## Tests
- `PYTHONPATH=src python -m pytest -q`
- If pytest fails due to the `dash` plugin, use `-p no:dash`.

## Notes
- OpenRouter free tier is used by default. You can change the model via `OPENROUTER_MODEL`.
- Some tools degrade gracefully if optional dependencies are missing.
