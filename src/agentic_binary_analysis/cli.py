from __future__ import annotations

import argparse
import json
import sys

from agentic_binary_analysis.analysis.apk_analysis import (
    analyze_network_behavior,
    detect_obfuscation_techniques,
    extract_permissions_with_risk,
    find_hardcoded_secrets,
)
from agentic_binary_analysis.analysis.binary_dynamic import (
    detect_anti_analysis,
    find_suspicious_syscalls,
    trace_data_flow,
)
from agentic_binary_analysis.analysis.binary_static import (
    analyze_imports_exports,
    extract_crypto_constants,
    extract_strings_with_context,
)
from agentic_binary_analysis.analysis.patterns import (
    analyze_control_flow_anomalies,
    detect_packing_encryption,
    match_malware_signatures,
)
from agentic_binary_analysis.config import load_openrouter_config
from agentic_binary_analysis.agent.agno_agent import run_agent
from agentic_binary_analysis.agent.toolset import build_agent_tools
from agentic_binary_analysis.reporting import generate_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agentic binary/APK analysis")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Run analysis")
    analyze.add_argument("--file", required=True, help="Path to binary or APK")
    analyze.add_argument("--kind", choices=["binary", "apk"], required=True)
    analyze.add_argument("--out", help="Output JSON report path")
    analyze.add_argument("--agent", action="store_true", help="Use LLM agent")
    analyze.add_argument(
        "--agent-orchestrate",
        action="store_true",
        help="Let the agent call tools instead of running all tools locally",
    )

    return parser


def run_binary(file_path: str) -> dict:
    return {
        "static": {
            "crypto_constants": extract_crypto_constants(file_path),
            "strings_with_context": extract_strings_with_context(file_path),
            "imports_exports": analyze_imports_exports(file_path),
        },
        "dynamic": {
            "suspicious_syscalls": find_suspicious_syscalls(file_path),
            "anti_analysis": detect_anti_analysis(file_path),
            "data_flow": trace_data_flow(file_path),
        },
        "patterns": {
            "control_flow": analyze_control_flow_anomalies(file_path),
            "packing_encryption": detect_packing_encryption(file_path),
            "malware_signatures": match_malware_signatures(file_path),
        },
    }


def run_apk(file_path: str) -> dict:
    return {
        "permissions": extract_permissions_with_risk(file_path),
        "secrets": find_hardcoded_secrets(file_path),
        "network": analyze_network_behavior(file_path),
        "obfuscation": detect_obfuscation_techniques(file_path),
    }


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        payload = None

        if args.agent and args.agent_orchestrate:
            config = load_openrouter_config()
            tools = build_agent_tools(args.kind)
            prompt = (
                "Analyze the file using the available tools and summarize the key risks. "
                f"File: {args.file} Kind: {args.kind}. "
                "Return a concise Markdown summary."
            )
            agent_output, used_agent = run_agent(prompt=prompt, tools=tools, config=config)
            payload = {"agent_output": agent_output, "used_agent": used_agent}

        if payload is None:
            if args.kind == "binary":
                payload = run_binary(args.file)
            else:
                payload = run_apk(args.file)

            if args.agent:
                config = load_openrouter_config()
                summary, used_agent = run_agent(
                    prompt=(
                        "Summarize the analysis results and highlight risks. "
                        f"Results: {json.dumps(payload)[:6000]}"
                    ),
                    tools=[],
                    config=config,
                )
                payload["agent_summary"] = summary
                payload["used_agent"] = used_agent

        report = generate_report(payload, args.out)
        print(json.dumps(report, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
