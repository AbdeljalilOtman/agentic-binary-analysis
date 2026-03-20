from __future__ import annotations

from fastmcp import FastMCP

from agentic_binary_analysis.analysis.patterns import (
    analyze_control_flow_anomalies as binary_analyze_control_flow_anomalies,
    detect_packing_encryption as binary_detect_packing_encryption,
    match_malware_signatures as binary_match_malware_signatures,
)

mcp = FastMCP("binary-patterns")


@mcp.tool()
def analyze_control_flow_anomalies(file_path: str) -> dict:
    return binary_analyze_control_flow_anomalies(file_path)


@mcp.tool()
def detect_packing_encryption(file_path: str) -> dict:
    return binary_detect_packing_encryption(file_path)


@mcp.tool()
def match_malware_signatures(file_path: str, rules_path: str | None = None) -> dict:
    return binary_match_malware_signatures(file_path, rules_path=rules_path)


if __name__ == "__main__":
    mcp.run()
