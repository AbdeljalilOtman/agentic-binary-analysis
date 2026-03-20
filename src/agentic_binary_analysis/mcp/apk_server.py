from __future__ import annotations

from fastmcp import FastMCP

from agentic_binary_analysis.analysis.apk_analysis import (
    analyze_network_behavior as apk_analyze_network_behavior,
    detect_obfuscation_techniques as apk_detect_obfuscation_techniques,
    extract_permissions_with_risk as apk_extract_permissions_with_risk,
    find_hardcoded_secrets as apk_find_hardcoded_secrets,
)

mcp = FastMCP("apk-analysis")


@mcp.tool()
def extract_permissions_with_risk(apk_path: str) -> dict:
    return apk_extract_permissions_with_risk(apk_path)


@mcp.tool()
def find_hardcoded_secrets(apk_path: str) -> dict:
    return apk_find_hardcoded_secrets(apk_path)


@mcp.tool()
def analyze_network_behavior(apk_path: str) -> dict:
    return apk_analyze_network_behavior(apk_path)


@mcp.tool()
def detect_obfuscation_techniques(apk_path: str) -> dict:
    return apk_detect_obfuscation_techniques(apk_path)


if __name__ == "__main__":
    mcp.run()
