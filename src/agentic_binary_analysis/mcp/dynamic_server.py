from __future__ import annotations

from fastmcp import FastMCP

from agentic_binary_analysis.analysis.binary_dynamic import (
    detect_anti_analysis as binary_detect_anti_analysis,
    find_suspicious_syscalls as binary_find_suspicious_syscalls,
    trace_data_flow as binary_trace_data_flow,
)

mcp = FastMCP("binary-dynamic")


@mcp.tool()
def find_suspicious_syscalls(file_path: str) -> dict:
    return binary_find_suspicious_syscalls(file_path)


@mcp.tool()
def detect_anti_analysis(file_path: str) -> dict:
    return binary_detect_anti_analysis(file_path)


@mcp.tool()
def trace_data_flow(file_path: str) -> dict:
    return binary_trace_data_flow(file_path)


if __name__ == "__main__":
    mcp.run()
