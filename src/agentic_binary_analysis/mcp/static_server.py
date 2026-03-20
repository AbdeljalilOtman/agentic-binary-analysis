from __future__ import annotations

from fastmcp import FastMCP

from agentic_binary_analysis.analysis.binary_static import (
    analyze_imports_exports as binary_analyze_imports_exports,
    extract_crypto_constants as binary_extract_crypto_constants,
    extract_strings_with_context as binary_extract_strings_with_context,
)

mcp = FastMCP("binary-static")


@mcp.tool()
def extract_crypto_constants(file_path: str) -> dict:
    return binary_extract_crypto_constants(file_path)


@mcp.tool()
def extract_strings_with_context(file_path: str, min_length: int = 4, context_bytes: int = 16) -> dict:
    return binary_extract_strings_with_context(file_path, min_length=min_length, context_bytes=context_bytes)


@mcp.tool()
def analyze_imports_exports(file_path: str) -> dict:
    return binary_analyze_imports_exports(file_path)


if __name__ == "__main__":
    mcp.run()
