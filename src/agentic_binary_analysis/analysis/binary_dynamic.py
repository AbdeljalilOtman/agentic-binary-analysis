from __future__ import annotations

from typing import Dict, List

from agentic_binary_analysis.analysis.binary_static import analyze_imports_exports
from agentic_binary_analysis.analysis.common import extract_ascii_strings, read_file_bytes


_SUSPICIOUS_IMPORTS = {
    "windows": {
        "CreateRemoteThread",
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateProcess",
        "OpenProcess",
        "WinExec",
    },
    "linux": {"ptrace", "execve", "fork", "clone", "socket", "connect", "mprotect"},
}

_ANTI_ANALYSIS_STRINGS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "ptrace",
    "Sleep",
    "GetTickCount",
    "QueryPerformanceCounter",
    "VBOX",
    "VMware",
}


def _scan_strings_for_indicators(file_path: str, indicators: set[str]) -> List[str]:
    data, _ = read_file_bytes(file_path)
    hits = set()
    for _, value in extract_ascii_strings(data, min_length=4):
        for indicator in indicators:
            if indicator.lower() in value.lower():
                hits.add(indicator)
    return sorted(hits)


def find_suspicious_syscalls(file_path: str) -> Dict:
    imports_result = analyze_imports_exports(file_path)
    imports = set(imports_result.get("imports", []))
    hits = set()
    for name in _SUSPICIOUS_IMPORTS["windows"].union(_SUSPICIOUS_IMPORTS["linux"]):
        if name in imports:
            hits.add(name)

    if not hits:
        hits = set(_scan_strings_for_indicators(file_path, _SUSPICIOUS_IMPORTS["windows"]))
        hits.update(_scan_strings_for_indicators(file_path, _SUSPICIOUS_IMPORTS["linux"]))

    return {
        "file": file_path,
        "hits": sorted(hits),
        "source": "imports" if imports else "strings",
    }


def detect_anti_analysis(file_path: str) -> Dict:
    hits = _scan_strings_for_indicators(file_path, _ANTI_ANALYSIS_STRINGS)
    return {"file": file_path, "hits": hits}


def trace_data_flow(file_path: str) -> Dict:
    imports_result = analyze_imports_exports(file_path)
    imports = set(imports_result.get("imports", []))
    network_indicators = {"socket", "connect", "InternetOpen", "HttpSendRequest"}
    crypto_indicators = {"CryptEncrypt", "AES", "RSA", "BCrypt"}

    return {
        "file": file_path,
        "network_indicators": sorted(imports.intersection(network_indicators)),
        "crypto_indicators": sorted(imports.intersection(crypto_indicators)),
        "note": "Heuristic import-based data flow indicators.",
    }
