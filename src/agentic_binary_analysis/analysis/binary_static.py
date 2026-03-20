from __future__ import annotations

import struct
from typing import Dict, List

from agentic_binary_analysis.analysis.common import (
    compute_entropy,
    extract_ascii_strings,
    get_context,
    read_file_bytes,
    search_bytes,
)


_CRYPTO_CONSTANTS = {
    "md5_init": [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
    "sha1_init": [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
}


def extract_crypto_constants(file_path: str) -> Dict:
    data, truncated = read_file_bytes(file_path)
    matches: List[Dict] = []
    for name, words in _CRYPTO_CONSTANTS.items():
        little = b"".join(struct.pack("<I", w) for w in words)
        big = b"".join(struct.pack(">I", w) for w in words)
        for idx in search_bytes(data, little):
            matches.append({"name": name, "offset": idx, "endianness": "little"})
        for idx in search_bytes(data, big):
            matches.append({"name": name, "offset": idx, "endianness": "big"})

    return {
        "file": file_path,
        "matches": matches,
        "truncated": truncated,
    }


def extract_strings_with_context(file_path: str, min_length: int = 4, context_bytes: int = 16) -> Dict:
    data, truncated = read_file_bytes(file_path)
    strings = []
    for offset, value in extract_ascii_strings(data, min_length=min_length):
        strings.append(
            {
                "offset": offset,
                "value": value,
                "context_hex": get_context(data, offset, context_bytes=context_bytes),
            }
        )
    return {
        "file": file_path,
        "strings": strings,
        "truncated": truncated,
    }


def analyze_imports_exports(file_path: str) -> Dict:
    result = {"file": file_path, "imports": [], "exports": [], "errors": []}
    try:
        import lief

        binary = lief.parse(file_path)
        if not binary:
            result["errors"].append("parse_failed")
            return result
        result["imports"] = sorted({str(i.name) for i in getattr(binary, "imports", [])})
        result["exports"] = sorted({str(e.name) for e in getattr(binary, "exported_functions", [])})
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def estimate_file_entropy(file_path: str) -> Dict:
    data, truncated = read_file_bytes(file_path)
    return {
        "file": file_path,
        "entropy": round(compute_entropy(data), 4),
        "truncated": truncated,
    }
