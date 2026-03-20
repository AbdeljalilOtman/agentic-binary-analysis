from __future__ import annotations

import math
from typing import Iterable, List, Tuple


def read_file_bytes(file_path: str, max_size_mb: int = 10) -> Tuple[bytes, bool]:
    max_size = max_size_mb * 1024 * 1024
    with open(file_path, "rb") as handle:
        data = handle.read(max_size + 1)
    truncated = len(data) > max_size
    if truncated:
        data = data[:max_size]
    return data, truncated


def extract_ascii_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
    results: List[Tuple[int, str]] = []
    current = []
    start_idx = 0
    for idx, byte in enumerate(data):
        if 32 <= byte <= 126:
            if not current:
                start_idx = idx
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                results.append((start_idx, "".join(current)))
            current = []
    if len(current) >= min_length:
        results.append((start_idx, "".join(current)))
    return results


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def get_context(data: bytes, offset: int, context_bytes: int = 16) -> str:
    start = max(0, offset - context_bytes)
    end = min(len(data), offset + context_bytes)
    return data[start:end].hex()


def search_bytes(data: bytes, needle: bytes) -> Iterable[int]:
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        yield idx
        start = idx + 1
