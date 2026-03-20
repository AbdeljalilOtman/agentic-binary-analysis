from __future__ import annotations

from typing import Dict, List

from agentic_binary_analysis.analysis.binary_static import estimate_file_entropy
from agentic_binary_analysis.analysis.common import compute_entropy, read_file_bytes


def analyze_control_flow_anomalies(file_path: str, max_bytes: int = 4096) -> Dict:
    result = {"file": file_path, "indirect_jump_ratio": 0.0, "total_instructions": 0}
    try:
        import capstone
        import lief

        binary = lief.parse(file_path)
        if not binary:
            result["note"] = "parse_failed"
            return result

        arch = binary.header.machine_type if hasattr(binary, "header") else None
        mode = capstone.CS_MODE_32
        if "64" in str(arch):
            mode = capstone.CS_MODE_64

        cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        data, _ = read_file_bytes(file_path)
        code = data[:max_bytes]
        indirect = 0
        total = 0
        for ins in cs.disasm(code, 0x0):
            total += 1
            if ins.mnemonic in {"jmp", "call"} and ins.op_str and "0x" not in ins.op_str:
                indirect += 1
        result["total_instructions"] = total
        result["indirect_jump_ratio"] = round(indirect / total, 4) if total else 0.0
        if result["indirect_jump_ratio"] > 0.15:
            result["anomaly"] = "high_indirect_jump_ratio"
    except Exception as exc:
        result["note"] = str(exc)
    return result


def detect_packing_encryption(file_path: str) -> Dict:
    entropy_info = estimate_file_entropy(file_path)
    verdict = "unknown"
    if entropy_info["entropy"] > 7.2:
        verdict = "high_entropy_suspected_packing"
    return {
        "file": file_path,
        "entropy": entropy_info["entropy"],
        "verdict": verdict,
    }


def match_malware_signatures(file_path: str, rules_path: str | None = None) -> Dict:
    result = {"file": file_path, "matches": [], "errors": []}
    try:
        import yara

        if rules_path:
            rules = yara.compile(filepath=rules_path)
        else:
            rules = yara.compile(
                source="""
rule PackedUPX {
    strings:
        $upx = "UPX!"
    condition:
        $upx
}
"""
            )
        matches = rules.match(file_path)
        result["matches"] = [m.rule for m in matches]
    except Exception as exc:
        result["errors"].append(str(exc))
    return result
