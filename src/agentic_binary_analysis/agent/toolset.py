from __future__ import annotations

from typing import Callable, Dict, List

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


def build_agent_tools(kind: str) -> List[Callable[..., Dict]]:
    if kind == "apk":
        return [
            extract_permissions_with_risk,
            find_hardcoded_secrets,
            analyze_network_behavior,
            detect_obfuscation_techniques,
        ]

    return [
        extract_crypto_constants,
        extract_strings_with_context,
        analyze_imports_exports,
        find_suspicious_syscalls,
        detect_anti_analysis,
        trace_data_flow,
        analyze_control_flow_anomalies,
        detect_packing_encryption,
        match_malware_signatures,
    ]
