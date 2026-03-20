from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict


def generate_report(payload: Dict[str, Any], output_path: str | None = None) -> Dict[str, Any]:
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "analysis": payload,
    }
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, default=str)
    return report
