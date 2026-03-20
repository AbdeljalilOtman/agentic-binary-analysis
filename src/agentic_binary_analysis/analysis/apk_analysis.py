from __future__ import annotations

import re
import zipfile
from typing import Dict, List

from agentic_binary_analysis.analysis.common import compute_entropy


_PERMISSION_RISK = {
    "android.permission.READ_SMS": "high",
    "android.permission.RECEIVE_SMS": "high",
    "android.permission.SEND_SMS": "high",
    "android.permission.READ_CONTACTS": "medium",
    "android.permission.WRITE_CONTACTS": "medium",
    "android.permission.RECORD_AUDIO": "high",
    "android.permission.CAMERA": "medium",
    "android.permission.ACCESS_FINE_LOCATION": "high",
    "android.permission.ACCESS_COARSE_LOCATION": "medium",
}

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,48}"),
    re.compile(r"(?i)secret[_-]?key\s*[:=]\s*[\w-]{8,}"),
]

_URL_PATTERN = re.compile(r"https?://[\w\-\.\:/%\?#&=]+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(r"\b[a-z0-9\-]+\.(com|net|org|io|dev|info|app)\b", re.IGNORECASE)


def _read_text_files(apk_path: str, max_files: int = 200) -> List[str]:
    texts: List[str] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for idx, name in enumerate(zf.namelist()):
            if idx > max_files:
                break
            if not name.endswith((".xml", ".txt", ".json", ".properties", ".smali", ".js")):
                continue
            try:
                data = zf.read(name)
            except Exception:
                continue
            try:
                texts.append(data.decode("utf-8", errors="ignore"))
            except Exception:
                continue
    return texts


def extract_permissions_with_risk(apk_path: str) -> Dict:
    permissions = set()
    with zipfile.ZipFile(apk_path, "r") as zf:
        if "AndroidManifest.xml" not in zf.namelist():
            return {"apk": apk_path, "permissions": [], "note": "manifest_missing"}
        manifest = zf.read("AndroidManifest.xml")
        if b"android.permission" not in manifest:
            return {"apk": apk_path, "permissions": [], "note": "manifest_binary_use_androguard"}
        try:
            text = manifest.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        permissions.update(re.findall(r"android.permission.[A-Z_]+", text))

    results = []
    for perm in sorted(permissions):
        risk = _PERMISSION_RISK.get(perm, "low")
        results.append({"permission": perm, "risk": risk})
    return {"apk": apk_path, "permissions": results}


def find_hardcoded_secrets(apk_path: str) -> Dict:
    hits: List[Dict] = []
    for text in _read_text_files(apk_path):
        for pattern in _SECRET_PATTERNS:
            for match in pattern.findall(text):
                hits.append({"match": match, "pattern": pattern.pattern})
    return {"apk": apk_path, "secrets": hits}


def analyze_network_behavior(apk_path: str) -> Dict:
    urls = set()
    domains = set()
    for text in _read_text_files(apk_path):
        urls.update(_URL_PATTERN.findall(text))
        domains.update(_DOMAIN_PATTERN.findall(text))
    return {"apk": apk_path, "urls": sorted(urls), "domains": sorted(domains)}


def detect_obfuscation_techniques(apk_path: str) -> Dict:
    notes = []
    dex_entropy = 0.0
    with zipfile.ZipFile(apk_path, "r") as zf:
        if "classes.dex" in zf.namelist():
            data = zf.read("classes.dex")
            dex_entropy = compute_entropy(data)
            if dex_entropy > 7.2:
                notes.append("high_dex_entropy")

    short_class_ratio = 0.0
    class_names = []
    for text in _read_text_files(apk_path):
        class_names += re.findall(r"L([a-zA-Z0-9_/]{1,80});", text)
    if class_names:
        short_names = [c for c in class_names if len(c.split("/")) >= 1 and len(c.split("/")[-1]) <= 2]
        short_class_ratio = len(short_names) / len(class_names)
        if short_class_ratio > 0.4:
            notes.append("high_short_class_ratio")

    return {
        "apk": apk_path,
        "dex_entropy": round(dex_entropy, 4),
        "short_class_ratio": round(short_class_ratio, 4),
        "notes": notes,
    }
