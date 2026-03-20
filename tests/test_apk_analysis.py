import tempfile
import zipfile

from agentic_binary_analysis.analysis.apk_analysis import (
    analyze_network_behavior,
    extract_permissions_with_risk,
    find_hardcoded_secrets,
)


def _make_apk(tmp_path: str) -> str:
    manifest = """
    <manifest package=\"com.example\">
        <uses-permission android:name=\"android.permission.READ_SMS\" />
    </manifest>
    """
    content = "API_KEY=AIza" + "a" * 35 + "\nhttps://example.com/api"
    apk_path = tmp_path + "/sample.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("assets/config.txt", content)
    return apk_path


def test_extract_permissions_with_risk(tmp_path):
    apk_path = _make_apk(str(tmp_path))
    result = extract_permissions_with_risk(apk_path)
    assert any(p["permission"] == "android.permission.READ_SMS" for p in result["permissions"])


def test_find_hardcoded_secrets(tmp_path):
    apk_path = _make_apk(str(tmp_path))
    result = find_hardcoded_secrets(apk_path)
    assert result["secrets"]


def test_analyze_network_behavior(tmp_path):
    apk_path = _make_apk(str(tmp_path))
    result = analyze_network_behavior(apk_path)
    assert "https://example.com/api" in result["urls"]
