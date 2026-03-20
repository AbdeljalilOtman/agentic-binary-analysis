import tempfile

from agentic_binary_analysis.analysis.patterns import detect_packing_encryption


def test_detect_packing_encryption_entropy():
    data = bytes([0, 255]) * 2048
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(data)
        path = handle.name

    result = detect_packing_encryption(path)
    assert "entropy" in result
